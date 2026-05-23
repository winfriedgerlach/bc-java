package org.bouncycastle.crypto.digests;

import java.security.SecureRandom;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

/**
 * Cross-checks the JDK 25 batched SHA-256 compressor
 * ({@link SHA256BatchedVectorImpl}) against the scalar
 * {@link SHA256Digest} reference, for the two patterns the SLH-DSA
 * batching needs:
 * <ul>
 *   <li>One-block hashes from the SHA-256 IV — so the batched output
 *       must match {@code SHA256(msg)} for {@code msg} of length
 *       {@code <= 55}.</li>
 *   <li>One-block hashes from a memoised pre-state (the
 *       {@code pkSeed || zero-pad-to-64} state SLH-DSA caches) — so
 *       the batched output must match {@code SHA256(pkSeedBlock || msg)}
 *       for messages whose total length still fits two SHA-256 blocks
 *       after padding.</li>
 * </ul>
 */
public class AllTestsSHA256BatchedVector
    extends TestCase
{
    private static final int[] SHA256_IV = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };

    public static void main(String[] args)
    {
        junit.textui.TestRunner.run(suite());
    }

    public static Test suite()
    {
        TestSuite suite = new TestSuite("Batched SHA-256 Vector Tests (JDK 25)");
        suite.addTestSuite(AllTestsSHA256BatchedVector.class);
        return suite;
    }

    public void testBatchedFromIvMatchesScalar()
    {
        SecureRandom rnd = new SecureRandom();
        int lanes = SHA256BatchedVectorImpl.LANES;

        for (int trial = 0; trial < 16; ++trial)
        {
            // Each lane gets a 32-byte message — short enough that one
            // SHA-256 block holds the message plus standard padding.
            byte[][] msg = new byte[lanes][32];
            for (int b = 0; b < lanes; ++b)
            {
                rnd.nextBytes(msg[b]);
            }

            int[] blockData = new int[16 * lanes];
            for (int b = 0; b < lanes; ++b)
            {
                byte[] block = buildSha256Block(msg[b], 0);
                packLane(block, blockData, b, lanes);
            }

            int[] outState = new int[8 * lanes];
            SHA256BatchedVectorImpl.compressBatch(SHA256_IV, blockData, outState);

            for (int b = 0; b < lanes; ++b)
            {
                byte[] expected = scalarHash(msg[b]);
                byte[] actual = extractLaneOutput(outState, b, lanes, 32);
                assertBytesEqual("trial=" + trial + ", lane=" + b, expected, actual);
            }
        }
    }

    public void testBatchedFromMemoisedPreStateMatchesScalar()
    {
        // Mirror the SLH-DSA pkSeed-memoise pattern: pre-load 64 bytes
        // (pkSeed || zero pad) into the SHA-256 state, then run a single
        // additional block per lane.
        SecureRandom rnd = new SecureRandom();
        int lanes = SHA256BatchedVectorImpl.LANES;

        for (int trial = 0; trial < 16; ++trial)
        {
            byte[] pkSeed = new byte[16 + (trial & 0xF)];   // 16..31 bytes
            rnd.nextBytes(pkSeed);

            byte[] pkSeedBlock = new byte[64];
            System.arraycopy(pkSeed, 0, pkSeedBlock, 0, pkSeed.length);

            int[] preState = derivePreState(pkSeedBlock);

            byte[][] msg = new byte[lanes][22 + 16];   // 22-byte ADRS + 16-byte m1 fits one block
            for (int b = 0; b < lanes; ++b)
            {
                rnd.nextBytes(msg[b]);
            }

            int[] blockData = new int[16 * lanes];
            for (int b = 0; b < lanes; ++b)
            {
                // The trailing block is "msg[b] || padding" but the bit
                // length encodes the total seen by the digest (64 bytes
                // already absorbed + msg[b].length more).
                byte[] block = buildSha256Block(msg[b], 64);
                packLane(block, blockData, b, lanes);
            }

            int[] outState = new int[8 * lanes];
            SHA256BatchedVectorImpl.compressBatch(preState, blockData, outState);

            for (int b = 0; b < lanes; ++b)
            {
                // Scalar reference: SHA-256(pkSeedBlock || msg[b]).
                byte[] full = new byte[pkSeedBlock.length + msg[b].length];
                System.arraycopy(pkSeedBlock, 0, full, 0, pkSeedBlock.length);
                System.arraycopy(msg[b], 0, full, pkSeedBlock.length, msg[b].length);

                byte[] expected = scalarHash(full);
                byte[] actual = extractLaneOutput(outState, b, lanes, 32);
                assertBytesEqual("memoised trial=" + trial + ", lane=" + b, expected, actual);
            }
        }
    }

    // ----- helpers -----

    /** Builds a single 64-byte SHA-256 block containing {@code msg} plus
     *  the standard 0x80 / zero-pad / 64-bit-length tail.  The bit-length
     *  field encodes {@code (alreadyConsumed + msg.length) * 8} so the
     *  caller can simulate a memoised state that has already absorbed
     *  {@code alreadyConsumed} bytes.  Requires {@code msg.length <= 55} when
     *  {@code alreadyConsumed == 0}. */
    private static byte[] buildSha256Block(byte[] msg, int alreadyConsumed)
    {
        byte[] block = new byte[64];
        System.arraycopy(msg, 0, block, 0, msg.length);
        block[msg.length] = (byte)0x80;
        long totalBits = ((long)alreadyConsumed + msg.length) * 8L;
        for (int k = 0; k < 8; ++k)
        {
            block[56 + k] = (byte)(totalBits >>> ((7 - k) * 8));
        }
        return block;
    }

    private static void packLane(byte[] block, int[] blockData, int lane, int lanes)
    {
        for (int s = 0; s < 16; ++s)
        {
            blockData[s * lanes + lane] =
                  ((block[4*s    ] & 0xff) << 24)
                | ((block[4*s + 1] & 0xff) << 16)
                | ((block[4*s + 2] & 0xff) <<  8)
                | ((block[4*s + 3] & 0xff)      );
        }
    }

    private static byte[] extractLaneOutput(int[] outState, int lane, int lanes, int byteLen)
    {
        byte[] out = new byte[byteLen];
        for (int s = 0; s < (byteLen + 3) / 4; ++s)
        {
            int word = outState[s * lanes + lane];
            int off = s * 4;
            if (off     < byteLen) out[off    ] = (byte)(word >>> 24);
            if (off + 1 < byteLen) out[off + 1] = (byte)(word >>> 16);
            if (off + 2 < byteLen) out[off + 2] = (byte)(word >>>  8);
            if (off + 3 < byteLen) out[off + 3] = (byte)word;
        }
        return out;
    }

    private static byte[] scalarHash(byte[] in)
    {
        SHA256Digest d = new SHA256Digest();
        d.update(in, 0, in.length);
        byte[] out = new byte[d.getDigestSize()];
        d.doFinal(out, 0);
        return out;
    }

    /** Runs one SHA-256 compression of {@code pkSeedBlock} (64 bytes,
     *  unpadded — caller has already padded) starting from the IV and
     *  returns the resulting {@code H1..H8} state.  Mirrors what SLH-DSA's
     *  Sha2Engine.init memoises. */
    private static int[] derivePreState(byte[] pkSeedBlock)
    {
        int[] X = new int[64];
        for (int i = 0; i < 16; ++i)
        {
            X[i] = ((pkSeedBlock[4*i    ] & 0xff) << 24)
                 | ((pkSeedBlock[4*i + 1] & 0xff) << 16)
                 | ((pkSeedBlock[4*i + 2] & 0xff) <<  8)
                 | ((pkSeedBlock[4*i + 3] & 0xff)      );
        }
        int[] preState = SHA256_IV.clone();
        SHA256Digest.messageScheduleScalar(X);

        int a = preState[0], b = preState[1], c = preState[2], d = preState[3];
        int e = preState[4], f = preState[5], g = preState[6], h = preState[7];
        for (int t = 0; t < 64; ++t)
        {
            int s1 = Integer.rotateRight(e, 6) ^ Integer.rotateRight(e, 11) ^ Integer.rotateRight(e, 25);
            int ch = (e & f) ^ (~e & g);
            int t1 = h + s1 + ch + K[t] + X[t];
            int s0 = Integer.rotateRight(a, 2) ^ Integer.rotateRight(a, 13) ^ Integer.rotateRight(a, 22);
            int mj = (a & b) ^ (a & c) ^ (b & c);
            int t2 = s0 + mj;
            h = g; g = f; f = e; e = d + t1;
            d = c; c = b; b = a; a = t1 + t2;
        }
        preState[0] += a; preState[1] += b; preState[2] += c; preState[3] += d;
        preState[4] += e; preState[5] += f; preState[6] += g; preState[7] += h;
        return preState;
    }

    private static void assertBytesEqual(String tag, byte[] expected, byte[] actual)
    {
        for (int i = 0; i < expected.length; ++i)
        {
            if (expected[i] != actual[i])
            {
                StringBuilder eHex = new StringBuilder(), aHex = new StringBuilder();
                for (byte v : expected) eHex.append(String.format("%02x", v & 0xff));
                for (byte v : actual)   aHex.append(String.format("%02x", v & 0xff));
                fail(tag + " differs at byte " + i + ": expected=" + eHex + " actual=" + aHex);
            }
        }
    }

    private static final int[] K = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };
}