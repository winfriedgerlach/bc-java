package org.bouncycastle.crypto.digests;

import java.security.SecureRandom;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.bouncycastle.util.encoders.Hex;

/**
 * Cross-checks the JDK 25 vectorized SHA-256 / SHA-512 message-schedule
 * expansion against the inherited scalar reference, and verifies that
 * full digests through the overlaid {@link SHA256Digest} /
 * {@link SHA512Digest} match the published FIPS 180-2 test vectors.
 * <p>
 * The {@code SHA256VectorImpl.messageSchedule} and the package-private
 * {@code SHA256Digest.messageScheduleScalar} (and their SHA-512
 * counterparts) are reachable from the overlay on the same JVM, so each
 * test runs the same random {@code X[0..15]} block through both and
 * asserts every expanded word matches.
 */
public class AllTestsSHAVector
    extends TestCase
{
    public static void main(String[] args)
    {
        junit.textui.TestRunner.run(suite());
    }

    public static Test suite()
    {
        TestSuite suite = new TestSuite("SHA-256 / SHA-512 Message-Schedule Vector Tests (JDK 25)");
        suite.addTestSuite(AllTestsSHAVector.class);
        return suite;
    }

    public void testSha256MessageScheduleVectorMatchesScalar()
    {
        SecureRandom rnd = new SecureRandom();
        for (int trial = 0; trial < 64; ++trial)
        {
            int[] vec = new int[64];
            int[] ref = new int[64];
            for (int i = 0; i < 16; ++i)
            {
                int word = rnd.nextInt();
                vec[i] = word;
                ref[i] = word;
            }

            SHA256VectorImpl.messageSchedule(vec);
            SHA256Digest.messageScheduleScalar(ref);

            for (int t = 16; t < 64; ++t)
            {
                if (vec[t] != ref[t])
                {
                    fail("SHA-256 schedule trial=" + trial + ", t=" + t
                        + ": vec=0x" + Integer.toHexString(vec[t])
                        + " scalar=0x" + Integer.toHexString(ref[t]));
                }
            }
        }
    }

    public void testSha512MessageScheduleVectorMatchesScalar()
    {
        SecureRandom rnd = new SecureRandom();
        for (int trial = 0; trial < 64; ++trial)
        {
            long[] vec = new long[80];
            long[] ref = new long[80];
            for (int i = 0; i < 16; ++i)
            {
                long word = rnd.nextLong();
                vec[i] = word;
                ref[i] = word;
            }

            SHA512VectorImpl.messageSchedule(vec);
            LongDigest.messageScheduleScalar(ref);

            for (int t = 16; t < 80; ++t)
            {
                if (vec[t] != ref[t])
                {
                    fail("SHA-512 schedule trial=" + trial + ", t=" + t
                        + ": vec=0x" + Long.toHexString(vec[t])
                        + " scalar=0x" + Long.toHexString(ref[t]));
                }
            }
        }
    }

    /** FIPS 180-2 § B.1 / B.2: SHA-256 of "abc". */
    public void testSha256KnownAnswerAbc()
    {
        byte[] expected = Hex.decode(
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        assertDigestEquals(new SHA256Digest(), "abc".getBytes(), expected);
    }

    /** FIPS 180-2 § B.2: SHA-256 of the 56-byte "abcdbcdecde..." string spanning two blocks. */
    public void testSha256KnownAnswerTwoBlocks()
    {
        byte[] expected = Hex.decode(
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
        assertDigestEquals(new SHA256Digest(),
            "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".getBytes(),
            expected);
    }

    /** FIPS 180-2 § C.1: SHA-512 of "abc". */
    public void testSha512KnownAnswerAbc()
    {
        byte[] expected = Hex.decode(
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
          + "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");
        assertDigestEquals(new SHA512Digest(), "abc".getBytes(), expected);
    }

    /** FIPS 180-2 § C.2: SHA-512 of the 112-byte two-block string. */
    public void testSha512KnownAnswerTwoBlocks()
    {
        byte[] expected = Hex.decode(
            "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018"
          + "501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909");
        assertDigestEquals(new SHA512Digest(),
            ("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn"
           + "hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu").getBytes(),
            expected);
    }

    /**
     * Hash random inputs of varying lengths covering: short (single
     * partial block), exactly one block, exactly two blocks, an odd-tail
     * span, and many-block streaming.  The vector path produces the
     * reference here — failure mode is "vector schedule disagrees with
     * scalar somewhere we didn't manage to coax into the direct unit
     * test", which would surface as a wrong end-to-end digest.
     */
    public void testSha256RandomInputsVsLightweightReference()
    {
        SecureRandom rnd = new SecureRandom();
        int[] sizes = {0, 1, 17, 55, 56, 63, 64, 65, 119, 120, 127, 128, 1024, 8192 + 17};
        for (int len : sizes)
        {
            byte[] in = new byte[len];
            rnd.nextBytes(in);

            SHA256Digest dig = new SHA256Digest();
            dig.update(in, 0, len);
            byte[] vecOut = new byte[dig.getDigestSize()];
            dig.doFinal(vecOut, 0);

            byte[] refOut = referenceSha256(in);
            for (int i = 0; i < refOut.length; ++i)
            {
                if (vecOut[i] != refOut[i])
                {
                    fail("SHA-256 random size=" + len + ", byte=" + i
                        + " differs: vec=" + (vecOut[i] & 0xFF)
                        + ", ref=" + (refOut[i] & 0xFF));
                }
            }
        }
    }

    public void testSha512RandomInputsVsLightweightReference()
    {
        SecureRandom rnd = new SecureRandom();
        int[] sizes = {0, 1, 17, 55, 56, 111, 112, 127, 128, 129, 255, 256, 1024, 8192 + 17};
        for (int len : sizes)
        {
            byte[] in = new byte[len];
            rnd.nextBytes(in);

            SHA512Digest dig = new SHA512Digest();
            dig.update(in, 0, len);
            byte[] vecOut = new byte[dig.getDigestSize()];
            dig.doFinal(vecOut, 0);

            byte[] refOut = referenceSha512(in);
            for (int i = 0; i < refOut.length; ++i)
            {
                if (vecOut[i] != refOut[i])
                {
                    fail("SHA-512 random size=" + len + ", byte=" + i
                        + " differs: vec=" + (vecOut[i] & 0xFF)
                        + ", ref=" + (refOut[i] & 0xFF));
                }
            }
        }
    }

    private static void assertDigestEquals(org.bouncycastle.crypto.Digest dig, byte[] in, byte[] expected)
    {
        dig.update(in, 0, in.length);
        byte[] actual = new byte[dig.getDigestSize()];
        dig.doFinal(actual, 0);
        for (int i = 0; i < expected.length; ++i)
        {
            if (actual[i] != expected[i])
            {
                fail(dig.getAlgorithmName() + " digest mismatch at byte " + i
                    + ": actual=" + Hex.toHexString(actual)
                    + " expected=" + Hex.toHexString(expected));
            }
        }
    }

    /**
     * Independent SHA-256 reference using only scalar primitives, so it
     * stays untouched even when {@code VECTOR_ENABLED == true} forces
     * the production digest into the vector schedule.  Calls into the
     * overlaid {@link SHA256Digest#messageScheduleScalar(int[])} so we
     * avoid duplicating the full compression body, but routes the block
     * through a fresh state with the scalar schedule explicitly.
     */
    private static byte[] referenceSha256(byte[] in)
    {
        // Round-trip through a tiny in-test scalar implementation that's
        // deliberately pedestrian — its only job is to refuse to share
        // any code path with the vector kernel.
        int h0 = 0x6a09e667, h1 = 0xbb67ae85, h2 = 0x3c6ef372, h3 = 0xa54ff53a;
        int h4 = 0x510e527f, h5 = 0x9b05688c, h6 = 0x1f83d9ab, h7 = 0x5be0cd19;
        long bitLen = (long)in.length * 8L;

        int padLen = (in.length % 64 < 56) ? 64 - (in.length % 64) : 128 - (in.length % 64);
        byte[] msg = new byte[in.length + padLen];
        System.arraycopy(in, 0, msg, 0, in.length);
        msg[in.length] = (byte)0x80;
        for (int i = 0; i < 8; ++i)
        {
            msg[msg.length - 8 + i] = (byte)(bitLen >>> ((7 - i) * 8));
        }

        int[] X = new int[64];
        for (int blk = 0; blk < msg.length; blk += 64)
        {
            for (int i = 0; i < 16; ++i)
            {
                X[i] = ((msg[blk + 4*i] & 0xff) << 24)
                     | ((msg[blk + 4*i + 1] & 0xff) << 16)
                     | ((msg[blk + 4*i + 2] & 0xff) <<  8)
                     | ((msg[blk + 4*i + 3] & 0xff)      );
            }
            SHA256Digest.messageScheduleScalar(X);

            int a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, h = h7;
            for (int t = 0; t < 64; ++t)
            {
                int s1 = Integer.rotateRight(e, 6) ^ Integer.rotateRight(e, 11) ^ Integer.rotateRight(e, 25);
                int ch = (e & f) ^ (~e & g);
                int t1 = h + s1 + ch + K256[t] + X[t];
                int s0 = Integer.rotateRight(a, 2) ^ Integer.rotateRight(a, 13) ^ Integer.rotateRight(a, 22);
                int mj = (a & b) ^ (a & c) ^ (b & c);
                int t2 = s0 + mj;
                h = g; g = f; f = e; e = d + t1;
                d = c; c = b; b = a; a = t1 + t2;
            }
            h0 += a; h1 += b; h2 += c; h3 += d;
            h4 += e; h5 += f; h6 += g; h7 += h;
        }

        byte[] out = new byte[32];
        int[] hh = {h0, h1, h2, h3, h4, h5, h6, h7};
        for (int i = 0; i < 8; ++i)
        {
            out[4*i] = (byte)(hh[i] >>> 24);
            out[4*i + 1] = (byte)(hh[i] >>> 16);
            out[4*i + 2] = (byte)(hh[i] >>>  8);
            out[4*i + 3] = (byte)(hh[i]);
        }
        return out;
    }

    /** Independent SHA-512 reference, same shape as {@link #referenceSha256(byte[])}. */
    private static byte[] referenceSha512(byte[] in)
    {
        long h0 = 0x6a09e667f3bcc908L, h1 = 0xbb67ae8584caa73bL;
        long h2 = 0x3c6ef372fe94f82bL, h3 = 0xa54ff53a5f1d36f1L;
        long h4 = 0x510e527fade682d1L, h5 = 0x9b05688c2b3e6c1fL;
        long h6 = 0x1f83d9abfb41bd6bL, h7 = 0x5be0cd19137e2179L;
        long bitLen = (long)in.length * 8L;

        int padLen = (in.length % 128 < 112) ? 128 - (in.length % 128) : 256 - (in.length % 128);
        byte[] msg = new byte[in.length + padLen];
        System.arraycopy(in, 0, msg, 0, in.length);
        msg[in.length] = (byte)0x80;
        for (int i = 0; i < 8; ++i)
        {
            msg[msg.length - 8 + i] = (byte)(bitLen >>> ((7 - i) * 8));
        }

        long[] W = new long[80];
        for (int blk = 0; blk < msg.length; blk += 128)
        {
            for (int i = 0; i < 16; ++i)
            {
                long v = 0;
                for (int j = 0; j < 8; ++j)
                {
                    v = (v << 8) | (msg[blk + 8*i + j] & 0xff);
                }
                W[i] = v;
            }
            LongDigest.messageScheduleScalar(W);

            long a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, h = h7;
            for (int t = 0; t < 80; ++t)
            {
                long s1 = Long.rotateRight(e, 14) ^ Long.rotateRight(e, 18) ^ Long.rotateRight(e, 41);
                long ch = (e & f) ^ (~e & g);
                long t1 = h + s1 + ch + K512[t] + W[t];
                long s0 = Long.rotateRight(a, 28) ^ Long.rotateRight(a, 34) ^ Long.rotateRight(a, 39);
                long mj = (a & b) ^ (a & c) ^ (b & c);
                long t2 = s0 + mj;
                h = g; g = f; f = e; e = d + t1;
                d = c; c = b; b = a; a = t1 + t2;
            }
            h0 += a; h1 += b; h2 += c; h3 += d;
            h4 += e; h5 += f; h6 += g; h7 += h;
        }

        byte[] out = new byte[64];
        long[] hh = {h0, h1, h2, h3, h4, h5, h6, h7};
        for (int i = 0; i < 8; ++i)
        {
            for (int j = 0; j < 8; ++j)
            {
                out[8*i + j] = (byte)(hh[i] >>> ((7 - j) * 8));
            }
        }
        return out;
    }

    private static final int[] K256 = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };

    private static final long[] K512 = {
        0x428a2f98d728ae22L, 0x7137449123ef65cdL, 0xb5c0fbcfec4d3b2fL, 0xe9b5dba58189dbbcL,
        0x3956c25bf348b538L, 0x59f111f1b605d019L, 0x923f82a4af194f9bL, 0xab1c5ed5da6d8118L,
        0xd807aa98a3030242L, 0x12835b0145706fbeL, 0x243185be4ee4b28cL, 0x550c7dc3d5ffb4e2L,
        0x72be5d74f27b896fL, 0x80deb1fe3b1696b1L, 0x9bdc06a725c71235L, 0xc19bf174cf692694L,
        0xe49b69c19ef14ad2L, 0xefbe4786384f25e3L, 0x0fc19dc68b8cd5b5L, 0x240ca1cc77ac9c65L,
        0x2de92c6f592b0275L, 0x4a7484aa6ea6e483L, 0x5cb0a9dcbd41fbd4L, 0x76f988da831153b5L,
        0x983e5152ee66dfabL, 0xa831c66d2db43210L, 0xb00327c898fb213fL, 0xbf597fc7beef0ee4L,
        0xc6e00bf33da88fc2L, 0xd5a79147930aa725L, 0x06ca6351e003826fL, 0x142929670a0e6e70L,
        0x27b70a8546d22ffcL, 0x2e1b21385c26c926L, 0x4d2c6dfc5ac42aedL, 0x53380d139d95b3dfL,
        0x650a73548baf63deL, 0x766a0abb3c77b2a8L, 0x81c2c92e47edaee6L, 0x92722c851482353bL,
        0xa2bfe8a14cf10364L, 0xa81a664bbc423001L, 0xc24b8b70d0f89791L, 0xc76c51a30654be30L,
        0xd192e819d6ef5218L, 0xd69906245565a910L, 0xf40e35855771202aL, 0x106aa07032bbd1b8L,
        0x19a4c116b8d2d0c8L, 0x1e376c085141ab53L, 0x2748774cdf8eeb99L, 0x34b0bcb5e19b48a8L,
        0x391c0cb3c5c95a63L, 0x4ed8aa4ae3418acbL, 0x5b9cca4f7763e373L, 0x682e6ff3d6b2b8a3L,
        0x748f82ee5defb2fcL, 0x78a5636f43172f60L, 0x84c87814a1f0ab72L, 0x8cc702081a6439ecL,
        0x90befffa23631e28L, 0xa4506cebde82bde9L, 0xbef9a3f7b2c67915L, 0xc67178f2e372532bL,
        0xca273eceea26619cL, 0xd186b8c721c0c207L, 0xeada7dd6cde0eb1eL, 0xf57d4f7fee6ed178L,
        0x06f067aa72176fbaL, 0x0a637dc5a2c898a6L, 0x113f9804bef90daeL, 0x1b710b35131c471bL,
        0x28db77f523047d84L, 0x32caab7b40c72493L, 0x3c9ebe0a15c9bebcL, 0x431d67c49c100d4cL,
        0x4cc5d4becb3e42b6L, 0x597f299cfc657e2aL, 0x5fcb6fab3ad6faecL, 0x6c44198c4a475817L
    };
}