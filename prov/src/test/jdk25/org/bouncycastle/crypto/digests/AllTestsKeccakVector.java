package org.bouncycastle.crypto.digests;

import java.security.SecureRandom;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.bouncycastle.util.encoders.Hex;

/**
 * Cross-checks the JDK 25 vectorised Keccak-f[1600] permutation against
 * the inherited scalar reference, plus published FIPS-202 / Keccak test
 * vectors.  The overlay's {@link KeccakDigest#forceScalarPath} field
 * (package-private) lets the test pin a digest to the scalar path
 * back-to-back with a default-dispatched vector digest, so any
 * divergence shows up as a byte-level mismatch in the fuzz tests below.
 * <p>
 * Coverage spans the legacy {@link KeccakDigest}, {@link SHA3Digest}
 * (FIPS-202 fixed-length), and {@link SHAKEDigest} (FIPS-202 XOF).
 * SHA-3 / SHAKE inherit the overlay's permutation through the parent
 * class, so a single overlay covers all three subclass hierarchies.
 */
public class AllTestsKeccakVector
    extends TestCase
{
    public static void main(String[] args)
    {
        junit.textui.TestRunner.run(suite());
    }

    public static Test suite()
    {
        TestSuite suite = new TestSuite("Keccak Vector Tests (JDK 25)");
        suite.addTestSuite(AllTestsKeccakVector.class);
        return suite;
    }

    /** FIPS-202 §B.1: SHA3-256("abc"). */
    public void testSha3_256_abc()
    {
        byte[] expected = Hex.decode(
            "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532");
        byte[] in = "abc".getBytes();
        assertSha3Equals(256, in, expected, false);
        assertSha3Equals(256, in, expected, true);
    }

    /** FIPS-202: SHA3-512("abc"). */
    public void testSha3_512_abc()
    {
        byte[] expected = Hex.decode(
            "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e"
          + "10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0");
        byte[] in = "abc".getBytes();
        assertSha3Equals(512, in, expected, false);
        assertSha3Equals(512, in, expected, true);
    }

    /** Empty-input SHA3-256. */
    public void testSha3_256_empty()
    {
        byte[] expected = Hex.decode(
            "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a");
        byte[] in = new byte[0];
        assertSha3Equals(256, in, expected, false);
        assertSha3Equals(256, in, expected, true);
    }

    /**
     * Direct permutation cross-check: hash a randomised 25-word state
     * through both the vector kernel and the static scalar reference,
     * compare lane by lane.  This is the cleanest way to localise a
     * regression to the kernel itself rather than the absorb/squeeze
     * surrounding it.
     */
    public void testPermutationVectorMatchesScalar()
    {
        SecureRandom rnd = new SecureRandom();
        for (int trial = 0; trial < 64; ++trial)
        {
            long[] vec = new long[25];
            long[] ref = new long[25];
            for (int i = 0; i < 25; ++i)
            {
                long word = rnd.nextLong();
                vec[i] = word;
                ref[i] = word;
            }

            KeccakVectorImpl.permutation(vec);
            KeccakDigest.KeccakPermutationScalar(ref);

            for (int i = 0; i < 25; ++i)
            {
                if (vec[i] != ref[i])
                {
                    fail("permutation trial=" + trial + " state[" + i
                        + "]: vec=0x" + Long.toHexString(vec[i])
                        + " scalar=0x" + Long.toHexString(ref[i]));
                }
            }
        }
    }

    /**
     * Apply the permutation 24 consecutive times to the same state and
     * compare paths — exercises round-state evolution across many
     * permutations, not just the first one.
     */
    public void testRepeatedPermutationVectorMatchesScalar()
    {
        long[] vec = new long[25];
        long[] ref = new long[25];
        for (int i = 0; i < 25; ++i)
        {
            vec[i] = ref[i] = 0x0123456789abcdefL ^ ((long)i * 0x9e3779b97f4a7c15L);
        }

        for (int round = 0; round < 24; ++round)
        {
            KeccakVectorImpl.permutation(vec);
            KeccakDigest.KeccakPermutationScalar(ref);
            for (int i = 0; i < 25; ++i)
            {
                if (vec[i] != ref[i])
                {
                    fail("repeated permutation round=" + round + " state[" + i
                        + "]: vec=0x" + Long.toHexString(vec[i])
                        + " scalar=0x" + Long.toHexString(ref[i]));
                }
            }
        }
    }

    /**
     * Hash random inputs of varying sizes through both the vector and
     * scalar paths on the same JVM and assert byte-identical SHA3-256
     * digests.  Sizes exercise &lt;1 block, exact-rate, multi-block,
     * and odd-tail cases for the SHA3-256 rate (136 bytes).
     */
    public void testSha3RandomSizesVectorMatchesScalar()
    {
        SecureRandom rnd = new SecureRandom();
        int[] sizes = {0, 1, 17, 135, 136, 137, 271, 272, 273, 1024, 4096, 8192 + 17};
        for (int len : sizes)
        {
            byte[] in = new byte[len];
            rnd.nextBytes(in);

            byte[] vec = sha3(256, in, false);
            byte[] ref = sha3(256, in, true);

            for (int i = 0; i < vec.length; ++i)
            {
                if (vec[i] != ref[i])
                {
                    fail("SHA3-256 len=" + len + " differs at byte " + i
                        + ": vec=" + Hex.toHexString(vec)
                        + " scalar=" + Hex.toHexString(ref));
                }
            }
        }
    }

    /**
     * Same fuzz across SHA3-224 / SHA3-384 / SHA3-512 — different rates
     * (144 / 104 / 72 bytes respectively) so this stresses the absorb
     * loop on top of the permutation.
     */
    public void testSha3AllSizesVectorMatchesScalar()
    {
        SecureRandom rnd = new SecureRandom();
        int[] bitLens = {224, 384, 512};
        for (int bits : bitLens)
        {
            for (int len = 0; len <= 600; len += 37)
            {
                byte[] in = new byte[len];
                rnd.nextBytes(in);

                byte[] vec = sha3(bits, in, false);
                byte[] ref = sha3(bits, in, true);

                for (int i = 0; i < vec.length; ++i)
                {
                    if (vec[i] != ref[i])
                    {
                        fail("SHA3-" + bits + " len=" + len + " differs at byte " + i
                            + ": vec=" + Hex.toHexString(vec)
                            + " scalar=" + Hex.toHexString(ref));
                    }
                }
            }
        }
    }

    /**
     * SHAKE128 and SHAKE256 cross-path: extendable-output mode exercises
     * the squeeze loop calling the permutation across many output blocks
     * (we ask for 4096 output bytes to force ~32 squeeze permutations).
     */
    public void testShakeVectorMatchesScalar()
    {
        SecureRandom rnd = new SecureRandom();
        int[] shakeBits = {128, 256};
        int outBytes = 4096;

        for (int bits : shakeBits)
        {
            for (int inLen = 0; inLen <= 256; inLen += 41)
            {
                byte[] in = new byte[inLen];
                rnd.nextBytes(in);

                byte[] vec = shakeAll(bits, in, outBytes, false);
                byte[] ref = shakeAll(bits, in, outBytes, true);

                for (int i = 0; i < outBytes; ++i)
                {
                    if (vec[i] != ref[i])
                    {
                        fail("SHAKE" + bits + " inLen=" + inLen + " differs at byte " + i
                            + ": vec[..]=" + Hex.toHexString(vec, Math.max(0, i - 4), Math.min(8, vec.length - Math.max(0, i - 4)))
                            + " ref[..]=" + Hex.toHexString(ref, Math.max(0, i - 4), Math.min(8, ref.length - Math.max(0, i - 4))));
                    }
                }
            }
        }
    }

    /**
     * Legacy {@link KeccakDigest} (NIST submission padding, not FIPS-202
     * SHA-3) — the original Bouncy Castle suite continues to test this
     * path, so the vector overlay must keep producing matching output.
     */
    public void testLegacyKeccakVectorMatchesScalar()
    {
        SecureRandom rnd = new SecureRandom();
        int[] bitLens = {224, 256, 288, 384, 512};
        for (int bits : bitLens)
        {
            for (int len = 0; len <= 400; len += 53)
            {
                byte[] in = new byte[len];
                rnd.nextBytes(in);

                byte[] vec = legacyKeccak(bits, in, false);
                byte[] ref = legacyKeccak(bits, in, true);

                for (int i = 0; i < vec.length; ++i)
                {
                    if (vec[i] != ref[i])
                    {
                        fail("Keccak-" + bits + " len=" + len + " differs at byte " + i
                            + ": vec=" + Hex.toHexString(vec)
                            + " scalar=" + Hex.toHexString(ref));
                    }
                }
            }
        }
    }

    private static byte[] sha3(int bits, byte[] in, boolean forceScalar)
    {
        SHA3Digest dig = new SHA3Digest(bits);
        dig.forceScalarPath = forceScalar;
        dig.update(in, 0, in.length);
        byte[] out = new byte[bits / 8];
        dig.doFinal(out, 0);
        return out;
    }

    private static byte[] shakeAll(int bits, byte[] in, int outBytes, boolean forceScalar)
    {
        SHAKEDigest dig = new SHAKEDigest(bits);
        dig.forceScalarPath = forceScalar;
        dig.update(in, 0, in.length);
        byte[] out = new byte[outBytes];
        dig.doFinal(out, 0, out.length);
        return out;
    }

    private static byte[] legacyKeccak(int bits, byte[] in, boolean forceScalar)
    {
        KeccakDigest dig = new KeccakDigest(bits);
        dig.forceScalarPath = forceScalar;
        dig.update(in, 0, in.length);
        byte[] out = new byte[bits / 8];
        dig.doFinal(out, 0);
        return out;
    }

    private static void assertSha3Equals(int bits, byte[] in, byte[] expected, boolean forceScalar)
    {
        byte[] actual = sha3(bits, in, forceScalar);
        for (int i = 0; i < expected.length; ++i)
        {
            if (actual[i] != expected[i])
            {
                fail((forceScalar ? "scalar" : "vector")
                    + " SHA3-" + bits + " mismatch at byte " + i
                    + ": actual=" + Hex.toHexString(actual)
                    + " expected=" + Hex.toHexString(expected));
            }
        }
    }
}
