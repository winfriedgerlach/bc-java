package org.bouncycastle.crypto.digests;

import java.security.SecureRandom;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.bouncycastle.util.encoders.Hex;

/**
 * Cross-checks the JDK 25 vectorised BLAKE2b compress against the
 * inherited scalar reference, plus the published RFC 7693 / canonical
 * test vectors.  The overlay's {@link Blake2bDigest#forceScalarPath}
 * field (package-private) lets the test pin a digest to the scalar
 * path back-to-back with a default-dispatched vector digest, so any
 * divergence shows up as a byte-level mismatch in the fuzz test below.
 */
public class AllTestsBlake2bVector
    extends TestCase
{
    public static void main(String[] args)
    {
        junit.textui.TestRunner.run(suite());
    }

    public static Test suite()
    {
        TestSuite suite = new TestSuite("BLAKE2b Vector Tests (JDK 25)");
        suite.addTestSuite(AllTestsBlake2bVector.class);
        return suite;
    }

    /** RFC 7693 §A.1: BLAKE2b-512 of "abc". */
    public void testKnownAnswer_abc_512()
    {
        byte[] expected = Hex.decode(
            "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1"
          + "7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923");
        assertDigestEquals(expected, "abc".getBytes(), false);
        assertDigestEquals(expected, "abc".getBytes(), true);
    }

    /** Empty-input BLAKE2b-512. */
    public void testKnownAnswer_empty_512()
    {
        byte[] expected = Hex.decode(
            "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419"
          + "d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce");
        assertDigestEquals(expected, new byte[0], false);
        assertDigestEquals(expected, new byte[0], true);
    }

    /**
     * Hash random inputs of varying sizes through both the vector and
     * scalar paths on the same JVM and assert byte-identical digests.
     * Sizes cover &lt;1 block, exact-block, multi-block, and odd tails.
     */
    public void testRandomInputsVectorMatchesScalar()
    {
        SecureRandom rnd = new SecureRandom();
        int[] sizes = {0, 1, 17, 64, 127, 128, 129, 255, 256, 1024, 4096, 8192 + 17};
        for (int len : sizes)
        {
            byte[] in = new byte[len];
            rnd.nextBytes(in);

            byte[] vec = hash(in, /*forceScalar=*/false);
            byte[] ref = hash(in, /*forceScalar=*/true);

            for (int i = 0; i < vec.length; i++)
            {
                if (vec[i] != ref[i])
                {
                    fail("BLAKE2b-512 len=" + len + " differs at byte " + i
                        + ": vec=" + Hex.toHexString(vec)
                        + " scalar=" + Hex.toHexString(ref));
                }
            }
        }
    }

    /**
     * Variable digest length (1..64 bytes) — exercises the
     * truncated-output path which post-processes the same chainValue
     * the compress() call produces.
     */
    public void testVariableDigestLengthsAcrossPaths()
    {
        SecureRandom rnd = new SecureRandom();
        byte[] in = new byte[256];
        rnd.nextBytes(in);

        for (int bits = 8; bits <= 512; bits += 8)
        {
            int byteLen = bits >>> 3;

            Blake2bDigest vec = new Blake2bDigest(bits);
            vec.update(in, 0, in.length);
            byte[] vecOut = new byte[byteLen];
            vec.doFinal(vecOut, 0);

            Blake2bDigest scalar = new Blake2bDigest(bits);
            scalar.forceScalarPath = true;
            scalar.update(in, 0, in.length);
            byte[] scalarOut = new byte[byteLen];
            scalar.doFinal(scalarOut, 0);

            for (int i = 0; i < byteLen; i++)
            {
                if (vecOut[i] != scalarOut[i])
                {
                    fail("BLAKE2b-" + bits + " differs at byte " + i
                        + ": vec=" + Hex.toHexString(vecOut)
                        + " scalar=" + Hex.toHexString(scalarOut));
                }
            }
        }
    }

    private static byte[] hash(byte[] in, boolean forceScalar)
    {
        Blake2bDigest dig = new Blake2bDigest(512);
        dig.forceScalarPath = forceScalar;
        dig.update(in, 0, in.length);
        byte[] out = new byte[64];
        dig.doFinal(out, 0);
        return out;
    }

    private static void assertDigestEquals(byte[] expected, byte[] in, boolean forceScalar)
    {
        byte[] out = hash(in, forceScalar);
        for (int i = 0; i < expected.length; i++)
        {
            if (out[i] != expected[i])
            {
                fail((forceScalar ? "scalar" : "vector")
                    + " BLAKE2b-512 mismatch at byte " + i
                    + ": actual=" + Hex.toHexString(out)
                    + " expected=" + Hex.toHexString(expected));
            }
        }
    }
}