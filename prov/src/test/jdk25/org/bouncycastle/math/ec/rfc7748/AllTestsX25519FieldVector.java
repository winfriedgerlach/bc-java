package org.bouncycastle.math.ec.rfc7748;

import java.security.SecureRandom;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.bouncycastle.util.encoders.Hex;

/**
 * Cross-checks the JDK 25 vectorised X25519Field carry-free element-wise
 * operations against the inherited scalar reference, plus the published
 * RFC 7748 X25519 test vectors.  The overlay's
 * {@link X25519Field#forceScalarPath} field (package-private) lets the
 * test pin a call site to the scalar path back-to-back with a default
 * dispatched call, so any divergence shows up as a byte-level mismatch
 * in the fuzz tests below.
 */
public class AllTestsX25519FieldVector
    extends TestCase
{
    public static void main(String[] args)
    {
        junit.textui.TestRunner.run(suite());
    }

    public static Test suite()
    {
        TestSuite suite = new TestSuite("X25519 Field Vector Tests (JDK 25)");
        suite.addTestSuite(AllTestsX25519FieldVector.class);
        return suite;
    }

    /** RFC 7748 §5.2 test vector 1: scalar=a546e..., u=e6db6...  →  c3da55... */
    public void testRfc7748Vector1()
    {
        byte[] scalar = Hex.decode(
            "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
        byte[] u = Hex.decode(
            "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
        byte[] expected = Hex.decode(
            "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552");

        byte[] r = new byte[32];
        X25519.scalarMult(scalar, 0, u, 0, r, 0);
        assertEquals("scalarMult vector path", Hex.toHexString(expected), Hex.toHexString(r));

        // Force scalar and re-check.
        X25519Field.forceScalarPath = true;
        try
        {
            byte[] r2 = new byte[32];
            X25519.scalarMult(scalar, 0, u, 0, r2, 0);
            assertEquals("scalarMult forced scalar", Hex.toHexString(expected), Hex.toHexString(r2));
        }
        finally
        {
            X25519Field.forceScalarPath = false;
        }
    }

    /** RFC 7748 §5.2 test vector 2. */
    public void testRfc7748Vector2()
    {
        byte[] scalar = Hex.decode(
            "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d");
        byte[] u = Hex.decode(
            "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493");
        byte[] expected = Hex.decode(
            "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957");

        byte[] r = new byte[32];
        X25519.scalarMult(scalar, 0, u, 0, r, 0);
        assertEquals("scalarMult vector path", Hex.toHexString(expected), Hex.toHexString(r));
    }

    public void testAddVectorMatchesScalar()
    {
        SecureRandom rnd = new SecureRandom();
        for (int trial = 0; trial < 256; ++trial)
        {
            int[] x = randomLimbs(rnd);
            int[] y = randomLimbs(rnd);
            int[] zVec = new int[10];
            int[] zRef = new int[10];

            X25519FieldVectorImpl.add(x, y, zVec);
            X25519Field.addScalar(x, y, zRef);

            assertLimbsEqual("add", zVec, zRef);
        }
    }

    public void testSubVectorMatchesScalar()
    {
        SecureRandom rnd = new SecureRandom();
        for (int trial = 0; trial < 256; ++trial)
        {
            int[] x = randomLimbs(rnd);
            int[] y = randomLimbs(rnd);
            int[] zVec = new int[10];
            int[] zRef = new int[10];

            X25519FieldVectorImpl.sub(x, y, zVec);
            X25519Field.subScalar(x, y, zRef);

            assertLimbsEqual("sub", zVec, zRef);
        }
    }

    public void testApmVectorMatchesScalar()
    {
        SecureRandom rnd = new SecureRandom();
        for (int trial = 0; trial < 256; ++trial)
        {
            int[] x = randomLimbs(rnd);
            int[] y = randomLimbs(rnd);
            int[] zpVec = new int[10];
            int[] zmVec = new int[10];
            int[] zpRef = new int[10];
            int[] zmRef = new int[10];

            X25519FieldVectorImpl.apm(x, y, zpVec, zmVec);
            X25519Field.apmScalar(x, y, zpRef, zmRef);

            assertLimbsEqual("apm zp", zpVec, zpRef);
            assertLimbsEqual("apm zm", zmVec, zmRef);
        }
    }

    public void testNegateVectorMatchesScalar()
    {
        SecureRandom rnd = new SecureRandom();
        for (int trial = 0; trial < 256; ++trial)
        {
            int[] x = randomLimbs(rnd);
            int[] zVec = new int[10];
            int[] zRef = new int[10];

            X25519FieldVectorImpl.negate(x, zVec);
            X25519Field.negateScalar(x, zRef);

            assertLimbsEqual("negate", zVec, zRef);
        }
    }

    public void testCopyVectorMatchesScalar()
    {
        SecureRandom rnd = new SecureRandom();
        for (int trial = 0; trial < 64; ++trial)
        {
            int[] x = new int[40];
            for (int i = 0; i < 40; ++i)
            {
                x[i] = rnd.nextInt();
            }
            int[] zVec = new int[40];
            int[] zRef = new int[40];

            X25519FieldVectorImpl.copy(x, 17, zVec, 5);
            X25519Field.copyScalar(x, 17, zRef, 5);

            for (int i = 0; i < 40; ++i)
            {
                assertEquals("copy[" + i + "]", zRef[i], zVec[i]);
            }
        }
    }

    public void testCmovVectorMatchesScalar()
    {
        SecureRandom rnd = new SecureRandom();
        for (int trial = 0; trial < 256; ++trial)
        {
            int cond = (trial & 1) == 0 ? 0 : -1;
            int[] x = new int[20];
            int[] vec = new int[20];
            int[] ref = new int[20];
            for (int i = 0; i < 20; ++i)
            {
                x[i] = rnd.nextInt();
                int v = rnd.nextInt();
                vec[i] = v;
                ref[i] = v;
            }

            X25519FieldVectorImpl.cmov(cond, x, 5, vec, 5);
            X25519Field.cmovScalar(cond, x, 5, ref, 5);

            for (int i = 0; i < 20; ++i)
            {
                assertEquals("cmov[" + i + "] cond=" + cond, ref[i], vec[i]);
            }
        }
    }

    public void testCnegateVectorMatchesScalar()
    {
        SecureRandom rnd = new SecureRandom();
        for (int trial = 0; trial < 256; ++trial)
        {
            int negate = trial & 1;
            int[] vec = randomLimbs(rnd);
            int[] ref = vec.clone();

            X25519FieldVectorImpl.cnegate(negate, vec);
            X25519Field.cnegateScalar(negate, ref);

            assertLimbsEqual("cnegate negate=" + negate, vec, ref);
        }
    }

    public void testCswapVectorMatchesScalar()
    {
        SecureRandom rnd = new SecureRandom();
        for (int trial = 0; trial < 256; ++trial)
        {
            int swap = trial & 1;
            int[] aVec = randomLimbs(rnd);
            int[] bVec = randomLimbs(rnd);
            int[] aRef = aVec.clone();
            int[] bRef = bVec.clone();

            X25519FieldVectorImpl.cswap(swap, aVec, bVec);
            X25519Field.cswapScalar(swap, aRef, bRef);

            assertLimbsEqual("cswap a swap=" + swap, aVec, aRef);
            assertLimbsEqual("cswap b swap=" + swap, bVec, bRef);
        }
    }

    /**
     * End-to-end fuzz: for each random scalar and basepoint, run a
     * full X25519 scalarMult through the vector path and the forced
     * scalar path on the same JVM and assert the 32-byte outputs
     * match.  Exercises the entire Montgomery ladder (apm / sub / add
     * / cswap and the surrounding scalar mul / sqr) end-to-end, not
     * just the kernels in isolation.
     */
    public void testScalarMultVectorMatchesScalar()
    {
        SecureRandom rnd = new SecureRandom();
        for (int trial = 0; trial < 32; ++trial)
        {
            byte[] scalar = new byte[32];
            byte[] u = new byte[32];
            rnd.nextBytes(scalar);
            rnd.nextBytes(u);

            byte[] rVec = new byte[32];
            X25519.scalarMult(scalar, 0, u, 0, rVec, 0);

            byte[] rRef = new byte[32];
            X25519Field.forceScalarPath = true;
            try
            {
                X25519.scalarMult(scalar, 0, u, 0, rRef, 0);
            }
            finally
            {
                X25519Field.forceScalarPath = false;
            }

            assertEquals("scalarMult trial=" + trial,
                Hex.toHexString(rRef), Hex.toHexString(rVec));
        }
    }

    private static int[] randomLimbs(SecureRandom rnd)
    {
        int[] out = new int[10];
        for (int i = 0; i < 10; ++i)
        {
            out[i] = rnd.nextInt();
        }
        return out;
    }

    private static void assertLimbsEqual(String label, int[] vec, int[] ref)
    {
        for (int i = 0; i < 10; ++i)
        {
            if (vec[i] != ref[i])
            {
                fail(label + " differs at limb " + i
                    + ": vec=0x" + Integer.toHexString(vec[i])
                    + " scalar=0x" + Integer.toHexString(ref[i]));
            }
        }
    }
}
