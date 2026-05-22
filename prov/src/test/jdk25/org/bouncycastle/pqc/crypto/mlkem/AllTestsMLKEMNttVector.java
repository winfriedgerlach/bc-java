package org.bouncycastle.pqc.crypto.mlkem;

import java.security.SecureRandom;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

/**
 * Cross-checks the JDK 25 vectorized ML-KEM NTT against the inherited
 * scalar reference.  Both paths are reachable from the overlaid
 * {@link Ntt} class on the same JVM ({@code ntt} dispatches to vector
 * when {@code VECTOR_ENABLED}, {@code nttScalar} is package-private
 * for direct invocation), so each test runs the same random polynomial
 * through both and asserts every coefficient matches.
 */
public class AllTestsMLKEMNttVector
    extends TestCase
{
    public static void main(String[] args)
    {
        junit.textui.TestRunner.run(suite());
    }

    public static Test suite()
    {
        TestSuite suite = new TestSuite("ML-KEM NTT Vector Tests (JDK 25)");
        suite.addTestSuite(AllTestsMLKEMNttVector.class);
        return suite;
    }

    public void testForwardVectorMatchesScalar()
    {
        SecureRandom rnd = new SecureRandom();
        for (int trial = 0; trial < 32; ++trial)
        {
            short[] a = randomCoefficients(rnd);
            short[] b = a.clone();

            Ntt.ntt(a);
            Ntt.nttScalar(b);

            assertCoefficientsEqual("forward, trial=" + trial, b, a);
        }
    }

    public void testInverseVectorMatchesScalar()
    {
        SecureRandom rnd = new SecureRandom();
        for (int trial = 0; trial < 32; ++trial)
        {
            short[] a = randomCoefficients(rnd);
            short[] b = a.clone();

            Ntt.invNtt(a);
            Ntt.invNttScalar(b);

            assertCoefficientsEqual("inverse, trial=" + trial, b, a);
        }
    }

    public void testRoundTripPreservesInput()
    {
        SecureRandom rnd = new SecureRandom();
        for (int trial = 0; trial < 8; ++trial)
        {
            short[] a = randomCoefficients(rnd);
            short[] original = a.clone();

            Ntt.ntt(a);
            Ntt.invNtt(a);

            // After ntt + invNtt the output is a multiplied by the Montgomery
            // factor; for the equality check we compare against the
            // scalar-only round trip so any divergence between the paths
            // surfaces here regardless of the algebraic factor.
            short[] reference = original.clone();
            Ntt.nttScalar(reference);
            Ntt.invNttScalar(reference);

            assertCoefficientsEqual("round trip, trial=" + trial, reference, a);
        }
    }

    private static short[] randomCoefficients(SecureRandom rnd)
    {
        // ML-KEM coefficients live in [0, q) with q=3329; sampling a
        // slightly wider band ensures the reductions inside the kernels
        // exercise both the positive and negative input ranges.
        short[] r = new short[256];
        for (int i = 0; i < 256; ++i)
        {
            r[i] = (short)(rnd.nextInt(2 * MLKEMEngine.Q) - MLKEMEngine.Q);
        }
        return r;
    }

    private static void assertCoefficientsEqual(String tag, short[] expected, short[] actual)
    {
        for (int i = 0; i < expected.length; ++i)
        {
            if (expected[i] != actual[i])
            {
                fail(tag + ": coefficient " + i + " differs: expected="
                    + expected[i] + ", actual=" + actual[i]);
            }
        }
    }
}