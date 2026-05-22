package org.bouncycastle.pqc.crypto.mldsa;

import java.security.SecureRandom;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

/**
 * Cross-checks the JDK 25 vectorised ML-DSA NTT against the inherited
 * scalar reference.  Same pattern as
 * {@code AllTestsMLKEMNttVector}: each test runs a random polynomial
 * through both the vector-aware {@code ntt}/{@code invNttToMont} entry
 * points and the package-private {@code nttScalar}/{@code invNttToMontScalar}
 * reference path, and asserts every coefficient matches.
 */
public class AllTestsMLDSANttVector
    extends TestCase
{
    public static void main(String[] args)
    {
        junit.textui.TestRunner.run(suite());
    }

    public static Test suite()
    {
        TestSuite suite = new TestSuite("ML-DSA NTT Vector Tests (JDK 25)");
        suite.addTestSuite(AllTestsMLDSANttVector.class);
        return suite;
    }

    public void testForwardVectorMatchesScalar()
    {
        SecureRandom rnd = new SecureRandom();
        for (int trial = 0; trial < 32; ++trial)
        {
            int[] a = randomCoefficients(rnd);

            int[] viaVector = Ntt.ntt(a);
            int[] viaScalar = Ntt.nttScalar(a);

            assertCoefficientsEqual("forward, trial=" + trial, viaScalar, viaVector);
        }
    }

    public void testInverseVectorMatchesScalar()
    {
        SecureRandom rnd = new SecureRandom();
        for (int trial = 0; trial < 32; ++trial)
        {
            int[] a = randomCoefficients(rnd);

            int[] viaVector = Ntt.invNttToMont(a);
            int[] viaScalar = Ntt.invNttToMontScalar(a);

            assertCoefficientsEqual("inverse, trial=" + trial, viaScalar, viaVector);
        }
    }

    public void testRoundTripVectorMatchesScalar()
    {
        SecureRandom rnd = new SecureRandom();
        for (int trial = 0; trial < 8; ++trial)
        {
            int[] a = randomCoefficients(rnd);

            int[] viaVector = Ntt.invNttToMont(Ntt.ntt(a));
            int[] viaScalar = Ntt.invNttToMontScalar(Ntt.nttScalar(a));

            assertCoefficientsEqual("round trip, trial=" + trial, viaScalar, viaVector);
        }
    }

    private static int[] randomCoefficients(SecureRandom rnd)
    {
        // ML-DSA coefficients live in (-q, q) with q=8380417; the input to
        // ntt() is typically reduced to that range.  Pick uniformly in
        // (-q, q) so reductions exercise the full input domain.
        int[] r = new int[MLDSAEngine.DilithiumN];
        for (int i = 0; i < r.length; ++i)
        {
            r[i] = rnd.nextInt(2 * MLDSAEngine.DilithiumQ) - MLDSAEngine.DilithiumQ;
        }
        return r;
    }

    private static void assertCoefficientsEqual(String tag, int[] expected, int[] actual)
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