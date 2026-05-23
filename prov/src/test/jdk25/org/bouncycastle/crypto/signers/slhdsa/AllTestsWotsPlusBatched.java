package org.bouncycastle.crypto.signers.slhdsa;

import java.security.SecureRandom;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.SLHDSAKeyPairGenerator;
import org.bouncycastle.crypto.params.SLHDSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.SLHDSAParameters;
import org.bouncycastle.crypto.params.SLHDSAPrivateKeyParameters;
import org.bouncycastle.crypto.params.SLHDSAPublicKeyParameters;
import org.bouncycastle.crypto.signers.SLHDSASigner;

/**
 * Asserts that the JDK 25 vectorised {@link WotsPlus#pkGen} produces
 * the same WOTS+ public-key bytes as the scalar reference, across the
 * SHA-2 SLH-DSA parameter sets ({@code N = 16, 24, 32}).  The overlay's
 * {@link WotsPlus#pkGenScalar} is package-private specifically so the
 * test can call both paths back-to-back with the same inputs.
 * <p>
 * Also runs an end-to-end SLH-DSA sign-and-verify cycle on the smallest
 * SHA-2 parameter set, to catch any indirect breakage along the path
 * (treehash → pkGen → T_l).
 */
public class AllTestsWotsPlusBatched
    extends TestCase
{
    public static void main(String[] args)
    {
        junit.textui.TestRunner.run(suite());
    }

    public static Test suite()
    {
        TestSuite suite = new TestSuite("WotsPlus Batched Vector Tests (JDK 25)");
        suite.addTestSuite(AllTestsWotsPlusBatched.class);
        return suite;
    }

    public void testPkGenVectorMatchesScalar_sha2_128s()
    {
        // n=16, w=16, d=7, a=12, k=14, h=63
        runPkGenMatch(new SLHDSAEngine.Sha2Engine(16, 16, 7, 12, 14, 63));
    }

    public void testPkGenVectorMatchesScalar_sha2_128f()
    {
        // n=16, w=16, d=22, a=6, k=33, h=66
        runPkGenMatch(new SLHDSAEngine.Sha2Engine(16, 16, 22, 6, 33, 66));
    }

    public void testPkGenVectorMatchesScalar_sha2_192s()
    {
        runPkGenMatch(new SLHDSAEngine.Sha2Engine(24, 16, 7, 14, 17, 63));
    }

    public void testPkGenVectorMatchesScalar_sha2_192f()
    {
        runPkGenMatch(new SLHDSAEngine.Sha2Engine(24, 16, 22, 8, 33, 66));
    }

    public void testPkGenVectorMatchesScalar_sha2_256s()
    {
        runPkGenMatch(new SLHDSAEngine.Sha2Engine(32, 16, 8, 14, 22, 64));
    }

    public void testPkGenVectorMatchesScalar_sha2_256f()
    {
        runPkGenMatch(new SLHDSAEngine.Sha2Engine(32, 16, 17, 9, 35, 68));
    }

    private void runPkGenMatch(SLHDSAEngine engine)
    {
        SecureRandom rnd = new SecureRandom();
        for (int trial = 0; trial < 4; trial++)
        {
            byte[] skSeed = new byte[engine.N];
            byte[] pkSeed = new byte[engine.N];
            rnd.nextBytes(skSeed);
            rnd.nextBytes(pkSeed);

            engine.init(pkSeed);

            ADRS adrs = new ADRS();
            adrs.setLayerAddress(0);
            adrs.setTreeAddress(rnd.nextLong() & 0x0FFFFFFFFFFFFFFFL);
            adrs.setTypeAndClear(ADRS.WOTS_HASH);
            adrs.setKeyPairAddress(trial);

            WotsPlus wots = new WotsPlus(engine);
            byte[] vec = wots.pkGen(skSeed, pkSeed, new ADRS(adrs));
            byte[] ref = wots.pkGenScalar(skSeed, pkSeed, new ADRS(adrs));

            if (vec.length != ref.length)
            {
                fail("N=" + engine.N + " trial=" + trial
                    + ": vector length " + vec.length + " != scalar " + ref.length);
            }
            for (int i = 0; i < vec.length; i++)
            {
                if (vec[i] != ref[i])
                {
                    fail("N=" + engine.N + " trial=" + trial
                        + ": pkGen mismatch at byte " + i
                        + " (vec=" + (vec[i] & 0xff)
                        + ", scalar=" + (ref[i] & 0xff) + ")");
                }
            }
        }
    }

    /**
     * End-to-end SLH-DSA round trip on sha2-128s — the smallest SHA-2
     * parameter set, ~250 ms keygen.  Goes through the batched WotsPlus
     * via treehash → pkGen and confirms a freshly generated signature
     * verifies.  If batching corrupts a single intermediate node, the
     * computed root won't match the embedded public key.
     */
    public void testEndToEndSignVerify_sha2_128s()
    {
        SecureRandom rnd = new SecureRandom();

        SLHDSAKeyPairGenerator kpg = new SLHDSAKeyPairGenerator();
        kpg.init(new SLHDSAKeyGenerationParameters(rnd, SLHDSAParameters.sha2_128s));
        AsymmetricCipherKeyPair kp = kpg.generateKeyPair();

        SLHDSAPublicKeyParameters pub = (SLHDSAPublicKeyParameters)kp.getPublic();
        SLHDSAPrivateKeyParameters priv = (SLHDSAPrivateKeyParameters)kp.getPrivate();

        byte[] msg = "vector-batched WOTS+ regression message".getBytes();

        SLHDSASigner signer = new SLHDSASigner();
        signer.init(true, priv);
        byte[] sig = signer.generateSignature(msg);

        SLHDSASigner verifier = new SLHDSASigner();
        verifier.init(false, pub);
        assertTrue("vectorised SLH-DSA sha2-128s signature failed to verify",
            verifier.verifySignature(msg, sig));
    }
}