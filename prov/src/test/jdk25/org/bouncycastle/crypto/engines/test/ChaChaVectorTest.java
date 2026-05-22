package org.bouncycastle.crypto.engines.test;

import java.security.SecureRandom;

import junit.framework.TestCase;
import org.bouncycastle.crypto.StreamCipher;
import org.bouncycastle.crypto.engines.ChaCha7539Engine;
import org.bouncycastle.crypto.engines.ChaChaEngine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

/**
 * Cross-checks the JDK 25+ vector overlay paths in {@link ChaChaEngine}
 * and {@link ChaCha7539Engine} against the inherited scalar path.
 * <p>
 * The vector path activates only above the {@code VECTOR_LANES * 64}
 * byte threshold, so feeding the same plaintext through the engine in
 * one large call (vector) and through a parallel engine instance in
 * single-byte calls (scalar) must produce byte-identical output.  The
 * test sweeps lengths that straddle the threshold and starting offsets
 * that exercise the partial-block prefix drain and the trailing tail.
 * <p>
 * RFC 7539 known-answer vectors for ChaCha7539 also run, guarding the
 * vector core against an arithmetic regression that would only surface
 * as a divergence from the published spec rather than a divergence
 * between two BC paths.
 */
public class ChaChaVectorTest
    extends TestCase
{
    public void testVectorMatchesScalar_ChaCha20()
        throws Exception
    {
        byte[] key = new byte[32];
        byte[] iv  = new byte[8];
        new SecureRandom().nextBytes(key);
        new SecureRandom().nextBytes(iv);

        for (int len : new int[]{ 0, 1, 63, 64, 65, 255, 256, 257, 511, 512, 513,
                                  1024, 4096, 4097 })
        {
            byte[] pt = new byte[len];
            new SecureRandom().nextBytes(pt);
            assertEqualsViaBothPaths(new ChaChaEngine(), new ChaChaEngine(),
                key, iv, pt);
        }
    }

    public void testVectorMatchesScalar_ChaCha7539()
        throws Exception
    {
        byte[] key = new byte[32];
        byte[] iv  = new byte[12];
        new SecureRandom().nextBytes(key);
        new SecureRandom().nextBytes(iv);

        for (int len : new int[]{ 0, 1, 63, 64, 65, 255, 256, 257, 511, 512, 513,
                                  1024, 4096, 4097 })
        {
            byte[] pt = new byte[len];
            new SecureRandom().nextBytes(pt);
            assertEqualsViaBothPaths(new ChaCha7539Engine(), new ChaCha7539Engine(),
                key, iv, pt);
        }
    }

    public void testVectorMatchesScalar_StreamingOffsets_ChaCha20()
        throws Exception
    {
        byte[] key = new byte[32];
        byte[] iv  = new byte[8];
        new SecureRandom().nextBytes(key);
        new SecureRandom().nextBytes(iv);

        // Drive one engine with a partial-block warm-up call (length
        // chosen to leave it mid-block) followed by a large bulk call,
        // and another engine byte-by-byte over the same total stream;
        // the override must hand off the prefix to super, run the
        // vector path, and resume cleanly.
        for (int warmup : new int[]{ 1, 7, 32, 33, 63 })
        {
            int bulk = 4096;
            byte[] pt = new byte[warmup + bulk];
            new SecureRandom().nextBytes(pt);

            byte[] viaVector = new byte[pt.length];
            byte[] viaScalar = new byte[pt.length];

            StreamCipher v = new ChaChaEngine();
            v.init(true, new ParametersWithIV(new KeyParameter(key), iv));
            v.processBytes(pt, 0, warmup, viaVector, 0);
            v.processBytes(pt, warmup, bulk, viaVector, warmup);

            StreamCipher s = new ChaChaEngine();
            s.init(true, new ParametersWithIV(new KeyParameter(key), iv));
            for (int i = 0; i < pt.length; ++i)
            {
                viaScalar[i] = s.returnByte(pt[i]);
            }

            assertTrue("warmup=" + warmup, Arrays.areEqual(viaVector, viaScalar));
        }
    }

    public void testRfc7539KAT()
        throws Exception
    {
        // RFC 7539 §2.4.2 example: counter starts at 1.
        byte[] key   = Hex.decode("000102030405060708090a0b0c0d0e0f"
                                + "101112131415161718191a1b1c1d1e1f");
        byte[] nonce = Hex.decode("000000000000004a00000000");
        byte[] plain = ("Ladies and Gentlemen of the class of '99: If I could "
                      + "offer you only one tip for the future, sunscreen would be it.")
                          .getBytes("US-ASCII");
        byte[] expected = Hex.decode(
              "6e2e359a2568f98041ba0728dd0d6981"
            + "e97e7aec1d4360c20a27afccfd9fae0b"
            + "f91b65c5524733ab8f593dabcd62b357"
            + "1639d624e65152ab8f530c359f0861d8"
            + "07ca0dbf500d6a6156a38e088a22b65e"
            + "52bc514d16ccf806818ce91ab7793736"
            + "5af90bbf74a35be6b40b8eedf2785e42"
            + "874d");

        // RFC 7539 conventionally encodes counter=1 in the first 32-bit
        // little-endian word of the keystream input block; BC's 7539
        // engine starts state[12] at 0 after init, so pre-skip 64 bytes
        // to reach counter=1 before encryption.
        byte[] zeroBlock = new byte[64];
        byte[] discard   = new byte[64];

        ChaCha7539Engine eng = new ChaCha7539Engine();
        eng.init(true, new ParametersWithIV(new KeyParameter(key), nonce));
        eng.processBytes(zeroBlock, 0, 64, discard, 0);

        byte[] out = new byte[plain.length];
        eng.processBytes(plain, 0, plain.length, out, 0);
        assertTrue("RFC 7539 §2.4.2 KAT", Arrays.areEqual(expected, out));
    }

    private static void assertEqualsViaBothPaths(StreamCipher vector,
                                                 StreamCipher scalar,
                                                 byte[] key, byte[] iv, byte[] pt)
    {
        vector.init(true, new ParametersWithIV(new KeyParameter(key), iv));
        scalar.init(true, new ParametersWithIV(new KeyParameter(key), iv));

        byte[] viaVector = new byte[pt.length];
        byte[] viaScalar = new byte[pt.length];

        if (pt.length > 0)
        {
            vector.processBytes(pt, 0, pt.length, viaVector, 0);
        }
        for (int i = 0; i < pt.length; ++i)
        {
            viaScalar[i] = scalar.returnByte(pt[i]);
        }

        assertTrue("len=" + pt.length, Arrays.areEqual(viaVector, viaScalar));
    }
}