package org.bouncycastle.crypto.signers.slhdsa;

import java.util.Random;

/**
 * Microbenchmark for the JDK 25 batched WOTS+ pkGen path.  Both the
 * vectorised and scalar pkGen are reachable on the same JVM
 * ({@link WotsPlus#pkGen} dispatches to vector when
 * {@code VECTOR_AVAILABLE}; {@link WotsPlus#pkGenScalar} is package-private
 * for direct invocation), so the only difference between the two timed
 * loops is the inner chain kernel.
 * <p>
 * Run with both the {@code jdk.incubator.vector} module and the test-task
 * minLanes overrides:
 * <pre>
 *   java --add-modules jdk.incubator.vector \
 *        -Dorg.bouncycastle.slhdsa.wots.vector.minLanes=2 \
 *        -cp ... org.bouncycastle.crypto.signers.slhdsa.WotsPlusBatchedBench
 * </pre>
 */
public final class WotsPlusBatchedBench
{
    private static final int WARMUP = 200;
    private static final int ITERS  = 2000;

    public static void main(String[] args)
    {
        // Three SLH-DSA SHA-2 parameter sets covering N = 16 / 24 / 32
        // and the small / fast WOTS_LEN values.  Each row is N, w, d,
        // a, k, h — same numbers as SLHDSAParameters.sha2_*.
        runOne("sha2-128s",  16, 16,  7, 12, 14, 63);
        runOne("sha2-192s",  24, 16,  7, 14, 17, 63);
        runOne("sha2-256s",  32, 16,  8, 14, 22, 64);
    }

    private static void runOne(String label, int n, int w, int d, int a, int k, int h)
    {
        SLHDSAEngine engine = new SLHDSAEngine.Sha2Engine(n, w, d, a, k, h);

        Random rnd = new Random(0xC0FFEEL ^ n);
        byte[] skSeed = new byte[n];
        byte[] pkSeed = new byte[n];
        rnd.nextBytes(skSeed);
        rnd.nextBytes(pkSeed);

        engine.init(pkSeed);

        ADRS adrs = new ADRS();
        adrs.setLayerAddress(0);
        adrs.setTreeAddress(0);
        adrs.setTypeAndClear(ADRS.WOTS_HASH);
        adrs.setKeyPairAddress(0);

        WotsPlus wots = new WotsPlus(engine);

        // Warmup + time vector path.
        for (int i = 0; i < WARMUP; i++)
        {
            wots.pkGen(skSeed, pkSeed, new ADRS(adrs));
        }
        long tVec = 0;
        for (int i = 0; i < ITERS; i++)
        {
            long t0 = System.nanoTime();
            wots.pkGen(skSeed, pkSeed, new ADRS(adrs));
            tVec += System.nanoTime() - t0;
        }

        // Warmup + time scalar path.
        for (int i = 0; i < WARMUP; i++)
        {
            wots.pkGenScalar(skSeed, pkSeed, new ADRS(adrs));
        }
        long tScalar = 0;
        for (int i = 0; i < ITERS; i++)
        {
            long t0 = System.nanoTime();
            wots.pkGenScalar(skSeed, pkSeed, new ADRS(adrs));
            tScalar += System.nanoTime() - t0;
        }

        report(label + " WOTS+ pkGen", tVec, tScalar);
    }

    private static void report(String label, long tVec, long tScalar)
    {
        double vUs = tVec / (double)ITERS / 1000.0;
        double sUs = tScalar / (double)ITERS / 1000.0;
        System.out.printf("%-26s  vector: %7.1f us/op   scalar: %7.1f us/op   speedup: %.2fx%n",
            label, vUs, sUs, sUs / vUs);
    }
}