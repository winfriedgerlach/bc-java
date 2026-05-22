package org.bouncycastle.pqc.crypto.mldsa;

import java.util.Random;

/**
 * Microbenchmark for the JDK 25 ML-DSA NTT vector overlay.
 * <p>
 * Run with both the {@code jdk.incubator.vector} module and the test-task
 * property override:
 * <pre>
 *   java --add-modules jdk.incubator.vector \
 *        -Dorg.bouncycastle.mldsa.ntt.vector.minLanes=2 \
 *        -cp ... org.bouncycastle.pqc.crypto.mldsa.NttBench
 * </pre>
 */
public final class NttBench
{
    private static final int POLY_SIZE = MLDSAEngine.DilithiumN;
    private static final int WARMUP = 30_000;
    private static final int ITERS  = 200_000;

    public static void main(String[] args)
    {
        int[] base = randomPoly(0xDA2A);

        runForward(base);
        runInverse(Ntt.nttScalar(base));
    }

    private static void runForward(int[] base)
    {
        for (int i = 0; i < WARMUP; ++i)
        {
            Ntt.ntt(base);
        }
        long tVec = 0;
        for (int i = 0; i < ITERS; ++i)
        {
            long t0 = System.nanoTime();
            Ntt.ntt(base);
            tVec += System.nanoTime() - t0;
        }

        for (int i = 0; i < WARMUP; ++i)
        {
            Ntt.nttScalar(base);
        }
        long tScalar = 0;
        for (int i = 0; i < ITERS; ++i)
        {
            long t0 = System.nanoTime();
            Ntt.nttScalar(base);
            tScalar += System.nanoTime() - t0;
        }

        report("ML-DSA ntt (forward)", tVec, tScalar);
    }

    private static void runInverse(int[] base)
    {
        for (int i = 0; i < WARMUP; ++i)
        {
            Ntt.invNttToMont(base);
        }
        long tVec = 0;
        for (int i = 0; i < ITERS; ++i)
        {
            long t0 = System.nanoTime();
            Ntt.invNttToMont(base);
            tVec += System.nanoTime() - t0;
        }

        for (int i = 0; i < WARMUP; ++i)
        {
            Ntt.invNttToMontScalar(base);
        }
        long tScalar = 0;
        for (int i = 0; i < ITERS; ++i)
        {
            long t0 = System.nanoTime();
            Ntt.invNttToMontScalar(base);
            tScalar += System.nanoTime() - t0;
        }

        report("ML-DSA invNttToMont", tVec, tScalar);
    }

    private static int[] randomPoly(long seed)
    {
        Random rnd = new Random(seed);
        int[] r = new int[POLY_SIZE];
        for (int i = 0; i < POLY_SIZE; ++i)
        {
            r[i] = rnd.nextInt(2 * MLDSAEngine.DilithiumQ) - MLDSAEngine.DilithiumQ;
        }
        return r;
    }

    private static void report(String label, long tVec, long tScalar)
    {
        double vNs = tVec / (double)ITERS;
        double sNs = tScalar / (double)ITERS;
        System.out.printf("%-26s  vector: %7.0f ns/op   scalar: %7.0f ns/op   speedup: %.2fx%n",
            label, vNs, sNs, sNs / vNs);
    }
}