package org.bouncycastle.pqc.crypto.mlkem;

import java.util.Random;

/**
 * Microbenchmark for the JDK 25 ML-KEM NTT vector overlay.
 * <p>
 * Run with both the {@code jdk.incubator.vector} module and the test-task
 * property override:
 * <pre>
 *   java --add-modules jdk.incubator.vector \
 *        -Dorg.bouncycastle.mlkem.ntt.vector.minLanes=4 \
 *        -cp ... org.bouncycastle.pqc.crypto.mlkem.NttBench
 * </pre>
 * The bench reads {@code Ntt.ntt} (vector-dispatched) and
 * {@code Ntt.nttScalar} (always scalar) on the same JVM; the only
 * difference between the two timed loops is the inner kernel.
 */
public final class NttBench
{
    private static final int POLY_SIZE = 256;
    private static final int WARMUP = 50_000;
    private static final int ITERS  = 500_000;

    public static void main(String[] args)
    {
        short[] base = randomPoly(0xC0FFEE);

        // Forward NTT
        runForward(base);

        // Inverse NTT — pre-NTT'd input so coefficients are in the
        // distribution invNtt actually sees in production.
        short[] forwarded = base.clone();
        Ntt.nttScalar(forwarded);
        runInverse(forwarded);
    }

    private static void runForward(short[] base)
    {
        short[] buf = new short[POLY_SIZE];

        for (int i = 0; i < WARMUP; ++i)
        {
            System.arraycopy(base, 0, buf, 0, POLY_SIZE);
            Ntt.ntt(buf);
        }
        long tVec = 0;
        for (int i = 0; i < ITERS; ++i)
        {
            System.arraycopy(base, 0, buf, 0, POLY_SIZE);
            long t0 = System.nanoTime();
            Ntt.ntt(buf);
            tVec += System.nanoTime() - t0;
        }

        for (int i = 0; i < WARMUP; ++i)
        {
            System.arraycopy(base, 0, buf, 0, POLY_SIZE);
            Ntt.nttScalar(buf);
        }
        long tScalar = 0;
        for (int i = 0; i < ITERS; ++i)
        {
            System.arraycopy(base, 0, buf, 0, POLY_SIZE);
            long t0 = System.nanoTime();
            Ntt.nttScalar(buf);
            tScalar += System.nanoTime() - t0;
        }

        report("ML-KEM ntt (forward)", tVec, tScalar);
    }

    private static void runInverse(short[] base)
    {
        short[] buf = new short[POLY_SIZE];

        for (int i = 0; i < WARMUP; ++i)
        {
            System.arraycopy(base, 0, buf, 0, POLY_SIZE);
            Ntt.invNtt(buf);
        }
        long tVec = 0;
        for (int i = 0; i < ITERS; ++i)
        {
            System.arraycopy(base, 0, buf, 0, POLY_SIZE);
            long t0 = System.nanoTime();
            Ntt.invNtt(buf);
            tVec += System.nanoTime() - t0;
        }

        for (int i = 0; i < WARMUP; ++i)
        {
            System.arraycopy(base, 0, buf, 0, POLY_SIZE);
            Ntt.invNttScalar(buf);
        }
        long tScalar = 0;
        for (int i = 0; i < ITERS; ++i)
        {
            System.arraycopy(base, 0, buf, 0, POLY_SIZE);
            long t0 = System.nanoTime();
            Ntt.invNttScalar(buf);
            tScalar += System.nanoTime() - t0;
        }

        report("ML-KEM invNtt (inverse)", tVec, tScalar);
    }

    private static short[] randomPoly(long seed)
    {
        Random rnd = new Random(seed);
        short[] r = new short[POLY_SIZE];
        for (int i = 0; i < POLY_SIZE; ++i)
        {
            r[i] = (short)rnd.nextInt(MLKEMEngine.Q);
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