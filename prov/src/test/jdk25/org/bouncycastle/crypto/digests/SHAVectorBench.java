package org.bouncycastle.crypto.digests;

import java.util.Random;

/**
 * Microbenchmark for the JDK 25 SHA-256 / SHA-512 message-schedule
 * vector overlays.
 * <p>
 * Run with both the {@code jdk.incubator.vector} module and the
 * test-task property overrides:
 * <pre>
 *   java --add-modules jdk.incubator.vector \
 *        -Dorg.bouncycastle.sha256.vector.minLanes=2 \
 *        -Dorg.bouncycastle.sha512.vector.minLanes=2 \
 *        -cp ... org.bouncycastle.crypto.digests.SHAVectorBench
 * </pre>
 * Both kernels are reachable on the same JVM
 * ({@code SHA256VectorImpl.messageSchedule} and
 * {@code SHA256Digest.messageScheduleScalar}, plus their SHA-512
 * counterparts), so the only difference between the two timed loops is
 * the inner kernel.
 */
public final class SHAVectorBench
{
    private static final int WARMUP = 100_000;
    private static final int ITERS  = 1_000_000;

    public static void main(String[] args)
    {
        runSha256Schedule();
        runSha512Schedule();
    }

    private static void runSha256Schedule()
    {
        int[] base = randomInts(0xDECAF, 16);
        int[] buf = new int[64];

        for (int i = 0; i < WARMUP; ++i)
        {
            System.arraycopy(base, 0, buf, 0, 16);
            SHA256VectorImpl.messageSchedule(buf);
        }
        long tVec = 0;
        for (int i = 0; i < ITERS; ++i)
        {
            System.arraycopy(base, 0, buf, 0, 16);
            long t0 = System.nanoTime();
            SHA256VectorImpl.messageSchedule(buf);
            tVec += System.nanoTime() - t0;
        }

        for (int i = 0; i < WARMUP; ++i)
        {
            System.arraycopy(base, 0, buf, 0, 16);
            SHA256Digest.messageScheduleScalar(buf);
        }
        long tScalar = 0;
        for (int i = 0; i < ITERS; ++i)
        {
            System.arraycopy(base, 0, buf, 0, 16);
            long t0 = System.nanoTime();
            SHA256Digest.messageScheduleScalar(buf);
            tScalar += System.nanoTime() - t0;
        }

        report("SHA-256 schedule", tVec, tScalar);
    }

    private static void runSha512Schedule()
    {
        long[] base = randomLongs(0xDECAF, 16);
        long[] buf = new long[80];

        for (int i = 0; i < WARMUP; ++i)
        {
            System.arraycopy(base, 0, buf, 0, 16);
            SHA512VectorImpl.messageSchedule(buf);
        }
        long tVec = 0;
        for (int i = 0; i < ITERS; ++i)
        {
            System.arraycopy(base, 0, buf, 0, 16);
            long t0 = System.nanoTime();
            SHA512VectorImpl.messageSchedule(buf);
            tVec += System.nanoTime() - t0;
        }

        for (int i = 0; i < WARMUP; ++i)
        {
            System.arraycopy(base, 0, buf, 0, 16);
            LongDigest.messageScheduleScalar(buf);
        }
        long tScalar = 0;
        for (int i = 0; i < ITERS; ++i)
        {
            System.arraycopy(base, 0, buf, 0, 16);
            long t0 = System.nanoTime();
            LongDigest.messageScheduleScalar(buf);
            tScalar += System.nanoTime() - t0;
        }

        report("SHA-512 schedule", tVec, tScalar);
    }

    private static int[] randomInts(long seed, int n)
    {
        Random rnd = new Random(seed);
        int[] r = new int[n];
        for (int i = 0; i < n; ++i)
        {
            r[i] = rnd.nextInt();
        }
        return r;
    }

    private static long[] randomLongs(long seed, int n)
    {
        Random rnd = new Random(seed);
        long[] r = new long[n];
        for (int i = 0; i < n; ++i)
        {
            r[i] = rnd.nextLong();
        }
        return r;
    }

    private static void report(String label, long tVec, long tScalar)
    {
        double vNs = tVec / (double)ITERS;
        double sNs = tScalar / (double)ITERS;
        System.out.printf("%-22s  vector: %7.0f ns/op   scalar: %7.0f ns/op   speedup: %.2fx%n",
            label, vNs, sNs, sNs / vNs);
    }
}