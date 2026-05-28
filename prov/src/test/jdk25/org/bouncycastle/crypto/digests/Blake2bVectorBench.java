package org.bouncycastle.crypto.digests;

import java.util.Random;

/**
 * Microbench measuring per-block BLAKE2b compress throughput, vector
 * dispatch vs forced scalar, on the same JVM.  Both paths are reachable
 * via the overlay's package-private {@code forceScalarPath} hook.
 */
public final class Blake2bVectorBench
{
    private static final int WARMUP = 50_000;
    private static final int ITERS  = 500_000;

    public static void main(String[] args)
    {
        // Hash a 4 KiB buffer (= 32 BLAKE2b blocks).  Larger buffers
        // amortize the per-call setup; smaller ones expose it.
        runOne("BLAKE2b 4 KiB",   4096);
        runOne("BLAKE2b 64 KiB", 65536);
    }

    private static void runOne(String label, int byteLen)
    {
        Random rnd = new Random(0xB1ABE2BL ^ byteLen);
        byte[] data = new byte[byteLen];
        rnd.nextBytes(data);
        byte[] out = new byte[64];

        // Warmup + time the vector path.
        for (int i = 0; i < WARMUP; i++)
        {
            Blake2bDigest dig = new Blake2bDigest(512);
            dig.update(data, 0, data.length);
            dig.doFinal(out, 0);
        }
        long tVec = 0;
        for (int i = 0; i < ITERS; i++)
        {
            Blake2bDigest dig = new Blake2bDigest(512);
            long t0 = System.nanoTime();
            dig.update(data, 0, data.length);
            dig.doFinal(out, 0);
            tVec += System.nanoTime() - t0;
        }

        // Warmup + time forced scalar.
        for (int i = 0; i < WARMUP; i++)
        {
            Blake2bDigest dig = new Blake2bDigest(512);
            dig.forceScalarPath = true;
            dig.update(data, 0, data.length);
            dig.doFinal(out, 0);
        }
        long tScalar = 0;
        for (int i = 0; i < ITERS; i++)
        {
            Blake2bDigest dig = new Blake2bDigest(512);
            dig.forceScalarPath = true;
            long t0 = System.nanoTime();
            dig.update(data, 0, data.length);
            dig.doFinal(out, 0);
            tScalar += System.nanoTime() - t0;
        }

        report(label, tVec, tScalar);
    }

    private static void report(String label, long tVec, long tScalar)
    {
        double vUs = tVec / (double)ITERS / 1000.0;
        double sUs = tScalar / (double)ITERS / 1000.0;
        System.out.printf("%-22s  vector: %7.2f us/op   scalar: %7.2f us/op   speedup: %.2fx%n",
            label, vUs, sUs, sUs / vUs);
    }
}