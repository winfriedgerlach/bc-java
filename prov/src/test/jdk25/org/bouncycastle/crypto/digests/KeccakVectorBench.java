package org.bouncycastle.crypto.digests;

import java.util.Random;

/**
 * Microbench measuring Keccak-f[1600] permutation throughput, vector
 * dispatch vs forced scalar, on the same JVM.  Both paths are reachable
 * via the overlay's package-private {@code forceScalarPath} hook and
 * via the static {@link KeccakVectorImpl#permutation(long[])} /
 * {@link KeccakDigest#KeccakPermutationScalar(long[])} entries.
 */
public final class KeccakVectorBench
{
    // The bench drives both paths back-to-back on the same JVM via the
    // overlay's package-private forceScalarPath hook.  Iter counts here
    // are sized for the SLOW path on AVX2 with -Dorg.bouncycastle.keccak
    // .vector.minLanes=2 forcing SPECIES_512 emulation: the vector path
    // runs ~140× slower than scalar there, so 200k iters of a 4 KiB
    // input would take >6 minutes.  On AVX-512 hosts, raise these.
    private static final int WARMUP = 5_000;
    private static final int ITERS  = 20_000;

    public static void main(String[] args)
    {
        // Direct kernel comparison: 24 rounds on a 25-word state.
        runKernel();

        // End-to-end SHA3-256 hashing (4 KiB input ~ 30 absorb permutations).
        runDigest("SHA3-256 4 KiB", 4096);
    }

    private static void runKernel()
    {
        Random rnd = new Random(0xCEC4AC0DEL);
        long[] init = new long[25];
        for (int i = 0; i < 25; ++i)
        {
            init[i] = rnd.nextLong();
        }

        long[] vec = new long[25];
        long[] ref = new long[25];

        for (int i = 0; i < WARMUP; ++i)
        {
            System.arraycopy(init, 0, vec, 0, 25);
            KeccakVectorImpl.permutation(vec);
        }
        long tVec = 0;
        for (int i = 0; i < ITERS; ++i)
        {
            System.arraycopy(init, 0, vec, 0, 25);
            long t0 = System.nanoTime();
            KeccakVectorImpl.permutation(vec);
            tVec += System.nanoTime() - t0;
        }

        for (int i = 0; i < WARMUP; ++i)
        {
            System.arraycopy(init, 0, ref, 0, 25);
            KeccakDigest.KeccakPermutationScalar(ref);
        }
        long tScalar = 0;
        for (int i = 0; i < ITERS; ++i)
        {
            System.arraycopy(init, 0, ref, 0, 25);
            long t0 = System.nanoTime();
            KeccakDigest.KeccakPermutationScalar(ref);
            tScalar += System.nanoTime() - t0;
        }

        report("Keccak-f[1600] permutation", tVec, tScalar, ITERS);
    }

    private static void runDigest(String label, int byteLen)
    {
        Random rnd = new Random(0x5EC003L ^ byteLen);
        byte[] data = new byte[byteLen];
        rnd.nextBytes(data);
        byte[] out = new byte[32];

        for (int i = 0; i < WARMUP; ++i)
        {
            SHA3Digest dig = new SHA3Digest(256);
            dig.update(data, 0, data.length);
            dig.doFinal(out, 0);
        }
        long tVec = 0;
        for (int i = 0; i < ITERS; ++i)
        {
            SHA3Digest dig = new SHA3Digest(256);
            long t0 = System.nanoTime();
            dig.update(data, 0, data.length);
            dig.doFinal(out, 0);
            tVec += System.nanoTime() - t0;
        }

        for (int i = 0; i < WARMUP; ++i)
        {
            SHA3Digest dig = new SHA3Digest(256);
            dig.forceScalarPath = true;
            dig.update(data, 0, data.length);
            dig.doFinal(out, 0);
        }
        long tScalar = 0;
        for (int i = 0; i < ITERS; ++i)
        {
            SHA3Digest dig = new SHA3Digest(256);
            dig.forceScalarPath = true;
            long t0 = System.nanoTime();
            dig.update(data, 0, data.length);
            dig.doFinal(out, 0);
            tScalar += System.nanoTime() - t0;
        }

        report(label, tVec, tScalar, ITERS);
    }

    private static void report(String label, long tVec, long tScalar, int iters)
    {
        double vUs = tVec / (double)iters / 1000.0;
        double sUs = tScalar / (double)iters / 1000.0;
        System.out.printf("%-30s  vector: %8.3f us/op   scalar: %8.3f us/op   speedup: %.2fx%n",
            label, vUs, sUs, sUs / vUs);
    }
}
