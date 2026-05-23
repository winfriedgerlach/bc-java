package org.bouncycastle.crypto.digests;

import java.util.Random;

/**
 * Microbench measuring the raw {@link SHA256BatchedVectorImpl#compressBatch}
 * cost against {@code LANES} independent scalar {@link SHA256Digest}
 * one-block compressions, to isolate the kernel speedup from the
 * surrounding bookkeeping in
 * {@code WotsPlusBatchedBench}.
 */
public final class SHA256BatchedKernelBench
{
    private static final int WARMUP = 50_000;
    private static final int ITERS  = 500_000;

    public static void main(String[] args)
    {
        int lanes = SHA256BatchedVectorImpl.LANES;
        int[] preState = SHA256_IV.clone();

        Random rnd = new Random(0xBA7C0DE5L);
        int[] blockData = new int[16 * lanes];
        for (int i = 0; i < blockData.length; i++)
        {
            blockData[i] = rnd.nextInt();
        }
        int[] outState = new int[8 * lanes];

        // Vector kernel.
        for (int i = 0; i < WARMUP; i++)
        {
            SHA256BatchedVectorImpl.compressBatch(preState, blockData, outState);
        }
        long tVec = 0;
        for (int i = 0; i < ITERS; i++)
        {
            long t0 = System.nanoTime();
            SHA256BatchedVectorImpl.compressBatch(preState, blockData, outState);
            tVec += System.nanoTime() - t0;
        }

        // LANES independent scalar one-block hashes — mirrors the work
        // a sequential implementation of the same batched call would do.
        byte[][] msg = new byte[lanes][32]; // 32-byte input fits one block
        for (int b = 0; b < lanes; b++)
        {
            rnd.nextBytes(msg[b]);
        }
        byte[][] out = new byte[lanes][32];

        for (int i = 0; i < WARMUP; i++)
        {
            for (int b = 0; b < lanes; b++)
            {
                scalarOneBlock(msg[b], out[b]);
            }
        }
        long tScalar = 0;
        for (int i = 0; i < ITERS; i++)
        {
            long t0 = System.nanoTime();
            for (int b = 0; b < lanes; b++)
            {
                scalarOneBlock(msg[b], out[b]);
            }
            tScalar += System.nanoTime() - t0;
        }

        double vNs = tVec / (double)ITERS;
        double sNs = tScalar / (double)ITERS;
        System.out.printf("compressBatch (LANES=%d)   vector: %7.0f ns/call   scalar (x%d): %7.0f ns/call   speedup: %.2fx%n",
            lanes, vNs, lanes, sNs, sNs / vNs);
    }

    private static void scalarOneBlock(byte[] msg, byte[] out)
    {
        SHA256Digest d = new SHA256Digest();
        d.update(msg, 0, msg.length);
        d.doFinal(out, 0);
    }

    private static final int[] SHA256_IV = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };
}