package org.bouncycastle.math.ec.rfc7748;

import java.security.SecureRandom;

/**
 * Microbench measuring the JDK 25 vectorised X25519 field operations
 * (the carry-free 10-limb adds plus cswap) and a full X25519
 * scalarMult, vector dispatch vs forced scalar on the same JVM.
 * The overlay's {@code forceScalarPath} switch lets the same call
 * sites be timed under both paths.
 */
public final class X25519FieldVectorBench
{
    private static final int WARMUP = 50_000;
    private static final int ITERS  = 200_000;

    public static void main(String[] args)
    {
        SecureRandom rnd = new SecureRandom();
        int[] x = new int[10];
        int[] y = new int[10];
        int[] z = new int[10];
        int[] zp = new int[10];
        int[] zm = new int[10];
        for (int i = 0; i < 10; ++i)
        {
            x[i] = rnd.nextInt();
            y[i] = rnd.nextInt();
        }

        runOp("add        (10-limb)", () -> X25519FieldVectorImpl.add(x, y, z),
                                       () -> X25519Field.addScalar(x, y, z));
        runOp("sub        (10-limb)", () -> X25519FieldVectorImpl.sub(x, y, z),
                                       () -> X25519Field.subScalar(x, y, z));
        runOp("apm        (10-limb)", () -> X25519FieldVectorImpl.apm(x, y, zp, zm),
                                       () -> X25519Field.apmScalar(x, y, zp, zm));
        runOp("cswap (swap=1)",       () -> X25519FieldVectorImpl.cswap(1, x, y),
                                       () -> X25519Field.cswapScalar(1, x, y));
        runOp("cmov  (cond=-1)",      () -> X25519FieldVectorImpl.cmov(-1, x, 0, z, 0),
                                       () -> X25519Field.cmovScalar(-1, x, 0, z, 0));

        runScalarMult();
    }

    private static void runOp(String label, Runnable vec, Runnable scalar)
    {
        for (int i = 0; i < WARMUP; ++i) vec.run();
        long tVec = 0;
        for (int i = 0; i < ITERS; ++i)
        {
            long t0 = System.nanoTime();
            vec.run();
            tVec += System.nanoTime() - t0;
        }

        for (int i = 0; i < WARMUP; ++i) scalar.run();
        long tScalar = 0;
        for (int i = 0; i < ITERS; ++i)
        {
            long t0 = System.nanoTime();
            scalar.run();
            tScalar += System.nanoTime() - t0;
        }

        report(label, tVec, tScalar, ITERS);
    }

    private static void runScalarMult()
    {
        SecureRandom rnd = new SecureRandom();
        byte[] scalar = new byte[32];
        byte[] u      = new byte[32];
        byte[] r      = new byte[32];
        rnd.nextBytes(scalar);
        rnd.nextBytes(u);

        // Vector path (default — VECTOR_ENABLED gate is on under the
        // test JVM's -Dorg.bouncycastle.x25519.vector.minLanes=2).
        for (int i = 0; i < 200; ++i) X25519.scalarMult(scalar, 0, u, 0, r, 0);
        long tVec = 0;
        int iters = 2_000;
        for (int i = 0; i < iters; ++i)
        {
            long t0 = System.nanoTime();
            X25519.scalarMult(scalar, 0, u, 0, r, 0);
            tVec += System.nanoTime() - t0;
        }

        X25519Field.forceScalarPath = true;
        try
        {
            for (int i = 0; i < 200; ++i) X25519.scalarMult(scalar, 0, u, 0, r, 0);
            long tScalar = 0;
            for (int i = 0; i < iters; ++i)
            {
                long t0 = System.nanoTime();
                X25519.scalarMult(scalar, 0, u, 0, r, 0);
                tScalar += System.nanoTime() - t0;
            }
            report("X25519 scalarMult", tVec, tScalar, iters);
        }
        finally
        {
            X25519Field.forceScalarPath = false;
        }
    }

    private static void report(String label, long tVec, long tScalar, int iters)
    {
        double vUs = tVec / (double)iters / 1000.0;
        double sUs = tScalar / (double)iters / 1000.0;
        System.out.printf("%-30s  vector: %9.4f us/op   scalar: %9.4f us/op   speedup: %.2fx%n",
            label, vUs, sUs, sUs / vUs);
    }
}
