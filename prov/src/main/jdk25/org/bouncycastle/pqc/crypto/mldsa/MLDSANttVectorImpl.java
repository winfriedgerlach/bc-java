package org.bouncycastle.pqc.crypto.mldsa;

import jdk.incubator.vector.IntVector;
import jdk.incubator.vector.LongVector;
import jdk.incubator.vector.VectorOperators;
import jdk.incubator.vector.VectorSpecies;

/**
 * Lane-parallel ML-DSA (Dilithium) NTT inner-loop kernels, built on the JDK
 * incubator Vector API.  ML-DSA polynomial coefficients are 32-bit signed
 * ints and Montgomery reduction multiplies them by a 32-bit zeta to
 * produce a 64-bit intermediate, so the kernel works in {@link LongVector}
 * with the matching half-wide {@link IntVector} for memory I/O.
 * <p>
 * One vector iteration of {@link #butterflyForward} or
 * {@link #butterflyInverse} applies {@link #LANES} independent butterflies
 * of one twiddle block.  The kernels apply only when the inner loop length
 * is at least {@link #LANES}; the caller falls back to the scalar pair
 * loop for the tail and for shorter twiddle blocks.
 * <p>
 * This class is loaded lazily by the JDK 25+ overlay of {@link Ntt}; if
 * {@code jdk.incubator.vector} is absent the overlay catches the linkage
 * error and runs the scalar path.
 */
final class MLDSANttVectorImpl
{
    private static final VectorSpecies<Long> LSPECIES = pickLongSpecies();
    private static final VectorSpecies<Integer> ISPECIES = pickIntSpecies();

    static final int LANES = LSPECIES.length();

    private static final long Q = MLDSAEngine.DilithiumQ;
    private static final long QINV = MLDSAEngine.DilithiumQinv;

    private static VectorSpecies<Long> pickLongSpecies()
    {
        VectorSpecies<Long> p = LongVector.SPECIES_PREFERRED;
        if (p.length() >= 8)
        {
            return LongVector.SPECIES_512;
        }
        if (p.length() >= 4)
        {
            return LongVector.SPECIES_256;
        }
        if (p.length() >= 2)
        {
            return LongVector.SPECIES_128;
        }
        return p;
    }

    private static VectorSpecies<Integer> pickIntSpecies()
    {
        // Match the LongVector lane count: an N-lane LongVector pairs with
        // an N-lane IntVector half its bit width for I2L / L2I conversions.
        int lanes = pickLongSpecies().length();
        if (lanes >= 8)
        {
            return IntVector.SPECIES_256;
        }
        if (lanes >= 4)
        {
            return IntVector.SPECIES_128;
        }
        return IntVector.SPECIES_64;
    }

    private MLDSANttVectorImpl()
    {
    }

    static int probe()
    {
        return LANES;
    }

    /**
     * Forward-NTT (Cooley–Tukey) butterfly over {@code [start, start + len)},
     * processing the leading {@code (len / LANES) * LANES} entries
     * lane-parallel.  Returns the index where the scalar tail must resume.
     */
    static int butterflyForward(int[] r, int start, int len, int zeta)
    {
        LongVector zetaV = LongVector.broadcast(LSPECIES, zeta);
        LongVector qV = LongVector.broadcast(LSPECIES, Q);
        LongVector qinvV = LongVector.broadcast(LSPECIES, QINV);

        int j = start;
        int end = start + len;
        while (j + LANES <= end)
        {
            LongVector rj  = loadIntsAsLongs(r, j);
            LongVector rjl = loadIntsAsLongs(r, j + len);

            LongVector u = montReduce(rjl.mul(zetaV), qV, qinvV);

            storeLongsAsInts(rj.add(u), r, j);
            storeLongsAsInts(rj.sub(u), r, j + len);

            j += LANES;
        }
        return j;
    }

    /**
     * Inverse-NTT (Gentleman–Sande) butterfly over {@code [start, start + len)}.
     * Returns the resume point for any scalar tail.
     */
    static int butterflyInverse(int[] r, int start, int len, int zeta)
    {
        LongVector zetaV = LongVector.broadcast(LSPECIES, zeta);
        LongVector qV = LongVector.broadcast(LSPECIES, Q);
        LongVector qinvV = LongVector.broadcast(LSPECIES, QINV);

        int j = start;
        int end = start + len;
        while (j + LANES <= end)
        {
            LongVector t = loadIntsAsLongs(r, j);
            LongVector u = loadIntsAsLongs(r, j + len);

            // r[j] = t + u
            // tmp  = t - u  (still int range)
            // r[j+len] = montgomeryReduce(zeta * tmp)
            storeLongsAsInts(t.add(u), r, j);
            LongVector diff = t.sub(u);
            storeLongsAsInts(montReduce(diff.mul(zetaV), qV, qinvV), r, j + len);

            j += LANES;
        }
        return j;
    }

    /**
     * Final {@code montgomeryReduce(f * out[j])} pass of {@code invNttToMont},
     * vectorised over the leading {@code (n / LANES) * LANES} entries.
     */
    static int scaleAll(int[] r, int factor, int n)
    {
        LongVector factorV = LongVector.broadcast(LSPECIES, factor);
        LongVector qV = LongVector.broadcast(LSPECIES, Q);
        LongVector qinvV = LongVector.broadcast(LSPECIES, QINV);

        int i = 0;
        int limit = n - LANES;
        while (i <= limit)
        {
            LongVector v = loadIntsAsLongs(r, i);
            storeLongsAsInts(montReduce(v.mul(factorV), qV, qinvV), r, i);
            i += LANES;
        }
        return i;
    }

    private static LongVector montReduce(LongVector a, LongVector qV, LongVector qinvV)
    {
        // Mirrors Reduce.montgomeryReduce(long):
        //   int  t  = (int)(a * Qinv);              // low 32 bits
        //   long ta = (a - (long)t * Q) >>> 32;     // logical shift
        //   return (int)ta;
        LongVector t = a.mul(qinvV);
        // sign-extend low 32 bits: (t << 32) >> 32  (arithmetic)
        t = t.lanewise(VectorOperators.LSHL, 32).lanewise(VectorOperators.ASHR, 32);
        LongVector tQ = t.mul(qV);
        LongVector r = a.sub(tQ);
        // logical (unsigned) right shift by 32, mirroring `>>> 32`
        return r.lanewise(VectorOperators.LSHR, 32);
    }

    private static LongVector loadIntsAsLongs(int[] r, int off)
    {
        return (LongVector)IntVector.fromArray(ISPECIES, r, off)
            .convertShape(VectorOperators.I2L, LSPECIES, 0);
    }

    private static void storeLongsAsInts(LongVector v, int[] r, int off)
    {
        IntVector iv = (IntVector)v.convertShape(VectorOperators.L2I, ISPECIES, 0);
        iv.intoArray(r, off);
    }
}