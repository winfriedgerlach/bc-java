package org.bouncycastle.pqc.crypto.mlkem;

import jdk.incubator.vector.IntVector;
import jdk.incubator.vector.ShortVector;
import jdk.incubator.vector.VectorOperators;
import jdk.incubator.vector.VectorSpecies;

/**
 * Lane-parallel ML-KEM (Kyber) NTT inner-loop kernels, built on the JDK
 * incubator Vector API.  Each {@code IntVector} lane holds one ML-KEM
 * coefficient sign-extended from {@code short} to {@code int}; a single
 * vector iteration of {@link #butterflyForward} or {@link #butterflyInverse}
 * applies {@link #LANES} independent butterflies of one twiddle block.
 * <p>
 * The kernels apply only when the inner loop length is at least
 * {@link #LANES}; the caller falls back to the scalar pair loop for the
 * tail and for shorter twiddle blocks (NTT stages with {@code len < LANES}).
 * <p>
 * This class is loaded lazily by the JDK 25+ overlay of {@link Ntt}; if
 * {@code jdk.incubator.vector} is absent the overlay catches the linkage
 * error and runs the scalar path.
 */
final class MLKEMNttVectorImpl
{
    private static final VectorSpecies<Integer> ISPECIES = pickIntSpecies();
    private static final VectorSpecies<Short> SSPECIES = pickShortSpecies();

    static final int LANES = ISPECIES.length();

    private static final int Q = MLKEMEngine.Q;
    private static final int QINV = MLKEMEngine.Qinv;
    private static final int BARRETT_V = ((1 << 26) + (Q / 2)) / Q;

    private static VectorSpecies<Integer> pickIntSpecies()
    {
        VectorSpecies<Integer> p = IntVector.SPECIES_PREFERRED;
        if (p.length() >= 16)
        {
            return IntVector.SPECIES_512;
        }
        if (p.length() >= 8)
        {
            return IntVector.SPECIES_256;
        }
        if (p.length() >= 4)
        {
            return IntVector.SPECIES_128;
        }
        return p;
    }

    private static VectorSpecies<Short> pickShortSpecies()
    {
        // Match the IntVector lane count: an N-lane IntVector pairs with an
        // N-lane ShortVector half its bit width for S2I / I2S conversions.
        int lanes = pickIntSpecies().length();
        if (lanes >= 16)
        {
            return ShortVector.SPECIES_256;
        }
        if (lanes >= 8)
        {
            return ShortVector.SPECIES_128;
        }
        return ShortVector.SPECIES_64;
    }

    private MLKEMNttVectorImpl()
    {
    }

    static int probe()
    {
        return LANES;
    }

    /**
     * Forward-NTT (Cooley–Tukey) butterfly over the inner range
     * {@code [start, start + len)}, processing the leading
     * {@code (len / LANES) * LANES} entries lane-parallel.  Returns the
     * index where the scalar tail must resume; for {@code len} a multiple
     * of {@code LANES} (the only case used by this kernel) that's
     * {@code start + len}.
     */
    static int butterflyForward(short[] r, int start, int len, short zeta)
    {
        IntVector zetaV = IntVector.broadcast(ISPECIES, zeta);
        IntVector qV = IntVector.broadcast(ISPECIES, Q);
        IntVector qinvV = IntVector.broadcast(ISPECIES, QINV);

        int j = start;
        int end = start + len;
        while (j + LANES <= end)
        {
            IntVector rj  = loadShortsAsInts(r, j);
            IntVector rjl = loadShortsAsInts(r, j + len);

            IntVector u = montReduce(rjl.mul(zetaV), qV, qinvV);

            storeIntsAsShorts(rj.add(u), r, j);
            storeIntsAsShorts(rj.sub(u), r, j + len);

            j += LANES;
        }
        return j;
    }

    /**
     * Inverse-NTT (Gentleman–Sande) butterfly over {@code [start, start + len)}.
     * Returns the resume point for any scalar tail.
     */
    static int butterflyInverse(short[] r, int start, int len, short zeta)
    {
        IntVector zetaV = IntVector.broadcast(ISPECIES, zeta);
        IntVector qV = IntVector.broadcast(ISPECIES, Q);
        IntVector qinvV = IntVector.broadcast(ISPECIES, QINV);
        IntVector barrettV = IntVector.broadcast(ISPECIES, BARRETT_V);

        int j = start;
        int end = start + len;
        while (j + LANES <= end)
        {
            IntVector t = loadShortsAsInts(r, j);
            IntVector u = loadShortsAsInts(r, j + len);

            IntVector sum  = t.add(u);
            IntVector diff = t.sub(u);

            storeIntsAsShorts(barrettReduce(sum, qV, barrettV), r, j);
            storeIntsAsShorts(montReduce(diff.mul(zetaV), qV, qinvV), r, j + len);

            j += LANES;
        }
        return j;
    }

    /**
     * Final {@code mulMont(r[i], factor)} pass of {@code invNtt}, vectorised
     * over the leading {@code (n / LANES) * LANES} entries.  Returns the
     * resume index for any scalar tail.
     */
    static int scaleAll(short[] r, short factor, int n)
    {
        IntVector factorV = IntVector.broadcast(ISPECIES, factor);
        IntVector qV = IntVector.broadcast(ISPECIES, Q);
        IntVector qinvV = IntVector.broadcast(ISPECIES, QINV);

        int i = 0;
        int limit = n - LANES;
        while (i <= limit)
        {
            IntVector v = loadShortsAsInts(r, i);
            storeIntsAsShorts(montReduce(v.mul(factorV), qV, qinvV), r, i);
            i += LANES;
        }
        return i;
    }

    private static IntVector montReduce(IntVector a, IntVector qV, IntVector qinvV)
    {
        // Mirrors Reduce.montgomeryReduce(int):
        //   short u = (short)(a * Qinv);   -> sign-extend low 16 bits of (a * Qinv)
        //   int t = u * Q;
        //   t = a - t;
        //   t >>= 16;
        IntVector u = a.mul(qinvV);
        u = u.lanewise(VectorOperators.LSHL, 16).lanewise(VectorOperators.ASHR, 16);
        IntVector t = u.mul(qV);
        t = a.sub(t);
        return t.lanewise(VectorOperators.ASHR, 16);
    }

    private static IntVector barrettReduce(IntVector a, IntVector qV, IntVector barrettV)
    {
        // Mirrors Reduce.barrettReduce(short):
        //   short t = (short)((v * a) >> 26);
        //   t = (short)(t * Q);
        //   return (short)(a - t);
        // Both intermediate (short) casts wrap mod 2^16, which is preserved
        // by the final I2S truncation on store; we don't need to rematerialise
        // them inside the IntVector arithmetic.  The scalar path's input is a
        // (short)(t + u) value, so the low 16 bits of `a` are the only ones
        // that matter and we re-sign-extend them up front for parity.
        IntVector aShort = a.lanewise(VectorOperators.LSHL, 16).lanewise(VectorOperators.ASHR, 16);
        IntVector vt = aShort.mul(barrettV).lanewise(VectorOperators.ASHR, 26);
        IntVector tQ = vt.mul(qV);
        return aShort.sub(tQ);
    }

    private static IntVector loadShortsAsInts(short[] r, int off)
    {
        return (IntVector)ShortVector.fromArray(SSPECIES, r, off)
            .convertShape(VectorOperators.S2I, ISPECIES, 0);
    }

    private static void storeIntsAsShorts(IntVector v, short[] r, int off)
    {
        ShortVector sv = (ShortVector)v.convertShape(VectorOperators.I2S, SSPECIES, 0);
        sv.intoArray(r, off);
    }
}