package org.bouncycastle.pqc.crypto.hqc;

import jdk.incubator.vector.LongVector;
import jdk.incubator.vector.VectorOperators;
import jdk.incubator.vector.VectorSpecies;

/**
 * Lane-parallel kernels for the GF(2) polynomial XOR / clear / merge
 * operations used by the HQC {@link GF2x} field.  GF(2) addition is
 * just bitwise XOR, and HQC operates on {@code long[]} polynomials
 * sized 277 / 561 / 901 longs (HQC-128 / 192 / 256), so all of these
 * loops are textbook lane-parallel work for {@link LongVector}.
 * <p>
 * Carry-less multiplication ({@link GF2x#implMulwAcc} word-level
 * bit-tricks) stays scalar — the inner kernel is sequential bit
 * manipulation, not lane-parallel work.
 * <p>
 * Loaded lazily by the JDK 25+ overlay of {@link GF2x}; if
 * {@code jdk.incubator.vector} is absent the overlay catches the
 * linkage error and runs the scalar reference.
 */
final class GF2xVectorImpl
{
    private static final VectorSpecies<Long> SPECIES = LongVector.SPECIES_PREFERRED;

    static final int LANES = SPECIES.length();

    private GF2xVectorImpl()
    {
    }

    static int probe()
    {
        return LANES;
    }

    /**
     * {@code z[i] ^= x[i]} for {@code i in [0, len)}.  Lane-parallel
     * via {@link LongVector#lanewise(VectorOperators.Binary, jdk.incubator.vector.Vector)}
     * on whatever the host's preferred LongVector width is, with a
     * scalar tail for the last (len % LANES) words.
     */
    static void xorTo(int len, long[] x, long[] z)
    {
        int i = 0;
        int bound = SPECIES.loopBound(len);
        for (; i < bound; i += LANES)
        {
            LongVector vx = LongVector.fromArray(SPECIES, x, i);
            LongVector vz = LongVector.fromArray(SPECIES, z, i);
            vx.lanewise(VectorOperators.XOR, vz).intoArray(z, i);
        }
        for (; i < len; ++i)
        {
            z[i] ^= x[i];
        }
    }

    /** {@code z[zOff + i] ^= x[xOff + i]}. */
    static void xorTo(int len, long[] x, int xOff, long[] z, int zOff)
    {
        int i = 0;
        int bound = SPECIES.loopBound(len);
        for (; i < bound; i += LANES)
        {
            LongVector vx = LongVector.fromArray(SPECIES, x, xOff + i);
            LongVector vz = LongVector.fromArray(SPECIES, z, zOff + i);
            vx.lanewise(VectorOperators.XOR, vz).intoArray(z, zOff + i);
        }
        for (; i < len; ++i)
        {
            z[zOff + i] ^= x[xOff + i];
        }
    }

    /** {@code z[zOff + i] ^= x[xOff + i] ^ y[yOff + i]}. */
    static void xorBothTo(int len, long[] x, int xOff, long[] y, int yOff, long[] z, int zOff)
    {
        int i = 0;
        int bound = SPECIES.loopBound(len);
        for (; i < bound; i += LANES)
        {
            LongVector vx = LongVector.fromArray(SPECIES, x, xOff + i);
            LongVector vy = LongVector.fromArray(SPECIES, y, yOff + i);
            LongVector vz = LongVector.fromArray(SPECIES, z, zOff + i);
            vx.lanewise(VectorOperators.XOR, vy)
                .lanewise(VectorOperators.XOR, vz)
                .intoArray(z, zOff + i);
        }
        for (; i < len; ++i)
        {
            z[zOff + i] ^= x[xOff + i] ^ y[yOff + i];
        }
    }

    /**
     * Karatsuba mid-coefficient XOR: applies the
     * {@code z[zOff + i] ^= zMid[zMidOff + i] ^ z0[z0Off + i] ^ z2[z2Off + i]}
     * recombination to {@code i in [0, mx2)} (where all three sources
     * are present), then the simpler
     * {@code z[zOff + i] ^= zMid[zMidOff + i] ^ z2[z2Off + i]} for
     * {@code i in [mx2, n1x2)} (where {@code z0[i]} would be zero
     * because the lower half ran out of words).  Folds the two cases
     * the scalar
     * <pre>
     *   for (int i = 0; i &lt; 2 * n1; i++) {
     *       long z0i = (i &lt; mx2) ? tmp[tmpOff + i] : 0;
     *       long z2i = (i &lt; n1x2) ? tmp[z2Offset + i] : 0;
     *       zz[zzOff + m + i] ^= tmp[zMidOffset + i] ^ z0i ^ z2i;
     *   }
     * </pre>
     * loop tracks; n1x2 is always at least mx2 because n1 = len - m and
     * m = len &gt;&gt; 1, so n1 ≥ m, so the i ≥ n1x2 case never fires.
     */
    static void karatsubaMidXor(long[] zz, int zzOff,
        long[] zMid, int zMidOff,
        long[] z0, int z0Off, int mx2,
        long[] z2, int z2Off, int n1x2)
    {
        // Triple-XOR for the overlap range.
        xorBothTo(mx2, zMid, zMidOff, z0, z0Off, zz, zzOff);
        // Then add z2 across the full range; we already folded zMid into zz
        // for [0, mx2) so the next call needs to XOR z2 only.  But we
        // also need to fold zMid into the [mx2, n1x2) tail.  Two helpers:
        xorTo(n1x2, z2, z2Off, zz, zzOff);
        if (n1x2 > mx2)
        {
            xorTo(n1x2 - mx2, zMid, zMidOff + mx2, zz, zzOff + mx2);
        }
    }

    /** {@code z[i] = 0} for {@code i in [0, len)}. */
    static void clear(int len, long[] z)
    {
        int i = 0;
        int bound = SPECIES.loopBound(len);
        LongVector zero = LongVector.zero(SPECIES);
        for (; i < bound; i += LANES)
        {
            zero.intoArray(z, i);
        }
        for (; i < len; ++i)
        {
            z[i] = 0L;
        }
    }
}
