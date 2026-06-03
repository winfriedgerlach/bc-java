package org.bouncycastle.math.ec.rfc7748;

import jdk.incubator.vector.IntVector;
import jdk.incubator.vector.VectorOperators;
import jdk.incubator.vector.VectorSpecies;

/**
 * Lane-parallel kernels for the 10-limb radix-2^25.5 X25519 field.  Each
 * field element is held as {@code int[10]}; this class vectorises the
 * carry-free element-wise operations called from the Montgomery ladder
 * (add / sub / apm / negate / conditional move / conditional negate /
 * conditional swap / copy).  The carry-bearing scalar paths
 * (mul / sqr / carry / reduce) remain in the overlay's scalar
 * implementations — those have intra-step long-multiply dependencies
 * the doc explicitly excludes.
 * <p>
 * Layout: lanes 0..7 of an {@link IntVector#SPECIES_256} carry the
 * first eight limbs; the trailing two limbs (indices 8 and 9) are
 * handled scalar-tail.  This keeps the kernel native-width on AVX2
 * (256-bit IntVector hardware ops) without paying for masked loads
 * past the {@code int[10]} array bounds, and stays a single 256-bit
 * AVX-512 op (lower half) on AVX-512 hosts where {@code minLanes=8}
 * makes the gate engage.
 * <p>
 * Loaded lazily by the JDK 25+ overlay of {@link X25519Field}; if
 * {@code jdk.incubator.vector} is absent the overlay catches the
 * linkage error and runs the scalar reference.
 */
final class X25519FieldVectorImpl
{
    private static final VectorSpecies<Integer> SPECIES = IntVector.SPECIES_256;

    static final int LANES = SPECIES.length(); // always 8 for SPECIES_256

    private X25519FieldVectorImpl()
    {
    }

    /**
     * Probes that the Vector API is usable on this runtime.  Returns the
     * width of {@link IntVector#SPECIES_PREFERRED} so the caller can gate
     * activation on hardware capability rather than the (algorithmically
     * fixed) eight-lane kernel width.
     */
    static int probe()
    {
        return IntVector.SPECIES_PREFERRED.length();
    }

    static void add(int[] x, int[] y, int[] z)
    {
        IntVector vx = IntVector.fromArray(SPECIES, x, 0);
        IntVector vy = IntVector.fromArray(SPECIES, y, 0);
        vx.add(vy).intoArray(z, 0);
        z[8] = x[8] + y[8];
        z[9] = x[9] + y[9];
    }

    static void sub(int[] x, int[] y, int[] z)
    {
        IntVector vx = IntVector.fromArray(SPECIES, x, 0);
        IntVector vy = IntVector.fromArray(SPECIES, y, 0);
        vx.sub(vy).intoArray(z, 0);
        z[8] = x[8] - y[8];
        z[9] = x[9] - y[9];
    }

    static void apm(int[] x, int[] y, int[] zp, int[] zm)
    {
        IntVector vx = IntVector.fromArray(SPECIES, x, 0);
        IntVector vy = IntVector.fromArray(SPECIES, y, 0);
        vx.add(vy).intoArray(zp, 0);
        vx.sub(vy).intoArray(zm, 0);
        int x8 = x[8], y8 = y[8];
        zp[8] = x8 + y8;
        zm[8] = x8 - y8;
        int x9 = x[9], y9 = y[9];
        zp[9] = x9 + y9;
        zm[9] = x9 - y9;
    }

    static void negate(int[] x, int[] z)
    {
        IntVector vx = IntVector.fromArray(SPECIES, x, 0);
        vx.neg().intoArray(z, 0);
        z[8] = -x[8];
        z[9] = -x[9];
    }

    static void copy(int[] x, int xOff, int[] z, int zOff)
    {
        IntVector.fromArray(SPECIES, x, xOff).intoArray(z, zOff);
        z[zOff + 8] = x[xOff + 8];
        z[zOff + 9] = x[xOff + 9];
    }

    static void cmov(int cond, int[] x, int xOff, int[] z, int zOff)
    {
        // assert 0 == cond || -1 == cond
        IntVector vx = IntVector.fromArray(SPECIES, x, xOff);
        IntVector vz = IntVector.fromArray(SPECIES, z, zOff);
        IntVector diff = vx.lanewise(VectorOperators.XOR, vz);
        IntVector mask = IntVector.broadcast(SPECIES, cond);
        vz.lanewise(VectorOperators.XOR,
            diff.lanewise(VectorOperators.AND, mask)).intoArray(z, zOff);

        int z8 = z[zOff + 8];
        z[zOff + 8] = z8 ^ ((z8 ^ x[xOff + 8]) & cond);
        int z9 = z[zOff + 9];
        z[zOff + 9] = z9 ^ ((z9 ^ x[xOff + 9]) & cond);
    }

    static void cnegate(int negate, int[] z)
    {
        // assert (negate >>> 1) == 0
        int mask = 0 - negate;
        IntVector vmask = IntVector.broadcast(SPECIES, mask);
        IntVector vz = IntVector.fromArray(SPECIES, z, 0);
        vz.lanewise(VectorOperators.XOR, vmask).sub(vmask).intoArray(z, 0);
        z[8] = (z[8] ^ mask) - mask;
        z[9] = (z[9] ^ mask) - mask;
    }

    static void cswap(int swap, int[] a, int[] b)
    {
        // assert (swap >>> 1) == 0; assert a != b
        int mask = 0 - swap;
        IntVector vmask = IntVector.broadcast(SPECIES, mask);
        IntVector va = IntVector.fromArray(SPECIES, a, 0);
        IntVector vb = IntVector.fromArray(SPECIES, b, 0);
        IntVector dummy = vmask.lanewise(VectorOperators.AND,
            va.lanewise(VectorOperators.XOR, vb));
        va.lanewise(VectorOperators.XOR, dummy).intoArray(a, 0);
        vb.lanewise(VectorOperators.XOR, dummy).intoArray(b, 0);

        int a8 = a[8], b8 = b[8];
        int d8 = mask & (a8 ^ b8);
        a[8] = a8 ^ d8;
        b[8] = b8 ^ d8;

        int a9 = a[9], b9 = b[9];
        int d9 = mask & (a9 ^ b9);
        a[9] = a9 ^ d9;
        b[9] = b9 ^ d9;
    }

    static void zero(int[] z)
    {
        IntVector.zero(SPECIES).intoArray(z, 0);
        z[8] = 0;
        z[9] = 0;
    }
}
