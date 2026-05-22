package org.bouncycastle.crypto.engines;

import java.lang.invoke.MethodHandles;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;

import jdk.incubator.vector.IntVector;
import jdk.incubator.vector.VectorOperators;
import jdk.incubator.vector.VectorSpecies;

/**
 * Lane-parallel ChaCha core built on the JDK incubator Vector API.  Each
 * IntVector lane corresponds to an independent ChaCha block, so a single
 * pass through the round loop produces {@link #LANES} blocks of key-stream
 * which are XORed against {@code LANES * 64} bytes of input.
 * <p>
 * This class is loaded lazily by the JDK 25+ overlays of
 * {@link ChaChaEngine} / {@link ChaCha7539Engine}; if {@code
 * jdk.incubator.vector} is not on the runtime module path the overlay
 * catches the resulting linkage error and falls back to the scalar path.
 */
final class ChaChaVectorImpl
{
    private static final VectorSpecies<Integer> SPECIES = pickSpecies();

    static final int LANES = SPECIES.length();

    static final int SCRATCH_LEN = 16 * LANES;

    private static final VarHandle INT_LE =
        MethodHandles.byteArrayViewVarHandle(int[].class, ByteOrder.LITTLE_ENDIAN);

    private static VectorSpecies<Integer> pickSpecies()
    {
        // SPECIES_PREFERRED on x86 typically reports SPECIES_256 (AVX2,
        // 8 lanes) or SPECIES_512 (AVX-512, 16 lanes).  Cap at SPECIES_512
        // because going wider adds bookkeeping without helping ChaCha
        // (each lane is an independent block).
        VectorSpecies<Integer> preferred = IntVector.SPECIES_PREFERRED;
        if (preferred.length() >= 16)
        {
            return IntVector.SPECIES_512;
        }
        if (preferred.length() >= 8)
        {
            return IntVector.SPECIES_256;
        }
        if (preferred.length() >= 4)
        {
            return IntVector.SPECIES_128;
        }
        return preferred;
    }

    private ChaChaVectorImpl()
    {
    }

    /**
     * Probes that the Vector API is usable on this runtime.  The very act
     * of calling this method forces class initialisation, which resolves
     * the {@code jdk.incubator.vector} references; if the module is not
     * present that resolution throws and the caller treats vectorisation
     * as unavailable.
     *
     * @return the lane count chosen by {@link #pickSpecies()}.
     */
    static int probe()
    {
        return LANES;
    }

    /**
     * Process {@link #LANES} ChaCha blocks in parallel, XORing the
     * resulting key-stream against {@code LANES * 64} bytes of input.
     * <p>
     * The {@code state[0..15]} array is the standard ChaCha 16-word state
     * with {@code state[12]} / {@code state[13]} holding the counter for
     * <em>lane&nbsp;0</em>.  The caller supplies pre-computed per-lane
     * values for the two counter words via {@code counters}: lane
     * <em>i</em>'s {@code state[12]} sits at {@code counters[i]} and its
     * {@code state[13]} at {@code counters[LANES + i]}.  This lets the
     * same kernel serve both the 64-bit counter form (DJB ChaCha,
     * {@link ChaChaEngine}) and the 32-bit counter / 96-bit nonce form
     * (RFC 7539, {@link ChaCha7539Engine}).
     * <p>
     * The kernel does <em>not</em> mutate {@code state[]}.  Advancing the
     * cipher state across the {@code LANES} blocks just consumed is the
     * caller's responsibility.
     */
    static void processBlocks(int rounds, int[] state, int[] counters,
                              byte[] in, int inOff,
                              byte[] out, int outOff)
    {
        // The transposition scratch is small, short-lived and never escapes
        // this method, so HotSpot's escape analysis stack-allocates it in
        // steady state — keeping it as a local also lets the kernel stay
        // within Sonar's 7-parameter limit.
        int[] scratch = new int[SCRATCH_LEN];
        IntVector v00 = IntVector.broadcast(SPECIES, state[ 0]);
        IntVector v01 = IntVector.broadcast(SPECIES, state[ 1]);
        IntVector v02 = IntVector.broadcast(SPECIES, state[ 2]);
        IntVector v03 = IntVector.broadcast(SPECIES, state[ 3]);
        IntVector v04 = IntVector.broadcast(SPECIES, state[ 4]);
        IntVector v05 = IntVector.broadcast(SPECIES, state[ 5]);
        IntVector v06 = IntVector.broadcast(SPECIES, state[ 6]);
        IntVector v07 = IntVector.broadcast(SPECIES, state[ 7]);
        IntVector v08 = IntVector.broadcast(SPECIES, state[ 8]);
        IntVector v09 = IntVector.broadcast(SPECIES, state[ 9]);
        IntVector v10 = IntVector.broadcast(SPECIES, state[10]);
        IntVector v11 = IntVector.broadcast(SPECIES, state[11]);
        IntVector v12 = IntVector.fromArray(SPECIES, counters, 0);
        IntVector v13 = IntVector.fromArray(SPECIES, counters, LANES);
        IntVector v14 = IntVector.broadcast(SPECIES, state[14]);
        IntVector v15 = IntVector.broadcast(SPECIES, state[15]);

        IntVector i00 = v00;
        IntVector i01 = v01;
        IntVector i02 = v02;
        IntVector i03 = v03;
        IntVector i04 = v04;
        IntVector i05 = v05;
        IntVector i06 = v06;
        IntVector i07 = v07;
        IntVector i08 = v08;
        IntVector i09 = v09;
        IntVector i10 = v10;
        IntVector i11 = v11;
        IntVector i12 = v12;
        IntVector i13 = v13;
        IntVector i14 = v14;
        IntVector i15 = v15;

        for (int r = rounds; r > 0; r -= 2)
        {
            // Column round
            v00 = v00.add(v04); v12 = rotl(v12.lanewise(VectorOperators.XOR, v00), 16);
            v08 = v08.add(v12); v04 = rotl(v04.lanewise(VectorOperators.XOR, v08), 12);
            v00 = v00.add(v04); v12 = rotl(v12.lanewise(VectorOperators.XOR, v00),  8);
            v08 = v08.add(v12); v04 = rotl(v04.lanewise(VectorOperators.XOR, v08),  7);

            v01 = v01.add(v05); v13 = rotl(v13.lanewise(VectorOperators.XOR, v01), 16);
            v09 = v09.add(v13); v05 = rotl(v05.lanewise(VectorOperators.XOR, v09), 12);
            v01 = v01.add(v05); v13 = rotl(v13.lanewise(VectorOperators.XOR, v01),  8);
            v09 = v09.add(v13); v05 = rotl(v05.lanewise(VectorOperators.XOR, v09),  7);

            v02 = v02.add(v06); v14 = rotl(v14.lanewise(VectorOperators.XOR, v02), 16);
            v10 = v10.add(v14); v06 = rotl(v06.lanewise(VectorOperators.XOR, v10), 12);
            v02 = v02.add(v06); v14 = rotl(v14.lanewise(VectorOperators.XOR, v02),  8);
            v10 = v10.add(v14); v06 = rotl(v06.lanewise(VectorOperators.XOR, v10),  7);

            v03 = v03.add(v07); v15 = rotl(v15.lanewise(VectorOperators.XOR, v03), 16);
            v11 = v11.add(v15); v07 = rotl(v07.lanewise(VectorOperators.XOR, v11), 12);
            v03 = v03.add(v07); v15 = rotl(v15.lanewise(VectorOperators.XOR, v03),  8);
            v11 = v11.add(v15); v07 = rotl(v07.lanewise(VectorOperators.XOR, v11),  7);

            // Diagonal round
            v00 = v00.add(v05); v15 = rotl(v15.lanewise(VectorOperators.XOR, v00), 16);
            v10 = v10.add(v15); v05 = rotl(v05.lanewise(VectorOperators.XOR, v10), 12);
            v00 = v00.add(v05); v15 = rotl(v15.lanewise(VectorOperators.XOR, v00),  8);
            v10 = v10.add(v15); v05 = rotl(v05.lanewise(VectorOperators.XOR, v10),  7);

            v01 = v01.add(v06); v12 = rotl(v12.lanewise(VectorOperators.XOR, v01), 16);
            v11 = v11.add(v12); v06 = rotl(v06.lanewise(VectorOperators.XOR, v11), 12);
            v01 = v01.add(v06); v12 = rotl(v12.lanewise(VectorOperators.XOR, v01),  8);
            v11 = v11.add(v12); v06 = rotl(v06.lanewise(VectorOperators.XOR, v11),  7);

            v02 = v02.add(v07); v13 = rotl(v13.lanewise(VectorOperators.XOR, v02), 16);
            v08 = v08.add(v13); v07 = rotl(v07.lanewise(VectorOperators.XOR, v08), 12);
            v02 = v02.add(v07); v13 = rotl(v13.lanewise(VectorOperators.XOR, v02),  8);
            v08 = v08.add(v13); v07 = rotl(v07.lanewise(VectorOperators.XOR, v08),  7);

            v03 = v03.add(v04); v14 = rotl(v14.lanewise(VectorOperators.XOR, v03), 16);
            v09 = v09.add(v14); v04 = rotl(v04.lanewise(VectorOperators.XOR, v09), 12);
            v03 = v03.add(v04); v14 = rotl(v14.lanewise(VectorOperators.XOR, v03),  8);
            v09 = v09.add(v14); v04 = rotl(v04.lanewise(VectorOperators.XOR, v09),  7);
        }

        v00 = v00.add(i00); v01 = v01.add(i01); v02 = v02.add(i02); v03 = v03.add(i03);
        v04 = v04.add(i04); v05 = v05.add(i05); v06 = v06.add(i06); v07 = v07.add(i07);
        v08 = v08.add(i08); v09 = v09.add(i09); v10 = v10.add(i10); v11 = v11.add(i11);
        v12 = v12.add(i12); v13 = v13.add(i13); v14 = v14.add(i14); v15 = v15.add(i15);

        // Spill the 16xLANES key-stream matrix and transpose-XOR with the
        // input.  Layout: scratch[s * LANES + b] holds block b's word s.
        v00.intoArray(scratch,           0);
        v01.intoArray(scratch,       LANES);
        v02.intoArray(scratch,   2 * LANES);
        v03.intoArray(scratch,   3 * LANES);
        v04.intoArray(scratch,   4 * LANES);
        v05.intoArray(scratch,   5 * LANES);
        v06.intoArray(scratch,   6 * LANES);
        v07.intoArray(scratch,   7 * LANES);
        v08.intoArray(scratch,   8 * LANES);
        v09.intoArray(scratch,   9 * LANES);
        v10.intoArray(scratch,  10 * LANES);
        v11.intoArray(scratch,  11 * LANES);
        v12.intoArray(scratch,  12 * LANES);
        v13.intoArray(scratch,  13 * LANES);
        v14.intoArray(scratch,  14 * LANES);
        v15.intoArray(scratch,  15 * LANES);

        for (int b = 0; b < LANES; ++b)
        {
            int blkIn  = inOff  + (b << 6);
            int blkOut = outOff + (b << 6);
            for (int s = 0; s < 16; ++s)
            {
                int ks = scratch[s * LANES + b];
                int pt = (int)INT_LE.get(in, blkIn);
                INT_LE.set(out, blkOut, pt ^ ks);
                blkIn  += 4;
                blkOut += 4;
            }
        }
    }

    private static IntVector rotl(IntVector v, int n)
    {
        return v.lanewise(VectorOperators.ROL, n);
    }
}