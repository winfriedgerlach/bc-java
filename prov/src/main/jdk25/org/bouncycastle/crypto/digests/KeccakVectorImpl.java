package org.bouncycastle.crypto.digests;

import jdk.incubator.vector.LongVector;
import jdk.incubator.vector.VectorOperators;
import jdk.incubator.vector.VectorShuffle;
import jdk.incubator.vector.VectorSpecies;

/**
 * Lane-parallel Keccak-f[1600] permutation built on the JDK incubator
 * Vector API.  The 5x5 long-word state is held as five row-vectors
 * P[0..4] in {@link LongVector#SPECIES_512} (eight physical lanes;
 * lanes 0..4 carry the five row words, lanes 5..7 stay zero throughout
 * via the rotation table and shuffle layouts).  This layout makes
 * &theta; and &chi; trivially lane-parallel:
 * <ul>
 *   <li>&theta;: one five-way XOR-reduction across rows yields C, then
 *       a lane-rotate-left-by-1 plus a lane-rotate-left-by-4 (i.e. -1)
 *       and a per-lane long ROL by 1 give D, which is XORed back into
 *       all five rows.</li>
 *   <li>&rho;: per-row per-lane variable rotate via
 *       {@code lanewise(ROL, ROT_VEC[r])}.</li>
 *   <li>&pi;: cross-row position permutation, implemented as five
 *       small {@code lane}/{@code fromArray} gather rebuilds (the
 *       Vector API has no direct cross-vector gather; lane reads on
 *       AVX-512 collapse to single {@code vextract} instructions).</li>
 *   <li>&chi;: per-row {@code old ^ (~rotL1 & rotL2)} where rotL1/rotL2
 *       are five-cycle lane shuffles within each row vector.</li>
 *   <li>&iota;: scalar XOR of the round constant into lane 0 of P[0].</li>
 * </ul>
 * <p>
 * Loaded lazily by the JDK 25+ overlay of {@link KeccakDigest}; if
 * {@code jdk.incubator.vector} is absent the overlay catches the
 * linkage error and runs the scalar permutation.
 */
final class KeccakVectorImpl
{
    private static final VectorSpecies<Long> SPECIES = LongVector.SPECIES_512;

    static final int LANES = SPECIES.length(); // always 8 for SPECIES_512

    // Per-row per-lane rotate amounts for &rho;.  ROT_AMOUNTS[y][x] holds
    // the rotation applied to state position (x, y) (= state[5*y + x]).
    // FIPS-202 §3.2.2 r[x][y] table.  Lanes 5..7 are 0 (no-op rotate).
    private static final long[][] ROT_AMOUNTS = {
        { 0,  1, 62, 28, 27, 0, 0, 0},
        {36, 44,  6, 55, 20, 0, 0, 0},
        { 3, 10, 43, 25, 39, 0, 0, 0},
        {41, 45, 15, 21,  8, 0, 0, 0},
        {18,  2, 61, 56, 14, 0, 0, 0},
    };

    private static final LongVector ROT_VEC_0 = LongVector.fromArray(SPECIES, ROT_AMOUNTS[0], 0);
    private static final LongVector ROT_VEC_1 = LongVector.fromArray(SPECIES, ROT_AMOUNTS[1], 0);
    private static final LongVector ROT_VEC_2 = LongVector.fromArray(SPECIES, ROT_AMOUNTS[2], 0);
    private static final LongVector ROT_VEC_3 = LongVector.fromArray(SPECIES, ROT_AMOUNTS[3], 0);
    private static final LongVector ROT_VEC_4 = LongVector.fromArray(SPECIES, ROT_AMOUNTS[4], 0);

    // Lane-rotate-left-by-1 across the 5-wide row (lanes 0..4 cycle;
    // lanes 5..7 are pinned to themselves so they keep their stored zeros).
    // Result lane k holds source lane (k+1) mod 5 for k=0..4.
    private static final VectorShuffle<Long> ROT_LANES_LEFT_1 =
        VectorShuffle.fromValues(SPECIES, 1, 2, 3, 4, 0, 5, 6, 7);

    // Lane-rotate-left-by-4 (= -1 mod 5).  Lane k holds source lane (k+4) mod 5.
    private static final VectorShuffle<Long> ROT_LANES_LEFT_4 =
        VectorShuffle.fromValues(SPECIES, 4, 0, 1, 2, 3, 5, 6, 7);

    // &chi; lane shuffles within a 5-wide row: rotate left by 1 and 2.
    // CHI_R1 = ROT_LANES_LEFT_1; aliased for readability at the use site.
    private static final VectorShuffle<Long> CHI_R1 =
        VectorShuffle.fromValues(SPECIES, 1, 2, 3, 4, 0, 5, 6, 7);
    private static final VectorShuffle<Long> CHI_R2 =
        VectorShuffle.fromValues(SPECIES, 2, 3, 4, 0, 1, 5, 6, 7);

    // FIPS-202 round constants (24 rounds).
    private static final long[] RC = {
        0x0000000000000001L, 0x0000000000008082L, 0x800000000000808aL,
        0x8000000080008000L, 0x000000000000808bL, 0x0000000080000001L,
        0x8000000080008081L, 0x8000000000008009L, 0x000000000000008aL,
        0x0000000000000088L, 0x0000000080008009L, 0x000000008000000aL,
        0x000000008000808bL, 0x800000000000008bL, 0x8000000000008089L,
        0x8000000000008003L, 0x8000000000008002L, 0x8000000000000080L,
        0x000000000000800aL, 0x800000008000000aL, 0x8000000080008081L,
        0x8000000000008080L, 0x0000000080000001L, 0x8000000080008008L,
    };

    private KeccakVectorImpl()
    {
    }

    /**
     * Probes that the Vector API is usable on this runtime.  Returns the
     * width of {@link LongVector#SPECIES_PREFERRED} so the caller can
     * gate activation on hardware capability rather than the (fixed)
     * SPECIES_512 kernel width.
     */
    static int probe()
    {
        return LongVector.SPECIES_PREFERRED.length();
    }

    /**
     * Applies the 24-round Keccak-f[1600] permutation to {@code state}
     * (a {@code long[25]} holding the 5x5 lane-major state, with lane
     * (x, y) at index 5*y + x).
     */
    static void permutation(long[] state)
    {
        long[] padded = new long[8];

        System.arraycopy(state,  0, padded, 0, 5);
        LongVector p0 = LongVector.fromArray(SPECIES, padded, 0);
        System.arraycopy(state,  5, padded, 0, 5);
        LongVector p1 = LongVector.fromArray(SPECIES, padded, 0);
        System.arraycopy(state, 10, padded, 0, 5);
        LongVector p2 = LongVector.fromArray(SPECIES, padded, 0);
        System.arraycopy(state, 15, padded, 0, 5);
        LongVector p3 = LongVector.fromArray(SPECIES, padded, 0);
        System.arraycopy(state, 20, padded, 0, 5);
        LongVector p4 = LongVector.fromArray(SPECIES, padded, 0);

        long[] gather = new long[8]; // lanes 5..7 stay zero throughout

        for (int i = 0; i < 24; i++)
        {
            // ─────────── &theta; ───────────
            // C[x] = XOR of column x (lane x of all five row-vectors).
            LongVector c = p0
                .lanewise(VectorOperators.XOR, p1)
                .lanewise(VectorOperators.XOR, p2)
                .lanewise(VectorOperators.XOR, p3)
                .lanewise(VectorOperators.XOR, p4);

            // D[x] = C[(x-1) mod 5] XOR ROL(C[(x+1) mod 5], 1).
            // ROT_LANES_LEFT_1 puts C[(k+1) mod 5] in lane k.
            // ROT_LANES_LEFT_4 puts C[(k-1) mod 5] in lane k (since (k+4) mod 5 == (k-1) mod 5).
            LongVector cPlus1 = c.rearrange(ROT_LANES_LEFT_1);
            LongVector cMinus1 = c.rearrange(ROT_LANES_LEFT_4);
            LongVector d = cMinus1.lanewise(VectorOperators.XOR,
                cPlus1.lanewise(VectorOperators.ROL, 1));

            p0 = p0.lanewise(VectorOperators.XOR, d);
            p1 = p1.lanewise(VectorOperators.XOR, d);
            p2 = p2.lanewise(VectorOperators.XOR, d);
            p3 = p3.lanewise(VectorOperators.XOR, d);
            p4 = p4.lanewise(VectorOperators.XOR, d);

            // ─────────── &rho; ───────────
            // Per-lane variable rotate; ROT_VEC_r holds r[x][r] in lane x.
            p0 = p0.lanewise(VectorOperators.ROL, ROT_VEC_0);
            p1 = p1.lanewise(VectorOperators.ROL, ROT_VEC_1);
            p2 = p2.lanewise(VectorOperators.ROL, ROT_VEC_2);
            p3 = p3.lanewise(VectorOperators.ROL, ROT_VEC_3);
            p4 = p4.lanewise(VectorOperators.ROL, ROT_VEC_4);

            // ─────────── &pi; ───────────
            // P_new[y_d].lane(x_d) = P_old[x_d].lane((x_d + 3*y_d) mod 5).
            // Expressed as: source row = dest lane index; source lane =
            // (dest_lane + 3*dest_row) mod 5.  Five lane gathers per round.
            //
            // y_d = 0: src lane = (b + 0) mod 5 = (0,1,2,3,4)
            gather[0] = p0.lane(0);
            gather[1] = p1.lane(1);
            gather[2] = p2.lane(2);
            gather[3] = p3.lane(3);
            gather[4] = p4.lane(4);
            LongVector q0 = LongVector.fromArray(SPECIES, gather, 0);

            // y_d = 1: src lane = (b + 3) mod 5 = (3,4,0,1,2)
            gather[0] = p0.lane(3);
            gather[1] = p1.lane(4);
            gather[2] = p2.lane(0);
            gather[3] = p3.lane(1);
            gather[4] = p4.lane(2);
            LongVector q1 = LongVector.fromArray(SPECIES, gather, 0);

            // y_d = 2: src lane = (b + 1) mod 5 = (1,2,3,4,0)
            gather[0] = p0.lane(1);
            gather[1] = p1.lane(2);
            gather[2] = p2.lane(3);
            gather[3] = p3.lane(4);
            gather[4] = p4.lane(0);
            LongVector q2 = LongVector.fromArray(SPECIES, gather, 0);

            // y_d = 3: src lane = (b + 4) mod 5 = (4,0,1,2,3)
            gather[0] = p0.lane(4);
            gather[1] = p1.lane(0);
            gather[2] = p2.lane(1);
            gather[3] = p3.lane(2);
            gather[4] = p4.lane(3);
            LongVector q3 = LongVector.fromArray(SPECIES, gather, 0);

            // y_d = 4: src lane = (b + 2) mod 5 = (2,3,4,0,1)
            gather[0] = p0.lane(2);
            gather[1] = p1.lane(3);
            gather[2] = p2.lane(4);
            gather[3] = p3.lane(0);
            gather[4] = p4.lane(1);
            LongVector q4 = LongVector.fromArray(SPECIES, gather, 0);

            p0 = q0; p1 = q1; p2 = q2; p3 = q3; p4 = q4;

            // ─────────── &chi; ───────────
            // P[r] = P[r] XOR ((NOT lane-rotated-left-1(P[r])) AND lane-rotated-left-2(P[r]))
            LongVector r0a = p0.rearrange(CHI_R1);
            LongVector r0b = p0.rearrange(CHI_R2);
            p0 = p0.lanewise(VectorOperators.XOR,
                r0a.not().lanewise(VectorOperators.AND, r0b));

            LongVector r1a = p1.rearrange(CHI_R1);
            LongVector r1b = p1.rearrange(CHI_R2);
            p1 = p1.lanewise(VectorOperators.XOR,
                r1a.not().lanewise(VectorOperators.AND, r1b));

            LongVector r2a = p2.rearrange(CHI_R1);
            LongVector r2b = p2.rearrange(CHI_R2);
            p2 = p2.lanewise(VectorOperators.XOR,
                r2a.not().lanewise(VectorOperators.AND, r2b));

            LongVector r3a = p3.rearrange(CHI_R1);
            LongVector r3b = p3.rearrange(CHI_R2);
            p3 = p3.lanewise(VectorOperators.XOR,
                r3a.not().lanewise(VectorOperators.AND, r3b));

            LongVector r4a = p4.rearrange(CHI_R1);
            LongVector r4b = p4.rearrange(CHI_R2);
            p4 = p4.lanewise(VectorOperators.XOR,
                r4a.not().lanewise(VectorOperators.AND, r4b));

            // ─────────── &iota; ───────────
            // Scalar lane-0 modify; the rest of P[0] and all of P[1..4]
            // stay in their vector registers across the round boundary.
            p0 = p0.withLane(0, p0.lane(0) ^ RC[i]);
        }

        p0.intoArray(padded, 0); System.arraycopy(padded, 0, state,  0, 5);
        p1.intoArray(padded, 0); System.arraycopy(padded, 0, state,  5, 5);
        p2.intoArray(padded, 0); System.arraycopy(padded, 0, state, 10, 5);
        p3.intoArray(padded, 0); System.arraycopy(padded, 0, state, 15, 5);
        p4.intoArray(padded, 0); System.arraycopy(padded, 0, state, 20, 5);
    }
}
