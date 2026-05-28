package org.bouncycastle.crypto.digests;

import jdk.incubator.vector.LongVector;
import jdk.incubator.vector.VectorOperators;
import jdk.incubator.vector.VectorShuffle;
import jdk.incubator.vector.VectorSpecies;

/**
 * 4-lane SIMD BLAKE2b compression — the canonical SSE2/AVX2 layout, ported
 * to {@code LongVector.SPECIES_256}.  The 16-word state is held in four
 * row-major {@link LongVector}s (each lane a column), so the round's four
 * column-G calls collapse into one vector G, the four diagonal-G calls
 * into a second vector G, separated by a "diagonalize" lane shuffle.
 * <p>
 * Loaded lazily by the JDK 25+ overlay of {@link Blake2bDigest}; if
 * {@code jdk.incubator.vector} is absent the overlay catches the linkage
 * error and runs the scalar compression.
 */
final class Blake2bVectorImpl
{
    private static final VectorSpecies<Long> SPECIES = LongVector.SPECIES_256;

    static final int LANES = SPECIES.length(); // always 4 for SPECIES_256

    // After the column-G the state's diagonals must be brought into
    // column position before the second G.  Row 0 stays put; row 1 rotates
    // one lane left, row 2 two, row 3 three.  The reverse ("undiagonalize")
    // shuffles after the second G are the same pattern with rotation
    // direction flipped — so undiag_v3 == diag_v1 etc.
    private static final VectorShuffle<Long> DIAG_V1 =
        VectorShuffle.fromValues(SPECIES, 1, 2, 3, 0);
    private static final VectorShuffle<Long> DIAG_V2 =
        VectorShuffle.fromValues(SPECIES, 2, 3, 0, 1);
    private static final VectorShuffle<Long> DIAG_V3 =
        VectorShuffle.fromValues(SPECIES, 3, 0, 1, 2);

    // BLAKE2b initialisation vector — same constants as the scalar engine.
    private static final long[] IV =
    {
        0x6a09e667f3bcc908L, 0xbb67ae8584caa73bL, 0x3c6ef372fe94f82bL, 0xa54ff53a5f1d36f1L,
        0x510e527fade682d1L, 0x9b05688c2b3e6c1fL, 0x1f83d9abfb41bd6bL, 0x5be0cd19137e2179L
    };

    // Same sigma table as the scalar engine, but kept here so the vector
    // path is self-contained.  Indexed as SIGMA[round][sigma-step].
    private static final byte[][] SIGMA =
    {
        {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
        {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
        {11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
        {7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
        {9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
        {2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
        {12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
        {13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
        {6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
        {10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0},
        {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
        {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3}
    };

    private Blake2bVectorImpl()
    {
    }

    static int probe()
    {
        // SPECIES_256 is fixed, but report the host's preferred LongVector
        // width so the caller can gate on hardware capability rather than
        // the (algorithmically fixed) 4-lane kernel width.
        return LongVector.SPECIES_PREFERRED.length();
    }

    /**
     * Compresses one 128-byte BLAKE2b block.  {@code chainValue} is the 8-word
     * state vector (BLAKE2's "h"); on entry it holds the pre-block chaining
     * value, on exit the post-block chaining value.  {@code m} is the 16-word
     * little-endian-decoded message block.  {@code t0}/{@code t1} are the
     * counter words and {@code f0}/{@code f1} the finalisation flags.
     */
    static void compress(long[] chainValue, long[] m, long t0, long t1, long f0, long f1)
    {
        // Reusable 4-long scratch the JIT stack-allocates and reuses for
        // each LongVector.fromArray below — there's no fromValues(long...)
        // overload, and broadcast+withLane chains are slower than this.
        long[] mScratch = new long[4];

        // Initial state v: chain || IV[0..3] || (t0^IV[4], t1^IV[5], f0^IV[6], f1^IV[7])
        LongVector v0 = LongVector.fromArray(SPECIES, chainValue, 0);
        LongVector v1 = LongVector.fromArray(SPECIES, chainValue, 4);
        LongVector v2 = LongVector.fromArray(SPECIES, IV, 0);
        mScratch[0] = t0 ^ IV[4];
        mScratch[1] = t1 ^ IV[5];
        mScratch[2] = f0 ^ IV[6];
        mScratch[3] = f1 ^ IV[7];
        LongVector v3 = LongVector.fromArray(SPECIES, mScratch, 0);

        for (int r = 0; r < 12; r++)
        {
            byte[] s = SIGMA[r];

            // ---- Column-G applied to all four columns in parallel ----
            mScratch[0] = m[s[ 0]];
            mScratch[1] = m[s[ 2]];
            mScratch[2] = m[s[ 4]];
            mScratch[3] = m[s[ 6]];
            LongVector m1 = LongVector.fromArray(SPECIES, mScratch, 0);

            v0 = v0.add(v1).add(m1);
            v3 = v3.lanewise(VectorOperators.XOR, v0).lanewise(VectorOperators.ROR, 32);
            v2 = v2.add(v3);
            v1 = v1.lanewise(VectorOperators.XOR, v2).lanewise(VectorOperators.ROR, 24);

            mScratch[0] = m[s[ 1]];
            mScratch[1] = m[s[ 3]];
            mScratch[2] = m[s[ 5]];
            mScratch[3] = m[s[ 7]];
            LongVector m2 = LongVector.fromArray(SPECIES, mScratch, 0);

            v0 = v0.add(v1).add(m2);
            v3 = v3.lanewise(VectorOperators.XOR, v0).lanewise(VectorOperators.ROR, 16);
            v2 = v2.add(v3);
            v1 = v1.lanewise(VectorOperators.XOR, v2).lanewise(VectorOperators.ROR, 63);

            // ---- Diagonalize: rotate v1, v2, v3 lanes so columns become diagonals ----
            v1 = v1.rearrange(DIAG_V1);
            v2 = v2.rearrange(DIAG_V2);
            v3 = v3.rearrange(DIAG_V3);

            // ---- Diagonal-G (now structured as columns after the shuffle) ----
            mScratch[0] = m[s[ 8]];
            mScratch[1] = m[s[10]];
            mScratch[2] = m[s[12]];
            mScratch[3] = m[s[14]];
            LongVector m3 = LongVector.fromArray(SPECIES, mScratch, 0);

            v0 = v0.add(v1).add(m3);
            v3 = v3.lanewise(VectorOperators.XOR, v0).lanewise(VectorOperators.ROR, 32);
            v2 = v2.add(v3);
            v1 = v1.lanewise(VectorOperators.XOR, v2).lanewise(VectorOperators.ROR, 24);

            mScratch[0] = m[s[ 9]];
            mScratch[1] = m[s[11]];
            mScratch[2] = m[s[13]];
            mScratch[3] = m[s[15]];
            LongVector m4 = LongVector.fromArray(SPECIES, mScratch, 0);

            v0 = v0.add(v1).add(m4);
            v3 = v3.lanewise(VectorOperators.XOR, v0).lanewise(VectorOperators.ROR, 16);
            v2 = v2.add(v3);
            v1 = v1.lanewise(VectorOperators.XOR, v2).lanewise(VectorOperators.ROR, 63);

            // ---- Undiagonalize: reverse shuffles ----
            // undiag rotation of v1 by -1 == rotation of v3 by +3 == DIAG_V3.
            // undiag rotation of v2 by -2 == DIAG_V2 (self-inverse).
            // undiag rotation of v3 by -3 == DIAG_V1.
            v1 = v1.rearrange(DIAG_V3);
            v2 = v2.rearrange(DIAG_V2);
            v3 = v3.rearrange(DIAG_V1);
        }

        // Mix the post-round v back into the chain value.
        LongVector hLo = LongVector.fromArray(SPECIES, chainValue, 0)
            .lanewise(VectorOperators.XOR, v0)
            .lanewise(VectorOperators.XOR, v2);
        LongVector hHi = LongVector.fromArray(SPECIES, chainValue, 4)
            .lanewise(VectorOperators.XOR, v1)
            .lanewise(VectorOperators.XOR, v3);
        hLo.intoArray(chainValue, 0);
        hHi.intoArray(chainValue, 4);
    }
}