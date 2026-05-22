package org.bouncycastle.crypto.digests;

import jdk.incubator.vector.LongVector;
import jdk.incubator.vector.VectorOperators;
import jdk.incubator.vector.VectorSpecies;

/**
 * Lane-parallel SHA-512 message-schedule expansion built on the JDK
 * incubator Vector API.  Same shape as {@link SHA256VectorImpl}: the
 * recurrence
 * {@code W[t] = σ1(W[t-2]) + W[t-7] + σ0(W[t-15]) + W[t-16]} carries an
 * intra-block {@code W[t-2]} dependency that caps useful parallelism at
 * two lanes; we step {@code t} by two so the only σ1 reads in the pair
 * are {@code W[t-2]} and {@code W[t-1]}, both of which are already in
 * place when the iteration starts.
 * <p>
 * The kernel only fills {@code W[16..79]}; the unrolled SHA-512
 * compression body in {@link LongDigest#processBlock()} runs scalar, and
 * the resulting digest matches the scalar output bit for bit.
 * <p>
 * Loaded lazily by the JDK 25+ overlay of {@link LongDigest}; if
 * {@code jdk.incubator.vector} is absent the overlay catches the linkage
 * error and runs the scalar message schedule.
 */
final class SHA512VectorImpl
{
    // Two lanes is the algorithmic ceiling — see the class javadoc.  We
    // pin SPECIES_128 explicitly (= 2 long lanes) so we don't pay for
    // masked ops on a wider species.
    private static final VectorSpecies<Long> SPECIES = LongVector.SPECIES_128;

    static final int LANES = SPECIES.length();

    private SHA512VectorImpl()
    {
    }

    /**
     * Probes that the Vector API is usable on this runtime.  Returns the
     * width of {@link LongVector#SPECIES_PREFERRED} so the caller can
     * gate activation on hardware capability rather than the
     * (algorithmically fixed) two-lane kernel width.
     */
    static int probe()
    {
        return LongVector.SPECIES_PREFERRED.length();
    }

    /**
     * Fills {@code W[16..79]} with the SHA-512 message schedule, processing
     * two words at a time in a 2-lane {@code LongVector}.  The caller has
     * already populated {@code W[0..15]} from the input block.
     */
    static void messageSchedule(long[] W)
    {
        for (int t = 16; t <= 78; t += 2)
        {
            LongVector w16 = LongVector.fromArray(SPECIES, W, t - 16);
            LongVector w15 = LongVector.fromArray(SPECIES, W, t - 15);
            LongVector w7  = LongVector.fromArray(SPECIES, W, t - 7);
            LongVector w2  = LongVector.fromArray(SPECIES, W, t - 2);

            LongVector s0 = sigma0(w15);
            LongVector s1 = sigma1(w2);

            w16.add(w7).add(s0).add(s1).intoArray(W, t);
        }
    }

    private static LongVector sigma0(LongVector x)
    {
        // σ0(x) = ROTR^1(x) ^ ROTR^8(x) ^ SHR^7(x)
        LongVector r1 = x.lanewise(VectorOperators.ROR, 1);
        LongVector r8 = x.lanewise(VectorOperators.ROR, 8);
        LongVector s7 = x.lanewise(VectorOperators.LSHR, 7);
        return r1.lanewise(VectorOperators.XOR, r8).lanewise(VectorOperators.XOR, s7);
    }

    private static LongVector sigma1(LongVector x)
    {
        // σ1(x) = ROTR^19(x) ^ ROTR^61(x) ^ SHR^6(x)
        LongVector r19 = x.lanewise(VectorOperators.ROR, 19);
        LongVector r61 = x.lanewise(VectorOperators.ROR, 61);
        LongVector s6  = x.lanewise(VectorOperators.LSHR, 6);
        return r19.lanewise(VectorOperators.XOR, r61).lanewise(VectorOperators.XOR, s6);
    }
}