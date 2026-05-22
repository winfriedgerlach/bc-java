package org.bouncycastle.crypto.digests;

import jdk.incubator.vector.IntVector;
import jdk.incubator.vector.VectorOperators;
import jdk.incubator.vector.VectorSpecies;

/**
 * Lane-parallel SHA-256 message-schedule expansion built on the JDK
 * incubator Vector API.  The recurrence
 * {@code W[t] = σ1(W[t-2]) + W[t-7] + σ0(W[t-15]) + W[t-16]} carries an
 * intra-block dependency on {@code W[t-2]}, which limits parallelism to
 * two lanes: when we step {@code t} by two, the only σ1 inputs we read
 * are {@code W[t-2]} and {@code W[t-1]}, both of which are already in
 * place — either as part of the original 16-word load or as a result of
 * the previous pair iteration.  Three lanes or more would require also
 * reading {@code W[t]} (the value we're about to compute), so we cap at
 * two and accept the modest width.
 * <p>
 * The kernel only fills {@code X[16..63]}; the unrolled SHA-256
 * compression body stays in {@link SHA256Digest#processBlock()}, so the
 * resulting digest matches the scalar output bit for bit.
 * <p>
 * Loaded lazily by the JDK 25+ overlay of {@link SHA256Digest}; if
 * {@code jdk.incubator.vector} is absent the overlay catches the linkage
 * error and runs the scalar message schedule.
 */
final class SHA256VectorImpl
{
    // Two lanes is the algorithmic ceiling — see the class javadoc.  We
    // pin SPECIES_64 explicitly so we don't accidentally pay for masked
    // ops on a wider species, regardless of the host's preferred width.
    private static final VectorSpecies<Integer> SPECIES = IntVector.SPECIES_64;

    static final int LANES = SPECIES.length();

    private SHA256VectorImpl()
    {
    }

    /**
     * Probes that the Vector API is usable on this runtime.  Returns the
     * width of {@link IntVector#SPECIES_PREFERRED} so the caller can gate
     * activation on hardware capability rather than the (algorithmically
     * fixed) two-lane kernel width.
     */
    static int probe()
    {
        return IntVector.SPECIES_PREFERRED.length();
    }

    /**
     * Fills {@code X[16..63]} with the SHA-256 message schedule, processing
     * two words at a time in a 2-lane {@code IntVector}.  The caller has
     * already populated {@code X[0..15]} from the input block.
     */
    static void messageSchedule(int[] X)
    {
        for (int t = 16; t <= 62; t += 2)
        {
            IntVector w16 = IntVector.fromArray(SPECIES, X, t - 16);
            IntVector w15 = IntVector.fromArray(SPECIES, X, t - 15);
            IntVector w7  = IntVector.fromArray(SPECIES, X, t - 7);
            IntVector w2  = IntVector.fromArray(SPECIES, X, t - 2);

            IntVector s0 = sigma0(w15);
            IntVector s1 = sigma1(w2);

            w16.add(w7).add(s0).add(s1).intoArray(X, t);
        }
    }

    private static IntVector sigma0(IntVector x)
    {
        // σ0(x) = ROTR^7(x) ^ ROTR^18(x) ^ SHR^3(x)
        IntVector r7  = x.lanewise(VectorOperators.ROR, 7);
        IntVector r18 = x.lanewise(VectorOperators.ROR, 18);
        IntVector s3  = x.lanewise(VectorOperators.LSHR, 3);
        return r7.lanewise(VectorOperators.XOR, r18).lanewise(VectorOperators.XOR, s3);
    }

    private static IntVector sigma1(IntVector x)
    {
        // σ1(x) = ROTR^17(x) ^ ROTR^19(x) ^ SHR^10(x)
        IntVector r17 = x.lanewise(VectorOperators.ROR, 17);
        IntVector r19 = x.lanewise(VectorOperators.ROR, 19);
        IntVector s10 = x.lanewise(VectorOperators.LSHR, 10);
        return r17.lanewise(VectorOperators.XOR, r19).lanewise(VectorOperators.XOR, s10);
    }
}