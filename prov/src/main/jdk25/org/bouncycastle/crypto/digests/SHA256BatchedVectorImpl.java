package org.bouncycastle.crypto.digests;

import jdk.incubator.vector.IntVector;
import jdk.incubator.vector.VectorOperators;
import jdk.incubator.vector.VectorSpecies;

/**
 * Lane-parallel SHA-256 single-block compressor — same compression body
 * as the scalar engine, only the lanes carry independent inputs / states.
 * Built for the batched-hash pattern in suggestion #7 of
 * {@code VECTOR_API_OPPORTUNITIES.md}: SLH-DSA's WOTS chains, where many
 * one-block hashes are computed back-to-back from a shared pre-state but
 * with different ADRS / message bytes per chain.  Each lane runs the
 * full 64-round body in lockstep, so the speedup scales with lane count
 * (unlike the within-hash overlay in {@link SHA256VectorImpl} where the
 * {@code W[t-2]} dependency caps useful parallelism at two).
 * <p>
 * Layout of the in/out arrays is transposed lane-major:
 * <pre>
 *   blockData[s * LANES + b] = lane b's input word s   (W[s], big-endian)
 *   outState[s * LANES + b]  = lane b's output state word s
 * </pre>
 * The shared {@code preState} (8 ints) is broadcast across all lanes at
 * round 0; its value is whatever H1..H8 the caller has memoised
 * up-front (e.g. SHA-256 over {@code pkSeed || zero-pad to 64} for SLH-DSA).
 * <p>
 * The compression loop holds {@code W[0..15]} in a 16-element
 * {@code IntVector[]} circular buffer kept entirely inside the method.
 * HotSpot's escape analysis stack-allocates the array in steady state,
 * so the indices {@code (t+14)&15} / {@code (t+9)&15} / {@code (t+1)&15}
 * resolve to register-resident slots.  A fully-unrolled chunk-of-16
 * variant was attempted (the standard SIMD pattern with 16 named
 * {@code w0..w15} locals and the W rotation expressed via reassignment)
 * but failed to win:
 * <ul>
 *   <li>A single fully-unrolled method came in at ~8 KB of bytecode,
 *       above C2's {@code HugeMethodLimit=8000} threshold; HotSpot fell
 *       back to the interpreter and the kernel ran ~8x slower.</li>
 *   <li>Splitting into four chunks-of-16 static methods kept each under
 *       the size limit, but required passing state and W through
 *       {@code IntVector[]} arrays.  The arrays escape across the
 *       chunk-method call boundary, EA can't eliminate them, and every
 *       round body's {@code state[i]} / {@code w[i]} access becomes a
 *       real heap load — slower than the original loop.</li>
 * </ul>
 * The loop form is therefore the best HotSpot variant of this kernel; the
 * remaining gap relative to scalar is the per-IntVector-op overhead that
 * Vector API ops pay over native SHA-256 instructions.
 * <p>
 * Loaded lazily by the JDK 25+ overlay of
 * {@link org.bouncycastle.crypto.signers.slhdsa.WotsPlus}; if
 * {@code jdk.incubator.vector} is absent the overlay catches the linkage
 * error and runs the scalar chain.
 */
public final class SHA256BatchedVectorImpl
{
    private static final VectorSpecies<Integer> SPECIES = pickSpecies();

    public static final int LANES = SPECIES.length();

    private static final IntVector[] K_V;

    private static VectorSpecies<Integer> pickSpecies()
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

    private SHA256BatchedVectorImpl()
    {
    }

    public static int probe()
    {
        return LANES;
    }

    /**
     * Compresses one 64-byte block per lane against the shared
     * {@code preState}.  All arrays are transposed lane-major
     * (see class javadoc).
     */
    public static void compressBatch(int[] preState, int[] blockData, int[] outState)
    {
        final IntVector ia = IntVector.broadcast(SPECIES, preState[0]);
        final IntVector ib = IntVector.broadcast(SPECIES, preState[1]);
        final IntVector ic = IntVector.broadcast(SPECIES, preState[2]);
        final IntVector id = IntVector.broadcast(SPECIES, preState[3]);
        final IntVector ie = IntVector.broadcast(SPECIES, preState[4]);
        final IntVector iF = IntVector.broadcast(SPECIES, preState[5]);
        final IntVector ig = IntVector.broadcast(SPECIES, preState[6]);
        final IntVector ih = IntVector.broadcast(SPECIES, preState[7]);

        IntVector a = ia, b = ib, c = ic, d = id;
        IntVector e = ie, f = iF, g = ig, h = ih;

        IntVector[] W = new IntVector[16];
        W[0]  = IntVector.fromArray(SPECIES, blockData,  0 * LANES);
        W[1]  = IntVector.fromArray(SPECIES, blockData,  1 * LANES);
        W[2]  = IntVector.fromArray(SPECIES, blockData,  2 * LANES);
        W[3]  = IntVector.fromArray(SPECIES, blockData,  3 * LANES);
        W[4]  = IntVector.fromArray(SPECIES, blockData,  4 * LANES);
        W[5]  = IntVector.fromArray(SPECIES, blockData,  5 * LANES);
        W[6]  = IntVector.fromArray(SPECIES, blockData,  6 * LANES);
        W[7]  = IntVector.fromArray(SPECIES, blockData,  7 * LANES);
        W[8]  = IntVector.fromArray(SPECIES, blockData,  8 * LANES);
        W[9]  = IntVector.fromArray(SPECIES, blockData,  9 * LANES);
        W[10] = IntVector.fromArray(SPECIES, blockData, 10 * LANES);
        W[11] = IntVector.fromArray(SPECIES, blockData, 11 * LANES);
        W[12] = IntVector.fromArray(SPECIES, blockData, 12 * LANES);
        W[13] = IntVector.fromArray(SPECIES, blockData, 13 * LANES);
        W[14] = IntVector.fromArray(SPECIES, blockData, 14 * LANES);
        W[15] = IntVector.fromArray(SPECIES, blockData, 15 * LANES);

        for (int t = 0; t < 64; ++t)
        {
            IntVector wt;
            if (t < 16)
            {
                wt = W[t];
            }
            else
            {
                int idx  = t & 15;
                IntVector wm2  = W[(t + 14) & 15];
                IntVector wm7  = W[(t +  9) & 15];
                IntVector wm15 = W[(t +  1) & 15];
                IntVector wm16 = W[idx];
                wt = sigma1(wm2).add(wm7).add(sigma0(wm15)).add(wm16);
                W[idx] = wt;
            }

            IntVector T1 = h.add(sum1(e)).add(ch(e, f, g)).add(K_V[t]).add(wt);
            IntVector T2 = sum0(a).add(maj(a, b, c));
            h = g; g = f; f = e;
            e = d.add(T1);
            d = c; c = b; b = a;
            a = T1.add(T2);
        }

        a.add(ia).intoArray(outState, 0 * LANES);
        b.add(ib).intoArray(outState, 1 * LANES);
        c.add(ic).intoArray(outState, 2 * LANES);
        d.add(id).intoArray(outState, 3 * LANES);
        e.add(ie).intoArray(outState, 4 * LANES);
        f.add(iF).intoArray(outState, 5 * LANES);
        g.add(ig).intoArray(outState, 6 * LANES);
        h.add(ih).intoArray(outState, 7 * LANES);
    }

    private static IntVector ch(IntVector x, IntVector y, IntVector z)
    {
        // (x AND y) XOR (NOT x AND z)
        return x.lanewise(VectorOperators.AND, y)
                .lanewise(VectorOperators.XOR,
                          x.lanewise(VectorOperators.NOT)
                           .lanewise(VectorOperators.AND, z));
    }

    private static IntVector maj(IntVector x, IntVector y, IntVector z)
    {
        // (x AND y) XOR (x AND z) XOR (y AND z)
        IntVector xy = x.lanewise(VectorOperators.AND, y);
        IntVector xz = x.lanewise(VectorOperators.AND, z);
        IntVector yz = y.lanewise(VectorOperators.AND, z);
        return xy.lanewise(VectorOperators.XOR, xz).lanewise(VectorOperators.XOR, yz);
    }

    private static IntVector sum0(IntVector x)
    {
        // ROTR^2 ^ ROTR^13 ^ ROTR^22
        return x.lanewise(VectorOperators.ROR,  2)
                .lanewise(VectorOperators.XOR,
                          x.lanewise(VectorOperators.ROR, 13))
                .lanewise(VectorOperators.XOR,
                          x.lanewise(VectorOperators.ROR, 22));
    }

    private static IntVector sum1(IntVector x)
    {
        // ROTR^6 ^ ROTR^11 ^ ROTR^25
        return x.lanewise(VectorOperators.ROR,  6)
                .lanewise(VectorOperators.XOR,
                          x.lanewise(VectorOperators.ROR, 11))
                .lanewise(VectorOperators.XOR,
                          x.lanewise(VectorOperators.ROR, 25));
    }

    private static IntVector sigma0(IntVector x)
    {
        // ROTR^7 ^ ROTR^18 ^ SHR^3
        return x.lanewise(VectorOperators.ROR,  7)
                .lanewise(VectorOperators.XOR,
                          x.lanewise(VectorOperators.ROR, 18))
                .lanewise(VectorOperators.XOR,
                          x.lanewise(VectorOperators.LSHR, 3));
    }

    private static IntVector sigma1(IntVector x)
    {
        // ROTR^17 ^ ROTR^19 ^ SHR^10
        return x.lanewise(VectorOperators.ROR, 17)
                .lanewise(VectorOperators.XOR,
                          x.lanewise(VectorOperators.ROR, 19))
                .lanewise(VectorOperators.XOR,
                          x.lanewise(VectorOperators.LSHR, 10));
    }

    private static final int[] K = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };

    static
    {
        IntVector[] kv = new IntVector[64];
        for (int i = 0; i < 64; i++)
        {
            kv[i] = IntVector.broadcast(SPECIES, K[i]);
        }
        K_V = kv;
    }
}