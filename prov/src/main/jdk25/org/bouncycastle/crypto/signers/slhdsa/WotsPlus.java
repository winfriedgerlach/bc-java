package org.bouncycastle.crypto.signers.slhdsa;

import org.bouncycastle.crypto.digests.SHA256BatchedVectorImpl;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;

/**
 * WOTS+ chains for SLH-DSA.
 * <p>
 * JDK 25+ multi-release overlay.  Behaviour matches the base
 * {@code core/src/main/java} class exactly; the only change is that
 * {@link #pkGen} dispatches its {@code WOTS_LEN} chain loop through
 * {@link #pkGenBatched} when the host meets the
 * {@code org.bouncycastle.slhdsa.wots.vector.minLanes} threshold and
 * the engine is the SHA-256–based {@link SLHDSAEngine.Sha2Engine}.  The
 * batched path runs {@code LANES} independent chains lane-parallel
 * through {@link SHA256BatchedVectorImpl}; each F-call on the chain
 * collapses into a single batched 64-byte SHA-256 compression instead
 * of {@code LANES} scalar ones.
 * <p>
 * {@link #sign} and {@link #pkFromSig} stay scalar — their chain
 * lengths vary per chain index ({@code msg[i]} and {@code w-1-msg[i]}),
 * so naïvely batching there would do excess work or require length
 * grouping.  The pkGen path is the dominant cost in keygen and the
 * tree-hash auth-path construction, which is what the doc's "real 3–4×
 * on signing throughput" claim is anchored on.
 */
class WotsPlus
{
    /**
     * Minimum {@code SHA256BatchedVectorImpl.LANES} count at which the
     * batched chain path is activated.  Defaults to 8 (AVX2 width); set
     * {@code -Dorg.bouncycastle.slhdsa.wots.vector.minLanes=4} to engage
     * on smaller SIMD or for the JDK 25 regression tests.
     */
    private static final int MIN_LANES = Integer.getInteger(
        "org.bouncycastle.slhdsa.wots.vector.minLanes", 8);

    private static final int VECTOR_LANES = detectVectorLanes();
    private static final boolean VECTOR_AVAILABLE = VECTOR_LANES >= MIN_LANES;

    private static int detectVectorLanes()
    {
        try
        {
            return SHA256BatchedVectorImpl.probe();
        }
        catch (Throwable t)
        {
            return 0;
        }
    }

    private final SLHDSAEngine engine;
    private final int w;

    WotsPlus(SLHDSAEngine engine)
    {
        this.engine = engine;
        this.w = this.engine.WOTS_W;
    }

    byte[] pkGen(byte[] skSeed, byte[] pkSeed, ADRS paramAdrs)
    {
        if (VECTOR_AVAILABLE && engine instanceof SLHDSAEngine.Sha2Engine)
        {
            return pkGenBatched(skSeed, pkSeed, paramAdrs);
        }
        return pkGenScalar(skSeed, pkSeed, paramAdrs);
    }

    /**
     * Reference scalar pkGen — the original implementation, retained
     * unchanged so the overlay can dispatch and the regression test can
     * run both paths back-to-back on the same JVM.
     */
    byte[] pkGenScalar(byte[] skSeed, byte[] pkSeed, ADRS paramAdrs)
    {
        ADRS wotspkADRS = new ADRS(paramAdrs); // copy address to create OTS public key address

        byte[][] tmp = new byte[engine.WOTS_LEN][];
        for (int i = 0; i < engine.WOTS_LEN; i++)
        {
            ADRS adrs = new ADRS(paramAdrs);
            adrs.setTypeAndClear(ADRS.WOTS_PRF);
            adrs.setKeyPairAddress(paramAdrs.getKeyPairAddress());
            adrs.setChainAddress(i);
            adrs.setHashAddress(0);

            byte[] sk = engine.PRF(pkSeed, skSeed, adrs);

            adrs.setTypeAndClear(ADRS.WOTS_HASH);
            adrs.setKeyPairAddress(paramAdrs.getKeyPairAddress());
            adrs.setChainAddress(i);
            adrs.setHashAddress(0);
            tmp[i] = chain(sk, 0, w - 1, pkSeed, adrs);
        }

        wotspkADRS.setTypeAndClear(ADRS.WOTS_PK);
        wotspkADRS.setKeyPairAddress(paramAdrs.getKeyPairAddress());

        return engine.T_l(pkSeed, wotspkADRS, Arrays.concatenate(tmp));
    }

    /**
     * Lane-parallel pkGen using {@link SHA256BatchedVectorImpl} for the
     * {@code WOTS_LEN}-by-{@code w-1} F-call grid.  Chains in groups of
     * {@code LANES} run in lockstep through {@code w-1} batched F-calls;
     * the partial tail (fewer than {@code LANES} chains) falls back to
     * the scalar chain loop.  PRF / T_l stay scalar — they're called
     * once per pkGen and aren't batchable in the same shape.
     */
    private byte[] pkGenBatched(byte[] skSeed, byte[] pkSeed, ADRS paramAdrs)
    {
        ADRS wotspkADRS = new ADRS(paramAdrs);

        // Generate sk values up front (PRF call per chain — scalar).
        byte[][] sk = new byte[engine.WOTS_LEN][];
        for (int i = 0; i < engine.WOTS_LEN; i++)
        {
            ADRS adrs = new ADRS(paramAdrs);
            adrs.setTypeAndClear(ADRS.WOTS_PRF);
            adrs.setKeyPairAddress(paramAdrs.getKeyPairAddress());
            adrs.setChainAddress(i);
            adrs.setHashAddress(0);
            sk[i] = engine.PRF(pkSeed, skSeed, adrs);
        }

        final int N = engine.N;
        final long bitLen = (64L + 22 + N) * 8L;
        final int lanes = SHA256BatchedVectorImpl.LANES;

        final int[] preState = derivePreState(pkSeed);
        final byte[] adrsPrefix14 = buildAdrsPrefix14(paramAdrs);

        byte[][] tmp = new byte[engine.WOTS_LEN][];

        // Reusable scratch buffers.  laneState[b] is lane b's running
        // chain value (the input to F at the start of each step, the
        // output at the end).  scratchBlock is one persistent 64-byte
        // SHA-256 input block we overwrite per (chunk, step, lane) — its
        // [0..14) prefix and [22+N..64) tail are constant across the
        // whole pkGen, so we set them once up front and only rewrite the
        // [14..22+N) middle inside the hot loop.
        int[] blockData = new int[16 * lanes];
        int[] outState = new int[8 * lanes];
        byte[][] laneState = new byte[lanes][N];
        byte[] scratchBlock = new byte[64];
        System.arraycopy(adrsPrefix14, 0, scratchBlock, 0, 14);
        scratchBlock[22 + N] = (byte)0x80;
        for (int k = 0; k < 8; k++)
        {
            scratchBlock[56 + k] = (byte)(bitLen >>> ((7 - k) * 8));
        }

        int batched = (engine.WOTS_LEN / lanes) * lanes;
        for (int chunkStart = 0; chunkStart < batched; chunkStart += lanes)
        {
            for (int b = 0; b < lanes; b++)
            {
                System.arraycopy(sk[chunkStart + b], 0, laneState[b], 0, N);
            }

            for (int j = 0; j < w - 1; j++)
            {
                buildBlockData(blockData, lanes, scratchBlock, chunkStart, j, N, laneState);
                SHA256BatchedVectorImpl.compressBatch(preState, blockData, outState);
                extractLaneStates(outState, lanes, N, laneState);
            }

            for (int b = 0; b < lanes; b++)
            {
                tmp[chunkStart + b] = Arrays.clone(laneState[b]);
            }
        }

        // Tail: scalar chain for any remaining chains that don't fill a
        // full LANES-wide batch.
        for (int i = batched; i < engine.WOTS_LEN; i++)
        {
            ADRS adrs = new ADRS(paramAdrs);
            adrs.setTypeAndClear(ADRS.WOTS_HASH);
            adrs.setKeyPairAddress(paramAdrs.getKeyPairAddress());
            adrs.setChainAddress(i);
            adrs.setHashAddress(0);
            tmp[i] = chain(sk[i], 0, w - 1, pkSeed, adrs);
        }

        wotspkADRS.setTypeAndClear(ADRS.WOTS_PK);
        wotspkADRS.setKeyPairAddress(paramAdrs.getKeyPairAddress());

        return engine.T_l(pkSeed, wotspkADRS, Arrays.concatenate(tmp));
    }

    // #Input: Input string X, start index i, number of steps s, public seed PK.seed, address ADRS
    // #Output: value of F iterated s times on X
    byte[] chain(byte[] X, int i, int s, byte[] pkSeed, ADRS adrs)
    {
        if (s == 0)
        {
            return Arrays.clone(X);
        }
        if ((i + s) > (this.w - 1))
        {
            return null;
        }
        byte[] result = X;
        for (int j = 0; j < s; ++j)
        {
            adrs.setHashAddress(i + j);
            result = engine.F(pkSeed, adrs, result);
        }
        return result;
    }

    // #Input: Message M, secret seed SK.seed, public seed PK.seed, address ADRS
    // #Output: WOTS+ signature sig
    public byte[] sign(byte[] M, byte[] skSeed, byte[] pkSeed, ADRS paramAdrs)
    {
        ADRS adrs = new ADRS(paramAdrs);

        int[] msg = new int[engine.WOTS_LEN];

        // convert message to base w
        base_w(M, 0, w, msg, 0, engine.WOTS_LEN1);

        // compute checksum
        int csum = 0;
        for (int i = 0; i < engine.WOTS_LEN1; i++)
        {
            csum += w - 1 - msg[i];
        }

        // convert csum to base w
        if ((engine.WOTS_LOGW % 8) != 0)
        {
            csum = csum << (8 - ((engine.WOTS_LEN2 * engine.WOTS_LOGW) % 8));
        }
        int len_2_bytes = (engine.WOTS_LEN2 * engine.WOTS_LOGW + 7) / 8;
        byte[] csum_bytes = Pack.intToBigEndian(csum);
        base_w(csum_bytes, 4 - len_2_bytes, w, msg, engine.WOTS_LEN1, engine.WOTS_LEN2);

        byte[][] sig = new byte[engine.WOTS_LEN][];
        for (int i = 0; i < engine.WOTS_LEN; i++)
        {
            adrs.setTypeAndClear(ADRS.WOTS_PRF);
            adrs.setKeyPairAddress(paramAdrs.getKeyPairAddress());
            adrs.setChainAddress(i);
            adrs.setHashAddress(0);
            byte[] sk = engine.PRF(pkSeed, skSeed, adrs);
            adrs.setTypeAndClear(ADRS.WOTS_HASH);
            adrs.setKeyPairAddress(paramAdrs.getKeyPairAddress());
            adrs.setChainAddress(i);
            adrs.setHashAddress(0);
            sig[i] = chain(sk, 0, msg[i], pkSeed, adrs);
        }
        return Arrays.concatenate(sig);
    }

    //
    // Input: len_X-byte string X, int w, output length out_len
    // Output: out_len int array basew
    void base_w(byte[] X, int XOff, int w, int[] output, int outOff, int outLen)
    {
        int total = 0;
        int bits = 0;

        for (int consumed = 0; consumed < outLen; consumed++)
        {
            if (bits == 0)
            {
                total = X[XOff++];
                bits += 8;
            }
            bits -= engine.WOTS_LOGW;
            output[outOff++] = ((total >>> bits) & (w - 1));
        }
    }

    public byte[] pkFromSig(byte[] sig, byte[] M, byte[] pkSeed, ADRS adrs)
    {
        ADRS wotspkADRS = new ADRS(adrs);

        int[] msg = new int[engine.WOTS_LEN];

        // convert message to base w
        base_w(M, 0, w, msg, 0, engine.WOTS_LEN1);

        // compute checksum
        int csum = 0;
        for (int i = 0; i < engine.WOTS_LEN1; i++ )
        {
            csum += w - 1 - msg[i];
        }

        // convert csum to base w
        csum = csum << (8 - ((engine.WOTS_LEN2 * engine.WOTS_LOGW) % 8));
        int len_2_bytes = (engine.WOTS_LEN2 * engine.WOTS_LOGW + 7) / 8;
        byte[] csum_bytes = Pack.intToBigEndian(csum);
        base_w(csum_bytes, 4 - len_2_bytes, w, msg, engine.WOTS_LEN1, engine.WOTS_LEN2);

        byte[] sigI = new byte[engine.N];
        byte[][] tmp = new byte[engine.WOTS_LEN][];
        for (int  i = 0; i < engine.WOTS_LEN; i++ )
        {
            adrs.setChainAddress(i);
            System.arraycopy(sig, i * engine.N, sigI, 0, engine.N);
            tmp[i] = chain(sigI, msg[i], w - 1 - msg[i], pkSeed, adrs);
        }

        wotspkADRS.setTypeAndClear(ADRS.WOTS_PK);
        wotspkADRS.setKeyPairAddress(adrs.getKeyPairAddress());

        return engine.T_l(pkSeed, wotspkADRS, Arrays.concatenate(tmp));
    }

    // ----- helpers for the batched path -----

    /**
     * Mirrors {@link SLHDSAEngine.Sha2Engine}'s init memoisation:
     * SHA-256 over {@code pkSeed} extended to 64 zero-padded bytes,
     * one block of compression, returning the resulting H1..H8.
     */
    static int[] derivePreState(byte[] pkSeed)
    {
        byte[] pkSeedBlock = new byte[64];
        System.arraycopy(pkSeed, 0, pkSeedBlock, 0, pkSeed.length);

        SHA256Digest dig = new SHA256Digest();
        dig.update(pkSeedBlock, 0, 64); // exactly one block triggers processBlock

        // SHA256Digest.getEncodedState lays out byte-length / xBuf / xBufOff
        // first, then H1..H8 at offsets 16..44 (4 bytes each, big-endian).
        byte[] enc = dig.getEncodedState();
        int[] preState = new int[8];
        for (int i = 0; i < 8; i++)
        {
            int off = 16 + 4 * i;
            preState[i] = ((enc[off    ] & 0xff) << 24)
                        | ((enc[off + 1] & 0xff) << 16)
                        | ((enc[off + 2] & 0xff) <<  8)
                        | ((enc[off + 3] & 0xff)      );
        }
        return preState;
    }

    /**
     * Builds the 14-byte fixed prefix of {@code Sha2Engine.compressedADRS}
     * for the WOTS_HASH type — the bytes that don't change across lanes
     * or chain steps.  The remaining 8 bytes (chain address, hash address)
     * are filled per-block in {@link #buildBlockData}.
     */
    static byte[] buildAdrsPrefix14(ADRS paramAdrs)
    {
        byte[] p = new byte[14];
        p[0] = paramAdrs.value[ADRS.OFFSET_LAYER + 3];
        System.arraycopy(paramAdrs.value, ADRS.OFFSET_TREE + 4, p, 1, 8);
        p[9] = (byte)ADRS.WOTS_HASH;
        System.arraycopy(paramAdrs.value, ADRS.OFFSET_KP_ADDR, p, 10, 4);
        return p;
    }

    /**
     * Fills {@code blockData} (transposed lane-major) for one batched
     * compression step.  {@code scratchBlock} is a 64-byte buffer whose
     * constant prefix (bytes 0..14: ADRS layer / tree / type / kp) and
     * tail (bytes 22+N..64: 0x80 / zeros / bit length) have been written
     * once by the caller; this method only rewrites the per-(lane, step)
     * middle ([14..22+N): chain idx, hash addr, m1) and packs the result
     * into {@code blockData}.
     */
    private static void buildBlockData(int[] blockData, int lanes, byte[] scratchBlock,
        int chunkStart, int hashAddr, int N, byte[][] laneState)
    {
        scratchBlock[18] = (byte)(hashAddr >>> 24);
        scratchBlock[19] = (byte)(hashAddr >>> 16);
        scratchBlock[20] = (byte)(hashAddr >>>  8);
        scratchBlock[21] = (byte)hashAddr;

        for (int b = 0; b < lanes; b++)
        {
            int chainIdx = chunkStart + b;
            scratchBlock[14] = (byte)(chainIdx >>> 24);
            scratchBlock[15] = (byte)(chainIdx >>> 16);
            scratchBlock[16] = (byte)(chainIdx >>>  8);
            scratchBlock[17] = (byte)chainIdx;

            System.arraycopy(laneState[b], 0, scratchBlock, 22, N);

            for (int s = 0; s < 16; s++)
            {
                blockData[s * lanes + b] =
                      ((scratchBlock[4*s    ] & 0xff) << 24)
                    | ((scratchBlock[4*s + 1] & 0xff) << 16)
                    | ((scratchBlock[4*s + 2] & 0xff) <<  8)
                    | ((scratchBlock[4*s + 3] & 0xff)      );
            }
        }
    }

    private static void extractLaneStates(int[] outState, int lanes, int N, byte[][] laneState)
    {
        for (int b = 0; b < lanes; b++)
        {
            for (int s = 0; s < (N + 3) / 4; s++)
            {
                int word = outState[s * lanes + b];
                int off = s * 4;
                if (off     < N) laneState[b][off    ] = (byte)(word >>> 24);
                if (off + 1 < N) laneState[b][off + 1] = (byte)(word >>> 16);
                if (off + 2 < N) laneState[b][off + 2] = (byte)(word >>>  8);
                if (off + 3 < N) laneState[b][off + 3] = (byte)word;
            }
        }
    }
}