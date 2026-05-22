package org.bouncycastle.crypto.engines;

import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.util.Integers;
import org.bouncycastle.util.Pack;

/**
 * Implementation of Daniel J. Bernstein's ChaCha stream cipher.
 * <p>
 * JDK 25+ multi-release overlay: identical to the base
 * {@code core/src/main/java} variant except that {@link #processBytes} routes
 * aligned bulk runs through {@link ChaChaVectorImpl}, a lane-parallel core
 * built on the {@code jdk.incubator.vector} API.  The vector path is used
 * only when the runtime exposes that module and only above a length
 * threshold where the SIMD speed-up outweighs setup cost; everything else
 * falls through to the inherited scalar loop in {@link Salsa20Engine}.
 * Output is bit-for-bit identical to the base implementation.
 * <p>
 * The overlay sits at the {@code jdk25} layer rather than {@code jdk17} so
 * the runtime gets the more mature C2 codegen for {@code jdk.incubator.vector}
 * shipped with JDK 25 — the rotate-heavy ChaCha kernel is sensitive to it,
 * and earlier JIT backends can underperform the scalar path on AVX2.
 * Older JVMs continue to load the unchanged base class.
 */
public class ChaChaEngine extends Salsa20Engine
{
    /**
     * Minimum {@code IntVector} lane count at which the vector path is
     * activated by default.  On AVX-512 (16 lanes) the per-round rotate
     * compiles to a single {@code vprolld} and the kernel comfortably
     * beats the inherited scalar loop; on AVX2 (8 lanes) the rotate
     * emulates as {@code vpsllld + vpsrld + vpor} and a first-pass
     * implementation can run slower than the scalar baseline, so AVX2
     * is held back behind an opt-in property by default.
     * <p>
     * Override at runtime with
     * {@code -Dorg.bouncycastle.chacha.vector.minLanes=8} to force
     * activation on AVX2 (useful for tests or for benchmarking a more
     * tuned kernel).
     */
    private static final int MIN_LANES = Integer.getInteger(
        "org.bouncycastle.chacha.vector.minLanes", 16);

    private static final int VECTOR_LANES = detectVectorLanes();
    private static final boolean VECTOR_ENABLED = VECTOR_LANES >= MIN_LANES;

    private static int detectVectorLanes()
    {
        // The probe forces ChaChaVectorImpl to initialise, which in turn
        // resolves the jdk.incubator.vector references.  If the module is
        // absent (the JVM does not auto-add incubator modules), the linkage
        // failure surfaces here and we disable the vector path; loading of
        // ChaChaEngine itself is unaffected because it never references
        // jdk.incubator.vector directly.
        try
        {
            return ChaChaVectorImpl.probe();
        }
        catch (Throwable t)
        {
            return 0;
        }
    }

    /**
     * Creates a 20 rounds ChaCha engine.
     */
    public ChaChaEngine()
    {
        super();
    }

    /**
     * Creates a ChaCha engine with a specific number of rounds.
     * @param rounds the number of rounds (must be an even number).
     */
    public ChaChaEngine(int rounds)
    {
        super(rounds);
    }

    public String getAlgorithmName()
    {
        return "ChaCha" + rounds;
    }

    protected void advanceCounter(long diff)
    {
        int hi = (int)(diff >>> 32);
        int lo = (int)diff;

        if (hi > 0)
        {
            engineState[13] += hi;
        }

        int oldState = engineState[12];

        engineState[12] += lo;

        if (oldState != 0 && engineState[12] < oldState)
        {
            engineState[13]++;
        }
    }

    protected void advanceCounter()
    {
        if (++engineState[12] == 0)
        {
            ++engineState[13];
        }
    }

    protected void retreatCounter(long diff)
    {
        int hi = (int)(diff >>> 32);
        int lo = (int)diff;

        if (hi != 0)
        {
            if ((engineState[13] & 0xffffffffL) >= (hi & 0xffffffffL))
            {
                engineState[13] -= hi;
            }
            else
            {
                throw new IllegalStateException("attempt to reduce counter past zero.");
            }
        }

        if ((engineState[12] & 0xffffffffL) >= (lo & 0xffffffffL))
        {
            engineState[12] -= lo;
        }
        else
        {
            if (engineState[13] != 0)
            {
                --engineState[13];
                engineState[12] -= lo;
            }
            else
            {
                throw new IllegalStateException("attempt to reduce counter past zero.");
            }
        }
    }

    protected void retreatCounter()
    {
        if (engineState[12] == 0 && engineState[13] == 0)
        {
            throw new IllegalStateException("attempt to reduce counter past zero.");
        }

        if (--engineState[12] == -1)
        {
            --engineState[13];
        }
    }

    protected long getCounter()
    {
        return ((long)engineState[13] << 32) | (engineState[12] & 0xffffffffL);
    }

    protected void resetCounter()
    {
        engineState[12] = engineState[13] = 0;
    }

    protected void setKey(byte[] keyBytes, byte[] ivBytes)
    {
        if (keyBytes != null)
        {
            if ((keyBytes.length != 16) && (keyBytes.length != 32))
            {
                throw new IllegalArgumentException(getAlgorithmName() + " requires 128 bit or 256 bit key");
            }

            packTauOrSigma(keyBytes.length, engineState, 0);

            // Key
            Pack.littleEndianToInt(keyBytes, 0, engineState, 4, 4);
            Pack.littleEndianToInt(keyBytes, keyBytes.length - 16, engineState, 8, 4);
        }

        // IV
        Pack.littleEndianToInt(ivBytes, 0, engineState, 14, 2);
    }

    protected void generateKeyStream(byte[] output)
    {
        chachaCore(rounds, engineState, x);
        Pack.intToLittleEndian(x, output, 0);
    }

    @Override
    public int processBytes(byte[] in, int inOff, int len, byte[] out, int outOff)
    {
        if (!VECTOR_ENABLED || len < (VECTOR_LANES << 6))
        {
            return super.processBytes(in, inOff, len, out, outOff);
        }

        if ((inOff + len) > in.length)
        {
            throw new DataLengthException("input buffer too short");
        }
        if ((outOff + len) > out.length)
        {
            throw new OutputLengthException("output buffer too short");
        }

        int processed = 0;

        // Drain any partial-block leftover from the inherited key-stream
        // cache through the scalar path so we resume aligned to a 64-byte
        // boundary.  getPosition() is the public projection of (counter,
        // index) and avoids reaching into Salsa20Engine's private state.
        // The call is unconditional: a prefix length of zero still routes
        // through super and so inherits the "<algo> not initialised"
        // IllegalStateException check that would otherwise be skipped on
        // an aligned input.
        int intoBlock = (int)(getPosition() & 63);
        int prefix = (intoBlock != 0) ? Math.min(64 - intoBlock, len) : 0;
        super.processBytes(in, inOff, prefix, out, outOff);
        inOff   += prefix;
        outOff  += prefix;
        processed += prefix;
        len     -= prefix;

        if (len >= (VECTOR_LANES << 6))
        {
            int chunkBytes = VECTOR_LANES << 6;
            int chunks = len / chunkBytes;
            int bulkBytes = chunks * chunkBytes;

            int[] counters = new int[2 * VECTOR_LANES];

            for (int c = 0; c < chunks; ++c)
            {
                fillCounters(counters);
                ChaChaVectorImpl.processBlocks(rounds, engineState, counters,
                    in, inOff, out, outOff);
                advanceCounterBlocks(VECTOR_LANES);
                inOff  += chunkBytes;
                outOff += chunkBytes;
            }

            processed += bulkBytes;
            len     -= bulkBytes;

            // Refresh the inherited key-stream cache for the new counter
            // and account for the bytes we wrote outside super.processBytes
            // against the per-IV byte limit.
            noteBlocksProcessed(bulkBytes);
        }

        if (len > 0)
        {
            super.processBytes(in, inOff, len, out, outOff);
            processed += len;
        }

        return processed;
    }

    private void fillCounters(int[] counters)
    {
        long base = ((long)engineState[13] << 32) | (engineState[12] & 0xffffffffL);
        for (int i = 0; i < VECTOR_LANES; ++i)
        {
            long v = base + i;
            counters[i              ] = (int)v;
            counters[i + VECTOR_LANES] = (int)(v >>> 32);
        }
    }

    private void advanceCounterBlocks(int blocks)
    {
        long c = ((long)engineState[13] << 32) | (engineState[12] & 0xffffffffL);
        c += blocks;
        engineState[12] = (int)c;
        engineState[13] = (int)(c >>> 32);
    }

    /**
     * ChaCha function
     *
     * @param   input   input data
     */
    public static void chachaCore(int rounds, int[] input, int[] x)
    {
        if (input.length != 16)
        {
            throw new IllegalArgumentException();
        }
        if (x.length != 16)
        {
            throw new IllegalArgumentException();
        }
        if (rounds % 2 != 0)
        {
            throw new IllegalArgumentException("Number of rounds must be even");
        }

        int x00 = input[ 0];
        int x01 = input[ 1];
        int x02 = input[ 2];
        int x03 = input[ 3];
        int x04 = input[ 4];
        int x05 = input[ 5];
        int x06 = input[ 6];
        int x07 = input[ 7];
        int x08 = input[ 8];
        int x09 = input[ 9];
        int x10 = input[10];
        int x11 = input[11];
        int x12 = input[12];
        int x13 = input[13];
        int x14 = input[14];
        int x15 = input[15];

        for (int i = rounds; i > 0; i -= 2)
        {
            x00 += x04; x12 = Integers.rotateLeft(x12 ^ x00, 16);
            x08 += x12; x04 = Integers.rotateLeft(x04 ^ x08, 12);
            x00 += x04; x12 = Integers.rotateLeft(x12 ^ x00, 8);
            x08 += x12; x04 = Integers.rotateLeft(x04 ^ x08, 7);
            x01 += x05; x13 = Integers.rotateLeft(x13 ^ x01, 16);
            x09 += x13; x05 = Integers.rotateLeft(x05 ^ x09, 12);
            x01 += x05; x13 = Integers.rotateLeft(x13 ^ x01, 8);
            x09 += x13; x05 = Integers.rotateLeft(x05 ^ x09, 7);
            x02 += x06; x14 = Integers.rotateLeft(x14 ^ x02, 16);
            x10 += x14; x06 = Integers.rotateLeft(x06 ^ x10, 12);
            x02 += x06; x14 = Integers.rotateLeft(x14 ^ x02, 8);
            x10 += x14; x06 = Integers.rotateLeft(x06 ^ x10, 7);
            x03 += x07; x15 = Integers.rotateLeft(x15 ^ x03, 16);
            x11 += x15; x07 = Integers.rotateLeft(x07 ^ x11, 12);
            x03 += x07; x15 = Integers.rotateLeft(x15 ^ x03, 8);
            x11 += x15; x07 = Integers.rotateLeft(x07 ^ x11, 7);
            x00 += x05; x15 = Integers.rotateLeft(x15 ^ x00, 16);
            x10 += x15; x05 = Integers.rotateLeft(x05 ^ x10, 12);
            x00 += x05; x15 = Integers.rotateLeft(x15 ^ x00, 8);
            x10 += x15; x05 = Integers.rotateLeft(x05 ^ x10, 7);
            x01 += x06; x12 = Integers.rotateLeft(x12 ^ x01, 16);
            x11 += x12; x06 = Integers.rotateLeft(x06 ^ x11, 12);
            x01 += x06; x12 = Integers.rotateLeft(x12 ^ x01, 8);
            x11 += x12; x06 = Integers.rotateLeft(x06 ^ x11, 7);
            x02 += x07; x13 = Integers.rotateLeft(x13 ^ x02, 16);
            x08 += x13; x07 = Integers.rotateLeft(x07 ^ x08, 12);
            x02 += x07; x13 = Integers.rotateLeft(x13 ^ x02, 8);
            x08 += x13; x07 = Integers.rotateLeft(x07 ^ x08, 7);
            x03 += x04; x14 = Integers.rotateLeft(x14 ^ x03, 16);
            x09 += x14; x04 = Integers.rotateLeft(x04 ^ x09, 12);
            x03 += x04; x14 = Integers.rotateLeft(x14 ^ x03, 8);
            x09 += x14; x04 = Integers.rotateLeft(x04 ^ x09, 7);

        }

        x[ 0] = x00 + input[ 0];
        x[ 1] = x01 + input[ 1];
        x[ 2] = x02 + input[ 2];
        x[ 3] = x03 + input[ 3];
        x[ 4] = x04 + input[ 4];
        x[ 5] = x05 + input[ 5];
        x[ 6] = x06 + input[ 6];
        x[ 7] = x07 + input[ 7];
        x[ 8] = x08 + input[ 8];
        x[ 9] = x09 + input[ 9];
        x[10] = x10 + input[10];
        x[11] = x11 + input[11];
        x[12] = x12 + input[12];
        x[13] = x13 + input[13];
        x[14] = x14 + input[14];
        x[15] = x15 + input[15];
    }
}