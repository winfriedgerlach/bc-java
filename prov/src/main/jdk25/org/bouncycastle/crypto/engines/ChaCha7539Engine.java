package org.bouncycastle.crypto.engines;

import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.util.Pack;

/**
 * Implementation of Daniel J. Bernstein's ChaCha stream cipher.
 * <p>
 * JDK 25+ multi-release overlay.  Behaviour and externally visible state
 * match the base {@code core/src/main/java} class exactly; the only
 * addition is a vectorised bulk path in {@link #processBytes} that uses
 * {@link ChaChaVectorImpl} when {@code jdk.incubator.vector} is available
 * at runtime.  RFC 7539's 32-bit counter is enforced lane-by-lane: if
 * processing the next {@code VECTOR_LANES} blocks would wrap
 * {@code state[12]} the engine falls back to the scalar path so the
 * eventual overflow throws from the existing {@link #advanceCounter()}
 * with the same {@code "attempt to increase counter past 2^32."} message.
 */
public class ChaCha7539Engine extends Salsa20Engine
{
    /**
     * Minimum {@code IntVector} lane count at which the vector path is
     * activated.  See {@link ChaChaEngine#MIN_LANES} for the rationale
     * and the {@code org.bouncycastle.chacha.vector.minLanes} property
     * that controls it.
     */
    private static final int MIN_LANES = Integer.getInteger(
        "org.bouncycastle.chacha.vector.minLanes", 16);

    private static final int VECTOR_LANES = detectVectorLanes();
    private static final boolean VECTOR_ENABLED = VECTOR_LANES >= MIN_LANES;

    private static int detectVectorLanes()
    {
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
    public ChaCha7539Engine()
    {
        super();
    }

    public String getAlgorithmName()
    {
        return "ChaCha7539";
    }

    protected int getNonceSize()
    {
        return 12;
    }

    protected void advanceCounter(long diff)
    {
        int hi = (int)(diff >>> 32);
        int lo = (int)diff;

        if (hi > 0)
        {
            throw new IllegalStateException("attempt to increase counter past 2^32.");
        }

        int oldState = engineState[12];

        engineState[12] += lo;

        if (oldState != 0 && engineState[12] < oldState)
        {
            throw new IllegalStateException("attempt to increase counter past 2^32.");
        }
    }

    protected void advanceCounter()
    {
        if (++engineState[12] == 0)
        {
            throw new IllegalStateException("attempt to increase counter past 2^32.");
        }
    }

    protected void retreatCounter(long diff)
    {
        int hi = (int)(diff >>> 32);
        int lo = (int)diff;

        if (hi != 0)
        {
            throw new IllegalStateException("attempt to reduce counter past zero.");
        }

        if ((engineState[12] & 0xffffffffL) >= (lo & 0xffffffffL))
        {
            engineState[12] -= lo;
        }
        else
        {
            throw new IllegalStateException("attempt to reduce counter past zero.");
        }
    }

    protected void retreatCounter()
    {
        if (engineState[12] == 0)
        {
            throw new IllegalStateException("attempt to reduce counter past zero.");
        }

        --engineState[12];
    }

    protected long getCounter()
    {
        return engineState[12] & 0xffffffffL;
    }

    protected void resetCounter()
    {
        engineState[12] = 0;
    }

    protected void setKey(byte[] keyBytes, byte[] ivBytes)
    {
        if (keyBytes != null)
        {
            if (keyBytes.length != 32)
            {
                throw new IllegalArgumentException(getAlgorithmName() + " requires 256 bit key");
            }

            packTauOrSigma(keyBytes.length, engineState, 0);

            // Key
            Pack.littleEndianToInt(keyBytes, 0, engineState, 4, 8);
        }

        // IV
        Pack.littleEndianToInt(ivBytes, 0, engineState, 13, 3);
    }

    protected void generateKeyStream(byte[] output)
    {
        ChaChaEngine.chachaCore(rounds, engineState, x);
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

            int[] counters = new int[2 * VECTOR_LANES];
            // RFC 7539 fixes state[13] as the high half of the 96-bit
            // nonce; the upper LANES words of `counters` broadcast it
            // across every lane.
            for (int i = 0; i < VECTOR_LANES; ++i)
            {
                counters[i + VECTOR_LANES] = engineState[13];
            }

            int bulkBytes = 0;
            while (len >= chunkBytes)
            {
                long base = engineState[12] & 0xffffffffL;
                // RFC 7539 makes a wrap of state[12] an error.  Fall back
                // to the scalar path for any chunk that would cross the
                // 2^32 block boundary so the existing advanceCounter()
                // throws with its established message.
                if (base + VECTOR_LANES > 0xffffffffL)
                {
                    break;
                }

                for (int i = 0; i < VECTOR_LANES; ++i)
                {
                    counters[i] = (int)(base + i);
                }

                ChaChaVectorImpl.processBlocks(rounds, engineState, counters,
                    in, inOff, out, outOff);
                engineState[12] += VECTOR_LANES;

                inOff  += chunkBytes;
                outOff += chunkBytes;
                len    -= chunkBytes;
                bulkBytes += chunkBytes;
            }

            if (bulkBytes > 0)
            {
                processed += bulkBytes;
                noteBlocksProcessed(bulkBytes);
            }
        }

        if (len > 0)
        {
            super.processBytes(in, inOff, len, out, outOff);
            processed += len;
        }

        return processed;
    }
}