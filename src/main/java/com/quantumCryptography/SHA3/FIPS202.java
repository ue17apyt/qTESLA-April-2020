package com.quantumCryptography.SHA3;

import java.nio.ByteBuffer;
import java.util.Arrays;

public class FIPS202 {

    public static final int ROUND_NO = 24;

    public static final long[] KECCAK_F_PERMUTATION_CONST = {
            0x0000000000000001L, 0x0000000000008082L, 0x800000000000808AL, 0x8000000080008000L,
            0x000000000000808BL, 0x0000000080000001L, 0x8000000080008081L, 0x8000000000008009L,
            0x000000000000008AL, 0x0000000000000088L, 0x0000000080008009L, 0x000000008000000AL,
            0x000000008000808BL, 0x800000000000008BL, 0x8000000000008089L, 0x8000000000008003L,
            0x8000000000008002L, 0x8000000000000080L, 0x000000000000800AL, 0x800000008000000AL,
            0x8000000080008081L, 0x8000000000008080L, 0x0000000080000001L, 0x8000000080008008L
    };

    private final int bitrate;
    private final byte sep;

    public FIPS202(int bitrate, byte sep) {
        this.bitrate = bitrate;
        this.sep = sep;
    }

    private static void transformStatesInPermutation(long[] dest, long[] src, int offset, long xorFactor) {

        if (dest.length != 25 || src.length != 5) {
            throw new ArrayIndexOutOfBoundsException(
                    "The destination array should have 25 elements and\n"
                            + "the source array should have 5 elements\n"
                            + "but the destination array has " + dest.length + " elements and\n"
                            + "the source array has " + src.length + " elements.\n"
            );
        }

        for (int index = offset; index < offset + 5; index++) {
            dest[index] = src[index % 5] ^ ((~src[(index + 1) % 5]) & src[(index + 2) % 5]);
        }

        dest[0] ^= xorFactor;

    }

    public int getBitrate() {
        return this.bitrate;
    }

    public void keccakPermuteStates(long[] state) {

        if (state.length != 25) {
            throw new ArrayIndexOutOfBoundsException(
                    "The number of States should be 25 but " + state.length + " states are found.\n");
        }

        long[] B = new long[5];
        long[] D = new long[5];
        long[] E = new long[25];

        for (int round = 0; round < ROUND_NO; round += 2) {
            analyzePermutation(E, state, B, D, round);
            analyzePermutation(state, E, B, D, round + 1);
        }

    }

    private void analyzePermutation(long[] dest, long[] src, long[] B, long[] D, int round) {

        // prepare THETA
        Arrays.fill(B, 0L);

        for (int srcIndex = 0; srcIndex < 25; srcIndex++) {
            B[srcIndex % 5] ^= src[srcIndex];
        }

        // THETA_RHO_PI_IOTA
        for (int dIndex = 0; dIndex < 5; dIndex++) {
            D[dIndex] = B[(dIndex + 4) % 5] ^ Long.rotateLeft(B[(dIndex + 1) % 5], 1);
        }

        src[0] ^= D[0];
        B[0] = src[0];
        src[6] ^= D[1];
        B[1] = Long.rotateLeft(src[6], 44);
        src[12] ^= D[2];
        B[2] = Long.rotateLeft(src[12], 43);
        src[18] ^= D[3];
        B[3] = Long.rotateLeft(src[18], 21);
        src[24] ^= D[4];
        B[4] = Long.rotateLeft(src[24], 14);
        transformStatesInPermutation(dest, B, 0, KECCAK_F_PERMUTATION_CONST[round]);

        src[3] ^= D[3];
        B[0] = Long.rotateLeft(src[3], 28);
        src[9] ^= D[4];
        B[1] = Long.rotateLeft(src[9], 20);
        src[10] ^= D[0];
        B[2] = Long.rotateLeft(src[10], 3);
        src[16] ^= D[1];
        B[3] = Long.rotateLeft(src[16], 45);
        src[22] ^= D[2];
        B[4] = Long.rotateLeft(src[22], 61);
        transformStatesInPermutation(dest, B, 5, 0);

        src[1] ^= D[1];
        B[0] = Long.rotateLeft(src[1], 1);
        src[7] ^= D[2];
        B[1] = Long.rotateLeft(src[7], 6);
        src[13] ^= D[3];
        B[2] = Long.rotateLeft(src[13], 25);
        src[19] ^= D[4];
        B[3] = Long.rotateLeft(src[19], 8);
        src[20] ^= D[0];
        B[4] = Long.rotateLeft(src[20], 18);
        transformStatesInPermutation(dest, B, 10, 0);

        src[4] ^= D[4];
        B[0] = Long.rotateLeft(src[4], 27);
        src[5] ^= D[0];
        B[1] = Long.rotateLeft(src[5], 36);
        src[11] ^= D[1];
        B[2] = Long.rotateLeft(src[11], 10);
        src[17] ^= D[2];
        B[3] = Long.rotateLeft(src[17], 15);
        src[23] ^= D[3];
        B[4] = Long.rotateLeft(src[23], 56);
        transformStatesInPermutation(dest, B, 15, 0);

        src[2] ^= D[2];
        B[0] = Long.rotateLeft(src[2], 62);
        src[8] ^= D[3];
        B[1] = Long.rotateLeft(src[8], 55);
        src[14] ^= D[4];
        B[2] = Long.rotateLeft(src[14], 39);
        src[15] ^= D[0];
        B[3] = Long.rotateLeft(src[15], 41);
        src[21] ^= D[1];
        B[4] = Long.rotateLeft(src[21], 2);
        transformStatesInPermutation(dest, B, 20, 0);

    }

    public void keccakAbsorb(long[] state, int bitrate, ByteBuffer input, int inOffset, long inLen, byte pending) {

        ByteBuffer tempByteBuffer = ByteBuffer.allocate(8 * 25);
        input.position(inOffset);

        while (inLen >= bitrate) {
            for (int stateCounter = 0; stateCounter < (bitrate >>> 3); stateCounter++) {
                state[stateCounter] ^= Long.reverseBytes(input.getLong());
            }
            keccakPermuteStates(state);
            input.position(input.position() + bitrate - ((bitrate >>> 3) << 3));
            inLen -= bitrate;
        }

        while ((inLen--) > 0) {
            tempByteBuffer.put(input.get());
        }

        tempByteBuffer.put(pending);
        tempByteBuffer.put(bitrate - 1, (byte) (tempByteBuffer.get(bitrate - 1) | 0x80));

        tempByteBuffer.rewind();
        input.rewind();

        for (int stateCounter = 0; stateCounter < bitrate / Long.BYTES; stateCounter++) {
            state[stateCounter] ^= Long.reverseBytes(tempByteBuffer.getLong());
        }

    }

    public void keccakSqueezeBlocks(ByteBuffer output, int outOffset, long blockNo, long[] state) {

        output.position(outOffset);

        while (blockNo > 0) {

            keccakPermuteStates(state);

            for (int stateIndex = 0; stateIndex < (this.bitrate >>> 3); stateIndex++) {
                output.putLong(Long.reverseBytes(state[stateIndex]));
            }

            output.position(output.position() + this.bitrate - ((this.bitrate >>> 3) << 3));
            blockNo--;

        }

    }

    public void shake(ByteBuffer output, int outOffset, long outLen, ByteBuffer input, int inOffset, long inLen) {

        long[] state = new long[25];
        ByteBuffer tempByteBuffer = ByteBuffer.allocate(this.bitrate);
        long blockNo = outLen / this.bitrate;
        output.position(outOffset);

        // Absorb input
        keccakAbsorb(state, this.bitrate, input, inOffset, inLen, (byte) 0x1F);

        // Squeeze output
        keccakSqueezeBlocks(output, outOffset, blockNo, state);
        outLen -= this.bitrate * blockNo;

        if (outLen > 0) {

            keccakSqueezeBlocks(tempByteBuffer, 0, 1L, state);

            tempByteBuffer.rewind();
            while (output.remaining() > 0) {
                output.put(tempByteBuffer.get());
            }

        }

    }

    public void cShakeSimpleAbsorb(long[] state, short customization, ByteBuffer input, int inOffset, long inLen) {

        ByteBuffer firstState = ByteBuffer.allocate(8);
        firstState.put((byte) 0x01);
        firstState.put(this.sep);
        firstState.put((byte) 0x01);
        firstState.put((byte) 0x00);
        firstState.put((byte) 0x01);
        firstState.put((byte) 0x10); // Fixed bit-length of customization
        firstState.put((byte) (customization & 0xFF));
        firstState.put((byte) (customization >>> 8));
        firstState.rewind();

        Arrays.fill(state, 0L);
        state[0] = Long.reverseBytes(firstState.getLong());
        keccakPermuteStates(state);
        keccakAbsorb(state, this.bitrate, input, inOffset, inLen, (byte) 0x04);

    }

    public void cShakeSimple(

            ByteBuffer output, int outOffset, long outLen, short customization,
            ByteBuffer input, int inOffset, long inLen

    ) {

        long[] state = new long[25];
        ByteBuffer tempByteBuffer = ByteBuffer.allocate(this.bitrate);
        long blockNo = outLen / this.bitrate;

        cShakeSimpleAbsorb(state, customization, input, inOffset, inLen);

        // Squeeze output
        keccakSqueezeBlocks(output, outOffset, blockNo, state);

        if (outLen - 1 > output.position()) {

            keccakSqueezeBlocks(tempByteBuffer, 0, 1L, state);

            tempByteBuffer.rewind();
            while (output.remaining() > 0) {
                output.put(tempByteBuffer.get());
            }

        }

    }

}