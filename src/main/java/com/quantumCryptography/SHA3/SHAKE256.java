package com.quantumCryptography.SHA3;

import java.nio.ByteBuffer;

public class SHAKE256 extends FIPS202 {

    public static final int BITRATE = 136;
    public static final byte SEP = (byte) 0x88;

    public SHAKE256() {
        super(BITRATE, SEP);
    }

    public void shake(ByteBuffer output, int outOffset, long outLen, ByteBuffer input, int inOffset, long inLen) {
        super.shake(output, outOffset, outLen, input, inOffset, inLen);
    }

    public void shakeAbsorb(long[] state, ByteBuffer input, int inStart, long inLen) {
        super.keccakAbsorb(state, BITRATE, input, inStart, inLen, (byte) 0x1F);
    }

    public void shakeSqueezeBlocks(ByteBuffer output, int outStart, long blockNo, long[] state) {
        super.keccakSqueezeBlocks(output, outStart, blockNo, state);
    }

    public void cShakeSimpleAbsorb(long[] state, short customization, ByteBuffer input, int inOffset, long inLen) {
        super.cShakeSimpleAbsorb(state, customization, input, inOffset, inLen);
    }

    public void cShakeSimpleSqueezeBlocks(ByteBuffer output, int outStart, long blockNo, long[] state) {
        super.keccakSqueezeBlocks(output, outStart, blockNo, state);
    }

    public void cShakeSimple(
            ByteBuffer output, int outOffset, long outLen, short customization,
            ByteBuffer input, int inOffset, long inLen) {
        super.cShakeSimple(output, outOffset, outLen, customization, input, inOffset, inLen);
    }

}