package com.quantumCryptography.qTESLA;

import com.quantumCryptography.SHA3.FIPS202;

import java.nio.ByteBuffer;

import static com.quantumCryptography.qTESLA.Parameter.B;
import static com.quantumCryptography.qTESLA.Parameter.B_BITS;
import static com.quantumCryptography.qTESLA.Parameter.CDT;
import static com.quantumCryptography.qTESLA.Parameter.CDT_COL;
import static com.quantumCryptography.qTESLA.Parameter.CDT_ROW;
import static com.quantumCryptography.qTESLA.Parameter.CHUNK_INT;
import static com.quantumCryptography.qTESLA.Parameter.INT_BYTE;
import static com.quantumCryptography.qTESLA.Parameter.N;
import static com.quantumCryptography.qTESLA.Parameter.RADIX32;
import static com.quantumCryptography.qTESLA.Parameter.RANDOM_BYTE;
import static java.lang.Integer.reverseBytes;

public class Sample {

    private final FIPS202 fips202;

    public Sample(ParameterSet parameterSet, FIPS202 fips202) {
        Parameter parameter = new Parameter(parameterSet);
        this.fips202 = fips202;
    }

    /**
     * Samples polynomial y, such that each coefficient is in the range [-B,B]
     *
     * @param seed  32-byte seed
     * @param nonce Counter in integer
     * @return N-coefficient polynomial y
     */
    public int[] sampleY(ByteBuffer seed, int nonce) {

        int yIndex = 0;
        int blockNo = N;
        int byteNo = (B_BITS + 1 + 7) / 8;
        short domainSeparator = (short) (nonce << 8);
        ByteBuffer byteBuffer = ByteBuffer.allocate(N * byteNo + 1);
        int[] y = new int[N];

        this.fips202.cShakeSimple(
                byteBuffer, 0, N * byteNo, domainSeparator++, seed, 0, seed.limit()
        );
        byteBuffer.rewind();

        while (yIndex < N) {

            if (byteBuffer.position() >= byteNo * blockNo) {
                blockNo = this.fips202.getBitrate() / ((B_BITS + 1 + 7) / 8);
                byteBuffer.rewind();
                this.fips202.cShakeSimple(
                        byteBuffer, 0, this.fips202.getBitrate(), domainSeparator++, seed, 0, seed.limit()
                );
                byteBuffer.rewind();
            }

            y[yIndex] = reverseBytes(byteBuffer.getInt(byteBuffer.position())) & ((1 << (B_BITS + 1)) - 1);
            y[yIndex] -= B;

            if (y[yIndex] != (1 << B_BITS)) {
                yIndex++;
            }

            byteBuffer.position(byteBuffer.position() + byteNo);

        }

        return y;

    }

    /**
     * Samples polynomial z according to the Gaussian distribution with assistance of
     * cumulative distribution tables
     *
     * @param z          N-dimensional signature vector
     * @param zOffset    Offset of z
     * @param seed       (32 * K)-byte seed
     * @param seedOffset Seed offset
     * @param nonce      Counter in integer
     */
    public void sampleGaussPoly(int[] z, int zOffset, ByteBuffer seed, int seedOffset, int nonce) {

        int borrow;
        int sign;
        int domainSeparator = nonce << 8;
        int mask = 0x7FFFFFFF;
        int[] entry = new int[CDT_COL];
        ByteBuffer sampleBuffer = ByteBuffer.allocate(INT_BYTE * CHUNK_INT * CDT_COL);

        for (int zIndex = 0; zIndex < N; zIndex += CHUNK_INT) {

            this.fips202.cShakeSimple(
                    sampleBuffer, 0, sampleBuffer.limit(), (short) (domainSeparator++),
                    seed, seedOffset, RANDOM_BYTE
            );

            for (int chunkIndex = 0; chunkIndex < CHUNK_INT; chunkIndex++) {

                z[zOffset + zIndex + chunkIndex] = 0;

                for (int rowIndex = 1; rowIndex < CDT_ROW; rowIndex++) {

                    borrow = 0;

                    for (int colIndex = CDT_COL - 1; colIndex >= 0; colIndex--) {
                        entry[colIndex] = (reverseBytes(
                                sampleBuffer.getInt(INT_BYTE * (CDT_COL * chunkIndex + colIndex))) & mask) -
                                (CDT[CDT_COL * rowIndex + colIndex] + borrow);
                        borrow = entry[colIndex] >> (RADIX32 - 1);
                    }

                    z[zOffset + zIndex + chunkIndex] += ~borrow & 1;

                }

                sign = reverseBytes(sampleBuffer.getInt(INT_BYTE * chunkIndex * CDT_COL)) >> (RADIX32 - 1);
                z[zOffset + zIndex + chunkIndex] =
                        (sign & -z[zOffset + zIndex + chunkIndex]) | (~sign & z[zOffset + zIndex + chunkIndex]);

            }

        }

    }

}