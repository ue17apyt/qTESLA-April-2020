package com.quantumCryptography.qTESLA.Pack;

import java.nio.ByteBuffer;
import java.nio.IntBuffer;

import static com.quantumCryptography.qTESLA.Parameter.B_BITS;
import static com.quantumCryptography.qTESLA.Parameter.C_BYTE;
import static com.quantumCryptography.qTESLA.Parameter.INT_BYTE;
import static com.quantumCryptography.qTESLA.Parameter.K;
import static com.quantumCryptography.qTESLA.Parameter.MASK_B;
import static com.quantumCryptography.qTESLA.Parameter.MASK_Q;
import static com.quantumCryptography.qTESLA.Parameter.N;
import static com.quantumCryptography.qTESLA.Parameter.PK_BYTE;
import static com.quantumCryptography.qTESLA.Parameter.Q_LOG;
import static com.quantumCryptography.qTESLA.Parameter.SEED_BYTE;
import static com.quantumCryptography.qTESLA.ParameterSet.P_III;
import static java.lang.Integer.reverseBytes;

public class PiiiPack extends Pack {

    public PiiiPack() {
        super(P_III);
    }

    @Override
    public ByteBuffer encodePK(int[] t, ByteBuffer seedA, int seedAOffset) {

        ByteBuffer pk = ByteBuffer.allocate(PK_BYTE);

        for (int pkIndex = 0, tIndex = 0; pkIndex < N * K * Q_LOG / 32; pkIndex += 15, tIndex += 16) {
            for (int rangeIndex = 0; rangeIndex < 15; rangeIndex++) {
                pk.putInt(
                        INT_BYTE * (pkIndex + rangeIndex),
                        reverseBytes(
                                (t[tIndex + rangeIndex] >> (rangeIndex * 2)) |
                                        (t[tIndex + rangeIndex + 1] << (30 - rangeIndex * 2))
                        )
                );
            }
        }

        pk.position(N * K * Q_LOG / 8);
        seedA.position(seedAOffset);

        for (int pkIndex = 0; pkIndex < SEED_BYTE; pkIndex++) {
            pk.put(seedA.get());
        }

        return pk;

    }

    @Override
    public void decodePK(IntBuffer pkOut, ByteBuffer seedA, ByteBuffer pkIn) {

        for (int outIndex = 0, inIndex = 0; outIndex < N * K; outIndex += 16, inIndex += 15) {

            pkOut.put(reverseBytes(pkIn.getInt(INT_BYTE * inIndex)) & MASK_Q);

            for (int index = 0; index < 14; index++) {
                int left = reverseBytes(pkIn.getInt(INT_BYTE * (inIndex + index))) >>> (30 - 2 * index);
                int right = reverseBytes(pkIn.getInt(INT_BYTE * (inIndex + index + 1))) << (2 + 2 * index);
                pkOut.put((left | right) & MASK_Q);
            }

            pkOut.put((reverseBytes(pkIn.getInt(INT_BYTE * (inIndex + 14))) >>> 2) & MASK_Q);

        }

        pkIn.position(N * K * Q_LOG / 8);

        for (int seedIndex = 0; seedIndex < SEED_BYTE; seedIndex++) {
            seedA.put(pkIn.get());
        }

    }

    @Override
    public void encodeSig(ByteBuffer sig, ByteBuffer c, int[] z) {

        for (int sigIndex = 0, zIndex = 0; sigIndex < N * (B_BITS + 1) / 32; sigIndex += 11, zIndex += 16) {
            sig.putInt(reverseBytes((z[zIndex] & 0x3FFFFF) | (z[zIndex + 1] << 22)));
            sig.putInt(reverseBytes(((z[zIndex + 1] >>> 10) & 0xFFF) | (z[zIndex + 2] << 12)));
            sig.putInt(
                    reverseBytes(
                            ((z[zIndex + 2] >>> 20) & 0x3) | ((z[zIndex + 3] & MASK_B) << 2) | (z[zIndex + 4] << 24)
                    )
            );
            sig.putInt(reverseBytes(((z[zIndex + 4] >>> 8) & 0x3FFF) | (z[zIndex + 5] << 14)));
            sig.putInt(
                    reverseBytes(
                            ((z[zIndex + 5] >>> 18) & 0xF) | ((z[zIndex + 6] & MASK_B) << 4) | (z[zIndex + 7] << 26)
                    )
            );
            sig.putInt(reverseBytes(((z[zIndex + 7] >>> 6) & 0xFFFF) | (z[zIndex + 8] << 16)));
            sig.putInt(
                    reverseBytes(
                            ((z[zIndex + 8] >>> 16) & 0x3F) | ((z[zIndex + 9] & MASK_B) << 6) | (z[zIndex + 10] << 28)
                    )
            );
            sig.putInt(reverseBytes(((z[zIndex + 10] >>> 4) & 0x3FFFF) | (z[zIndex + 11] << 18)));
            sig.putInt(
                    reverseBytes(
                            ((z[zIndex + 11] >>> 14) & 0xFF) | ((z[zIndex + 12] & MASK_B) << 8) | (z[zIndex + 13] << 30)
                    )
            );
            sig.putInt(reverseBytes(((z[zIndex + 13] >>> 2) & 0xFFFFF) | (z[zIndex + 14] << 20)));
            sig.putInt(reverseBytes(((z[zIndex + 14] >>> 12) & 0x3FF) | (z[zIndex + 15] << 10)));
        }

        for (int cIndex = 0; cIndex < C_BYTE; cIndex++) {
            sig.put(c.get());
        }

    }

    @Override
    public void decodeSig(ByteBuffer c, int[] z, ByteBuffer sig) {

        for (int zIndex = 0, sigIndex = 0; zIndex < N; zIndex += 16, sigIndex += 11) {
            z[zIndex] = (reverseBytes(sig.getInt(INT_BYTE * sigIndex)) << 10) >> 10;
            z[zIndex + 1] =
                    (reverseBytes(sig.getInt(INT_BYTE * sigIndex)) >>> 22) |
                            ((reverseBytes(sig.getInt(INT_BYTE * (sigIndex + 1))) << 20) >> 10);
            z[zIndex + 2] =
                    (reverseBytes(sig.getInt(INT_BYTE * (sigIndex + 1))) >>> 12) |
                            ((reverseBytes(sig.getInt(INT_BYTE * (sigIndex + 2))) << 30) >> 10);
            z[zIndex + 3] = (reverseBytes(sig.getInt(INT_BYTE * (sigIndex + 2))) << 8) >> 10;
            z[zIndex + 4] =
                    (reverseBytes(sig.getInt(INT_BYTE * (sigIndex + 2))) >>> 24) |
                            ((reverseBytes(sig.getInt(INT_BYTE * (sigIndex + 3))) << 18) >> 10);
            z[zIndex + 5] =
                    (reverseBytes(sig.getInt(INT_BYTE * (sigIndex + 3))) >>> 14) |
                            ((reverseBytes(sig.getInt(INT_BYTE * (sigIndex + 4))) << 28) >> 10);
            z[zIndex + 6] = (reverseBytes(sig.getInt(INT_BYTE * (sigIndex + 4))) << 6) >> 10;
            z[zIndex + 7] =
                    (reverseBytes(sig.getInt(INT_BYTE * (sigIndex + 4))) >>> 26) |
                            ((reverseBytes(sig.getInt(INT_BYTE * (sigIndex + 5))) << 16) >> 10);
            z[zIndex + 8] =
                    (reverseBytes(sig.getInt(INT_BYTE * (sigIndex + 5))) >>> 16) |
                            ((reverseBytes(sig.getInt(INT_BYTE * (sigIndex + 6))) << 26) >> 10);
            z[zIndex + 9] = (reverseBytes(sig.getInt(INT_BYTE * (sigIndex + 6))) << 4) >> 10;
            z[zIndex + 10] =
                    (reverseBytes(sig.getInt(INT_BYTE * (sigIndex + 6))) >>> 28) |
                            ((reverseBytes(sig.getInt(INT_BYTE * (sigIndex + 7))) << 14) >> 10);
            z[zIndex + 11] =
                    (reverseBytes(sig.getInt(INT_BYTE * (sigIndex + 7))) >>> 18) |
                            ((reverseBytes(sig.getInt(INT_BYTE * (sigIndex + 8))) << 24) >> 10);
            z[zIndex + 12] = (reverseBytes(sig.getInt(INT_BYTE * (sigIndex + 8))) << 2) >> 10;
            z[zIndex + 13] =
                    (reverseBytes(sig.getInt(INT_BYTE * (sigIndex + 8))) >>> 30) |
                            ((reverseBytes(sig.getInt(INT_BYTE * (sigIndex + 9))) << 12) >> 10);
            z[zIndex + 14] =
                    (reverseBytes(sig.getInt(INT_BYTE * (sigIndex + 9))) >>> 20) |
                            ((reverseBytes(sig.getInt(INT_BYTE * (sigIndex + 10))) << 22) >> 10);
            z[zIndex + 15] = reverseBytes(sig.getInt(INT_BYTE * (sigIndex + 10))) >> 10;
        }

        sig.position(N * (B_BITS + 1) / 8);

        for (int cIndex = 0; cIndex < C_BYTE; cIndex++) {
            c.put(sig.get());
        }

    }

}