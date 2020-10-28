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
import static com.quantumCryptography.qTESLA.ParameterSet.P_I;
import static java.lang.Integer.reverseBytes;

public class PiPack extends Pack {

    public PiPack() {
        super(P_I);
    }

    @Override
    public ByteBuffer encodePK(int[] t, ByteBuffer seedA, int seedAOffset) {

        ByteBuffer pk = ByteBuffer.allocate(PK_BYTE);

        for (int pkIndex = 0, tIndex = 0; pkIndex < N * K * Q_LOG / 32; pkIndex += Q_LOG, tIndex += 32) {

            pk.putInt(reverseBytes(t[tIndex] | (t[tIndex + 1] << 29)));
            pk.putInt(reverseBytes((t[tIndex + 1] >> 3) | (t[tIndex + 2] << 26)));
            pk.putInt(reverseBytes((t[tIndex + 2] >> 6) | (t[tIndex + 3] << 23)));
            pk.putInt(reverseBytes((t[tIndex + 3] >> 9) | (t[tIndex + 4] << 20)));
            pk.putInt(reverseBytes((t[tIndex + 4] >> 12) | (t[tIndex + 5] << 17)));
            pk.putInt(reverseBytes((t[tIndex + 5] >> 15) | (t[tIndex + 6] << 14)));
            pk.putInt(reverseBytes((t[tIndex + 6] >> 18) | (t[tIndex + 7] << 11)));
            pk.putInt(reverseBytes((t[tIndex + 7] >> 21) | (t[tIndex + 8] << 8)));
            pk.putInt(reverseBytes((t[tIndex + 8] >> 24) | (t[tIndex + 9] << 5)));
            pk.putInt(
                    reverseBytes((t[tIndex + 9] >> 27) | (t[tIndex + 10] << 2) | (t[tIndex + 11] << 31))
            );
            pk.putInt(reverseBytes((t[tIndex + 11] >> 1) | (t[tIndex + 12] << 28)));
            pk.putInt(reverseBytes((t[tIndex + 12] >> 4) | (t[tIndex + 13] << 25)));
            pk.putInt(reverseBytes((t[tIndex + 13] >> 7) | (t[tIndex + 14] << 22)));
            pk.putInt(reverseBytes((t[tIndex + 14] >> 10) | (t[tIndex + 15] << 19)));
            pk.putInt(reverseBytes((t[tIndex + 15] >> 13) | (t[tIndex + 16] << 16)));
            pk.putInt(reverseBytes((t[tIndex + 16] >> 16) | (t[tIndex + 17] << 13)));
            pk.putInt(reverseBytes((t[tIndex + 17] >> 19) | (t[tIndex + 18] << 10)));
            pk.putInt(reverseBytes((t[tIndex + 18] >> 22) | (t[tIndex + 19] << 7)));
            pk.putInt(reverseBytes((t[tIndex + 19] >> 25) | (t[tIndex + 20] << 4)));
            pk.putInt(
                    reverseBytes((t[tIndex + 20] >> 28) | (t[tIndex + 21] << 1) | (t[tIndex + 22] << 30))
            );
            pk.putInt(reverseBytes((t[tIndex + 22] >> 2) | (t[tIndex + 23] << 27)));
            pk.putInt(reverseBytes((t[tIndex + 23] >> 5) | (t[tIndex + 24] << 24)));
            pk.putInt(reverseBytes((t[tIndex + 24] >> 8) | (t[tIndex + 25] << 21)));
            pk.putInt(reverseBytes((t[tIndex + 25] >> 11) | (t[tIndex + 26] << 18)));
            pk.putInt(reverseBytes((t[tIndex + 26] >> 14) | (t[tIndex + 27] << 15)));
            pk.putInt(reverseBytes((t[tIndex + 27] >> 17) | (t[tIndex + 28] << 12)));
            pk.putInt(reverseBytes((t[tIndex + 28] >> 20) | (t[tIndex + 29] << 9)));
            pk.putInt(reverseBytes((t[tIndex + 29] >> 23) | (t[tIndex + 30] << 6)));
            pk.putInt(reverseBytes((t[tIndex + 30] >> 26) | (t[tIndex + 31] << 3)));

        }

        seedA.position(seedAOffset);

        for (int pkIndex = 0; pkIndex < SEED_BYTE; pkIndex++) {
            pk.put(seedA.get());
        }

        return pk;

    }

    @Override
    public void decodePK(IntBuffer pkOut, ByteBuffer seedA, ByteBuffer pkIn) {

        for (int outIndex = 0, inIndex = 0; outIndex < N * K; outIndex += 32, inIndex += 29) {
            pkOut.put(reverseBytes(pkIn.getInt(INT_BYTE * inIndex)) & MASK_Q);
            pkOut.put(
                    ((reverseBytes(pkIn.getInt(INT_BYTE * inIndex)) >>> 29) |
                            ((reverseBytes(pkIn.getInt(INT_BYTE * (inIndex + 1))) << 3))
                    ) & MASK_Q
            );
            pkOut.put(
                    ((reverseBytes(pkIn.getInt(INT_BYTE * (inIndex + 1))) >>> 26) |
                            ((reverseBytes(pkIn.getInt(INT_BYTE * (inIndex + 2))) << 6))
                    ) & MASK_Q
            );
            pkOut.put(
                    ((reverseBytes(pkIn.getInt(INT_BYTE * (inIndex + 2))) >>> 23) |
                            ((reverseBytes(pkIn.getInt(INT_BYTE * (inIndex + 3))) << 9))
                    ) & MASK_Q
            );
            pkOut.put(
                    ((reverseBytes(pkIn.getInt(INT_BYTE * (inIndex + 3))) >>> 20) |
                            ((reverseBytes(pkIn.getInt(INT_BYTE * (inIndex + 4))) << 12))
                    ) & MASK_Q
            );
            pkOut.put(
                    ((reverseBytes(pkIn.getInt(INT_BYTE * (inIndex + 4))) >>> 17) |
                            ((reverseBytes(pkIn.getInt(INT_BYTE * (inIndex + 5))) << 15))
                    ) & MASK_Q
            );
            pkOut.put(
                    ((reverseBytes(pkIn.getInt(INT_BYTE * (inIndex + 5))) >>> 14) |
                            ((reverseBytes(pkIn.getInt(INT_BYTE * (inIndex + 6))) << 18))
                    ) & MASK_Q
            );
            pkOut.put(
                    ((reverseBytes(pkIn.getInt(INT_BYTE * (inIndex + 6))) >>> 11) |
                            ((reverseBytes(pkIn.getInt(INT_BYTE * (inIndex + 7))) << 21))
                    ) & MASK_Q
            );
            pkOut.put(
                    ((reverseBytes(pkIn.getInt(INT_BYTE * (inIndex + 7))) >>> 8) |
                            ((reverseBytes(pkIn.getInt(INT_BYTE * (inIndex + 8))) << 24))
                    ) & MASK_Q
            );
            pkOut.put(
                    ((reverseBytes(pkIn.getInt(INT_BYTE * (inIndex + 8))) >>> 5) |
                            ((reverseBytes(pkIn.getInt(INT_BYTE * (inIndex + 9))) << 27))
                    ) & MASK_Q
            );
            pkOut.put((reverseBytes(pkIn.getInt(INT_BYTE * (inIndex + 9))) >>> 2) & MASK_Q);
            pkOut.put(
                    ((reverseBytes(pkIn.getInt(INT_BYTE * (inIndex + 9))) >>> 31) |
                            ((reverseBytes(pkIn.getInt(INT_BYTE * (inIndex + 10))) << 1))
                    ) & MASK_Q
            );
            pkOut.put(
                    ((reverseBytes(pkIn.getInt(INT_BYTE * (inIndex + 10))) >>> 28) |
                            ((reverseBytes(pkIn.getInt(INT_BYTE * (inIndex + 11))) << 4))
                    ) & MASK_Q
            );
            pkOut.put(
                    ((reverseBytes(pkIn.getInt(INT_BYTE * (inIndex + 11))) >>> 25) |
                            ((reverseBytes(pkIn.getInt(INT_BYTE * (inIndex + 12))) << 7))
                    ) & MASK_Q
            );
            pkOut.put(
                    ((reverseBytes(pkIn.getInt(INT_BYTE * (inIndex + 12))) >>> 22) |
                            ((reverseBytes(pkIn.getInt(INT_BYTE * (inIndex + 13))) << 10))
                    ) & MASK_Q
            );
            pkOut.put(
                    ((reverseBytes(pkIn.getInt(INT_BYTE * (inIndex + 13))) >>> 19) |
                            ((reverseBytes(pkIn.getInt(INT_BYTE * (inIndex + 14))) << 13))
                    ) & MASK_Q
            );
            pkOut.put(
                    ((reverseBytes(pkIn.getInt(INT_BYTE * (inIndex + 14))) >>> 16) |
                            ((reverseBytes(pkIn.getInt(INT_BYTE * (inIndex + 15))) << 16))
                    ) & MASK_Q
            );
            pkOut.put(
                    ((reverseBytes(pkIn.getInt(INT_BYTE * (inIndex + 15))) >>> 13) |
                            ((reverseBytes(pkIn.getInt(INT_BYTE * (inIndex + 16))) << 19))
                    ) & MASK_Q
            );
            pkOut.put(
                    ((reverseBytes(pkIn.getInt(INT_BYTE * (inIndex + 16))) >>> 10) |
                            ((reverseBytes(pkIn.getInt(INT_BYTE * (inIndex + 17))) << 22))
                    ) & MASK_Q
            );
            pkOut.put(
                    ((reverseBytes(pkIn.getInt(INT_BYTE * (inIndex + 17))) >>> 7) |
                            ((reverseBytes(pkIn.getInt(INT_BYTE * (inIndex + 18))) << 25))
                    ) & MASK_Q
            );
            pkOut.put(
                    ((reverseBytes(pkIn.getInt(INT_BYTE * (inIndex + 18))) >>> 4) |
                            ((reverseBytes(pkIn.getInt(INT_BYTE * (inIndex + 19))) << 28))
                    ) & MASK_Q
            );
            pkOut.put((reverseBytes(pkIn.getInt(INT_BYTE * (inIndex + 19))) >>> 1) & MASK_Q);
            pkOut.put(
                    ((reverseBytes(pkIn.getInt(INT_BYTE * (inIndex + 19))) >>> 30) |
                            ((reverseBytes(pkIn.getInt(INT_BYTE * (inIndex + 20))) << 2))
                    ) & MASK_Q
            );
            pkOut.put(
                    ((reverseBytes(pkIn.getInt(INT_BYTE * (inIndex + 20))) >>> 27) |
                            ((reverseBytes(pkIn.getInt(INT_BYTE * (inIndex + 21))) << 5))
                    ) & MASK_Q
            );
            pkOut.put(
                    ((reverseBytes(pkIn.getInt(INT_BYTE * (inIndex + 21))) >>> 24) |
                            ((reverseBytes(pkIn.getInt(INT_BYTE * (inIndex + 22))) << 8))
                    ) & MASK_Q
            );
            pkOut.put(
                    ((reverseBytes(pkIn.getInt(INT_BYTE * (inIndex + 22))) >>> 21) |
                            ((reverseBytes(pkIn.getInt(INT_BYTE * (inIndex + 23))) << 11))
                    ) & MASK_Q
            );
            pkOut.put(
                    ((reverseBytes(pkIn.getInt(INT_BYTE * (inIndex + 23))) >>> 18) |
                            ((reverseBytes(pkIn.getInt(INT_BYTE * (inIndex + 24))) << 14))
                    ) & MASK_Q
            );
            pkOut.put(
                    ((reverseBytes(pkIn.getInt(INT_BYTE * (inIndex + 24))) >>> 15) |
                            ((reverseBytes(pkIn.getInt(INT_BYTE * (inIndex + 25))) << 17))
                    ) & MASK_Q
            );
            pkOut.put(
                    ((reverseBytes(pkIn.getInt(INT_BYTE * (inIndex + 25))) >>> 12) |
                            ((reverseBytes(pkIn.getInt(INT_BYTE * (inIndex + 26))) << 20))
                    ) & MASK_Q
            );
            pkOut.put(
                    ((reverseBytes(pkIn.getInt(INT_BYTE * (inIndex + 26))) >>> 9) |
                            ((reverseBytes(pkIn.getInt(INT_BYTE * (inIndex + 27))) << 23))
                    ) & MASK_Q
            );
            pkOut.put(
                    ((reverseBytes(pkIn.getInt(INT_BYTE * (inIndex + 27))) >>> 6) |
                            ((reverseBytes(pkIn.getInt(INT_BYTE * (inIndex + 28))) << 26))
                    ) & MASK_Q
            );
            pkOut.put((reverseBytes(pkIn.getInt(INT_BYTE * (inIndex + 28))) >>> 3) & MASK_Q);
        }

        pkIn.position(N * K * Q_LOG / 8);

        for (int seedIndex = 0; seedIndex < SEED_BYTE; seedIndex++) {
            seedA.put(pkIn.get());
        }

    }

    @Override
    public void encodeSig(ByteBuffer sig, ByteBuffer c, int[] z) {

        for (int sigIndex = 0, zIndex = 0; sigIndex < N * (B_BITS + 1) / 32; sigIndex += 10, zIndex += 16) {
            sig.putInt(reverseBytes((z[zIndex] & 0xFFFFF) | (z[zIndex + 1] << 20)));
            sig.putInt(
                    reverseBytes(
                            ((z[zIndex + 1] >>> 12) & 0xFF) | ((z[zIndex + 2] & MASK_B) << 8) | (z[zIndex + 3] << 28)
                    )
            );
            sig.putInt(reverseBytes(((z[zIndex + 3] >>> 4) & 0xFFFF) | (z[zIndex + 4] << 16)));
            sig.putInt(
                    reverseBytes(
                            ((z[zIndex + 4] >>> 16) & 0xF) | ((z[zIndex + 5] & MASK_B) << 4) | (z[zIndex + 6] << 24)
                    )
            );
            sig.putInt(reverseBytes(((z[zIndex + 6] >>> 8) & 0xFFF) | (z[zIndex + 7] << 12)));
            sig.putInt(reverseBytes((z[zIndex + 8] & 0xFFFFF) | (z[zIndex + 9] << 20)));
            sig.putInt(
                    reverseBytes(
                            ((z[zIndex + 9] >>> 12) & 0xFF) | ((z[zIndex + 10] & MASK_B) << 8) | (z[zIndex + 11] << 28)
                    )
            );
            sig.putInt(reverseBytes(((z[zIndex + 11] >>> 4) & 0xFFFF) | (z[zIndex + 12] << 16)));
            sig.putInt(
                    reverseBytes(
                            ((z[zIndex + 12] >>> 16) & 0xF) | ((z[zIndex + 13] & MASK_B) << 4) | (z[zIndex + 14] << 24)
                    )
            );
            sig.putInt(reverseBytes(((z[zIndex + 14] >>> 8) & 0xFFF) | (z[zIndex + 15] << 12)));
        }

        for (int cIndex = 0; cIndex < C_BYTE; cIndex++) {
            sig.put(c.get());
        }

    }

    @Override
    public void decodeSig(ByteBuffer c, int[] z, ByteBuffer sig) {

        for (int zIndex = 0, sigIndex = 0; zIndex < N; zIndex += 16, sigIndex += 10) {
            z[zIndex] = (reverseBytes(sig.getInt(INT_BYTE * sigIndex)) << 12) >> 12;
            z[zIndex + 1] =
                    (reverseBytes(sig.getInt(INT_BYTE * sigIndex)) >>> 20) |
                            ((reverseBytes(sig.getInt(INT_BYTE * (sigIndex + 1))) << 24) >> 12);
            z[zIndex + 2] = (reverseBytes(sig.getInt(INT_BYTE * (sigIndex + 1))) << 4) >> 12;
            z[zIndex + 3] =
                    (reverseBytes(sig.getInt(INT_BYTE * (sigIndex + 1))) >>> 28) |
                            ((reverseBytes(sig.getInt(INT_BYTE * (sigIndex + 2))) << 16) >> 12);
            z[zIndex + 4] =
                    (reverseBytes(sig.getInt(INT_BYTE * (sigIndex + 2))) >>> 16) |
                            ((reverseBytes(sig.getInt(INT_BYTE * (sigIndex + 3))) << 28) >> 12);
            z[zIndex + 5] = (reverseBytes(sig.getInt(INT_BYTE * (sigIndex + 3))) << 8) >> 12;
            z[zIndex + 6] =
                    (reverseBytes(sig.getInt(INT_BYTE * (sigIndex + 3))) >>> 24) |
                            ((reverseBytes(sig.getInt(INT_BYTE * (sigIndex + 4))) << 20) >> 12);
            z[zIndex + 7] = reverseBytes(sig.getInt(INT_BYTE * (sigIndex + 4))) >> 12;
            z[zIndex + 8] = (reverseBytes(sig.getInt(INT_BYTE * (sigIndex + 5))) << 12) >> 12;
            z[zIndex + 9] =
                    (reverseBytes(sig.getInt(INT_BYTE * (sigIndex + 5))) >>> 20) |
                            ((reverseBytes(sig.getInt(INT_BYTE * (sigIndex + 6))) << 24) >> 12);
            z[zIndex + 10] = (reverseBytes(sig.getInt(INT_BYTE * (sigIndex + 6))) << 4) >> 12;
            z[zIndex + 11] =
                    (reverseBytes(sig.getInt(INT_BYTE * (sigIndex + 6))) >>> 28) |
                            ((reverseBytes(sig.getInt(INT_BYTE * (sigIndex + 7))) << 16) >> 12);
            z[zIndex + 12] =
                    (reverseBytes(sig.getInt(INT_BYTE * (sigIndex + 7))) >>> 16) |
                            ((reverseBytes(sig.getInt(INT_BYTE * (sigIndex + 8))) << 28) >> 12);
            z[zIndex + 13] = (reverseBytes(sig.getInt(INT_BYTE * (sigIndex + 8))) << 8) >> 12;
            z[zIndex + 14] =
                    (reverseBytes(sig.getInt(INT_BYTE * (sigIndex + 8))) >>> 24) |
                            ((reverseBytes(sig.getInt(INT_BYTE * (sigIndex + 9))) << 20) >> 12);
            z[zIndex + 15] = reverseBytes(sig.getInt(INT_BYTE * (sigIndex + 9))) >> 12;
        }

        sig.position(N * (B_BITS + 1) / 8);

        for (int cIndex = 0; cIndex < C_BYTE; cIndex++) {
            c.put(sig.get());
        }

    }

}