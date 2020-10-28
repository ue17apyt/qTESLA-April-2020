package com.quantumCryptography.qTESLA.Pack;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.IntBuffer;

import static com.quantumCryptography.SHA3.FIPS202Test.MSG_BYTE;
import static com.quantumCryptography.qTESLA.Parameter.C_BYTE;
import static com.quantumCryptography.qTESLA.Parameter.K;
import static com.quantumCryptography.qTESLA.Parameter.N;
import static com.quantumCryptography.qTESLA.Parameter.PK_BYTE;
import static com.quantumCryptography.qTESLA.Parameter.SEED_BYTE;
import static com.quantumCryptography.qTESLA.Parameter.SIG_BYTE;
import static com.quantumCryptography.utility.Utility.getByteArrayFromResFile;
import static com.quantumCryptography.utility.Utility.getIntArrayFromResFile;
import static java.lang.System.arraycopy;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class PiPackTest {

    private final Pack pack = new PiPack();

    @Test
    public void encodePublicKeyTest() throws IOException {

        byte[] partSeedA = getByteArrayFromResFile("FIPS202/seed.txt", SEED_BYTE);
        ByteBuffer seedA = ByteBuffer.allocate(SEED_BYTE * 3);
        int[] t = getIntArrayFromResFile("qTESLA/Pack/PiPack/t1.txt", N * K);
        byte[] expPK = getByteArrayFromResFile("qTESLA/Pack/PiPack/pkEnc1.txt", PK_BYTE);

        arraycopy(partSeedA, 0, seedA.array(), SEED_BYTE, SEED_BYTE);
        ByteBuffer pk = this.pack.encodePK(t, seedA, SEED_BYTE);

        assertArrayEquals(expPK, pk.array());

    }

    @Test
    public void decodePublicKeyTest() throws IOException {

        IntBuffer pkOut = IntBuffer.allocate(N * K);
        ByteBuffer seedA = ByteBuffer.allocate(SEED_BYTE);
        ByteBuffer pkIn = ByteBuffer.wrap(
                getByteArrayFromResFile("qTESLA/Pack/PiPack/pkIn1.txt", PK_BYTE)
        );
        int[] expPKOut = getIntArrayFromResFile("qTESLA/Pack/PiPack/pkDec1.txt", N * K);
        byte[] expSeedA = getByteArrayFromResFile("qTESLA/Pack/PiPack/seedA1.txt", SEED_BYTE);

        this.pack.decodePK(pkOut, seedA, pkIn);

        assertArrayEquals(expPKOut, pkOut.array());
        assertArrayEquals(expSeedA, seedA.array());

    }

    @Test
    public void encodeSignatureTest() throws IOException {

        ByteBuffer sig = ByteBuffer.allocate(SIG_BYTE + MSG_BYTE);
        byte[] cEncode = getByteArrayFromResFile("FIPS202/seed.txt", SEED_BYTE);
        int[] zEncode = getIntArrayFromResFile("qTESLA/Pack/PiPack/zEnc1.txt", N);
        byte[] expSig = getByteArrayFromResFile("qTESLA/Pack/PiPack/sigEnc1.txt", SIG_BYTE);

        this.pack.encodeSig(sig, ByteBuffer.wrap(cEncode), zEncode);

        for (int sigIndex = 0; sigIndex < SEED_BYTE; sigIndex++) {
            assertEquals(expSig[sigIndex], sig.get(sigIndex));
        }

    }

    @Test
    public void decodeSignatureTest() throws IOException {

        ByteBuffer cOut = ByteBuffer.allocate(C_BYTE);
        int[] zOut = new int[N];
        byte[] sigEncode = getByteArrayFromResFile("qTESLA/Pack/PiPack/sigEnc1.txt", SIG_BYTE);
        byte[] expC = getByteArrayFromResFile("FIPS202/seed.txt", SEED_BYTE);
        int[] expZ = getIntArrayFromResFile("qTESLA/Pack/PiPack/zDec1.txt", N);

        this.pack.decodeSig(cOut, zOut, ByteBuffer.wrap(sigEncode));

        assertArrayEquals(expC, cOut.array());
        assertArrayEquals(expZ, zOut);

    }

}