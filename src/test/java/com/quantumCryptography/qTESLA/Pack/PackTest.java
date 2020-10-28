package com.quantumCryptography.qTESLA.Pack;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.ByteBuffer;

import static com.quantumCryptography.qTESLA.Parameter.HASHED_MSG_BYTE;
import static com.quantumCryptography.qTESLA.Parameter.K;
import static com.quantumCryptography.qTESLA.Parameter.N;
import static com.quantumCryptography.qTESLA.Parameter.SEED_BYTE;
import static com.quantumCryptography.qTESLA.Parameter.SK_BYTE;
import static com.quantumCryptography.utility.Utility.getByteArrayFromResFile;
import static com.quantumCryptography.utility.Utility.getIntArrayFromResFile;
import static java.lang.System.arraycopy;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;

public class PackTest {

    Pack pack = new PiPack();

    @Test
    public void encodeSecretKeyTest() throws IOException {

        int[] s = getIntArrayFromResFile("qTESLA/Pack/s.txt", N);
        int[] e = getIntArrayFromResFile("qTESLA/Pack/e.txt", N * K);
        byte[] expSK = getByteArrayFromResFile("qTESLA/Pack/skEnc.txt", SK_BYTE);
        byte[] partSeed = getByteArrayFromResFile("qTESLA/Pack/seed.txt", SEED_BYTE * 2);
        ByteBuffer seed = ByteBuffer.allocate(SEED_BYTE * 4);
        byte[] hashedPK = getByteArrayFromResFile("qTESLA/Pack/hashedPK.txt", HASHED_MSG_BYTE);

        arraycopy(partSeed, 0, seed.array(), SEED_BYTE, SEED_BYTE * 2);
        ByteBuffer sk = this.pack.encodeSK(s, e, seed, SEED_BYTE, ByteBuffer.wrap(hashedPK));

        assertArrayEquals(expSK, sk.array());

    }

}