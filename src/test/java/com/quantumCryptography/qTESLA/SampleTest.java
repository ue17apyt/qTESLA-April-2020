package com.quantumCryptography.qTESLA;

import com.quantumCryptography.SHA3.SHAKE128;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.ByteBuffer;

import static com.quantumCryptography.qTESLA.Parameter.N;
import static com.quantumCryptography.qTESLA.Parameter.SEED_BYTE;
import static com.quantumCryptography.qTESLA.ParameterSet.P_I;
import static com.quantumCryptography.utility.Utility.getByteArrayFromResFile;
import static com.quantumCryptography.utility.Utility.getIntArrayFromResFile;
import static java.lang.System.arraycopy;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class SampleTest {

    private static final int NONCE_Y = 0x6789ABCD;
    private static final int NONCE_GAUSS = 0xABCD;
    private final Sample sample = new Sample(P_I, new SHAKE128());

    @Test
    public void sampleYTest() throws IOException {
        byte[] seed = getByteArrayFromResFile("FIPS202/seed.txt", SEED_BYTE);
        int[] y = this.sample.sampleY(ByteBuffer.wrap(seed), NONCE_Y);
        int[] expY = getIntArrayFromResFile("qTESLA/Sample/y.txt", N);
        assertArrayEquals(expY, y);
    }

    @Test
    public void sampleGaussPolynomialTest() throws IOException {

        int[] z = new int[N * 3];
        byte[] partSeed = getByteArrayFromResFile("FIPS202/seed.txt", SEED_BYTE);
        ByteBuffer seed = ByteBuffer.allocate(SEED_BYTE * 3);
        int[] expZ = getIntArrayFromResFile("qTESLA/Sample/z.txt", N);

        arraycopy(partSeed, 0, seed.array(), SEED_BYTE, SEED_BYTE);
        this.sample.sampleGaussPoly(z, N, seed, SEED_BYTE, NONCE_GAUSS);

        for (int zIndex = 0; zIndex < N; zIndex++) {
            assertEquals(expZ[zIndex], z[N + zIndex]);
        }

    }

}