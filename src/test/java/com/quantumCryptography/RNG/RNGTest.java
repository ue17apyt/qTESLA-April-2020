package com.quantumCryptography.RNG;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import static com.quantumCryptography.qTESLA.Parameter.RANDOM_BYTE;
import static com.quantumCryptography.utility.Utility.getByteArrayFromResFile;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class RNGTest {

    public static final int KEY_BYTE = 32;
    public static final int VAL_BYTE = 16;

    private final RNG rng = new RNG();
    private byte[] key;
    private byte[] val;
    private byte[] providedData;

    @BeforeEach
    public void initialize() throws IOException {
        this.key = getByteArrayFromResFile("FIPS202/seed.txt", KEY_BYTE);
        this.val = getByteArrayFromResFile("RNG/val.txt", VAL_BYTE);
        this.providedData = getByteArrayFromResFile("RNG/providedData.txt", KEY_BYTE + VAL_BYTE);
    }

    @Test
    public void aes256CtrDRBGUpdate() throws
            InvalidKeyException, IOException, NoSuchPaddingException, NoSuchAlgorithmException, ShortBufferException {

        byte[] expKey = getByteArrayFromResFile("RNG/expKey.txt", KEY_BYTE);
        byte[] expVal = getByteArrayFromResFile("RNG/expVal.txt", VAL_BYTE);

        this.rng.aes256CtrDRBGUpdate(this.providedData, this.key, this.val);

        assertArrayEquals(expKey, this.key);
        assertArrayEquals(expVal, this.val);

    }

    @Test
    public void generateRandomBytesTest() throws
            InvalidKeyException, IOException, NoSuchPaddingException, NoSuchAlgorithmException, ShortBufferException {

        ByteBuffer randomness = ByteBuffer.allocate(RANDOM_BYTE * 3);
        byte[] expRandomness = getByteArrayFromResFile("RNG/expRandomness.txt", RANDOM_BYTE);

        this.rng.generateRandomness(randomness, RANDOM_BYTE, RANDOM_BYTE);

        for (int randomIndex = 0; randomIndex < RANDOM_BYTE; randomIndex++) {
            assertEquals(expRandomness[randomIndex], randomness.get(RANDOM_BYTE + randomIndex));
        }

    }

}