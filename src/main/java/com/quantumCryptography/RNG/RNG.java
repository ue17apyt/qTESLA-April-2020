package com.quantumCryptography.RNG;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import static java.lang.System.arraycopy;
import static javax.crypto.Cipher.ENCRYPT_MODE;

public class RNG {

    private final byte[] key;
    private final byte[] value;
    private int reseedCounter;

    public RNG() {
        this.key = new byte[32];
        this.value = new byte[16];
        this.reseedCounter = 0;
    }

    /**
     * Encrypt a plaintext into a ciphertext with reference to Advanced Encryption Standard (AES)
     * with 256-bit key length and Password-Based Encryption Standard (Public Key Cryptography
     * Standard #5)
     *
     * @param key              256-bit (32-byte) AES key
     * @param plaintext        128-bit (16-byte) plaintext
     * @param ciphertext       128-bit (16-byte) ciphertext
     * @param ciphertextOffset offset of ciphertext
     * @throws InvalidKeyException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     * @throws ShortBufferException
     */
    private void aes256ECB(byte[] key, byte[] plaintext, byte[] ciphertext, int ciphertextOffset)
            throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, ShortBufferException {

        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(ENCRYPT_MODE, new SecretKeySpec(key, "AES"));
        cipher.update(plaintext, 0, 16, ciphertext, ciphertextOffset);

    }

    public void aes256CtrDRBGUpdate(byte[] providedData, byte[] key, byte[] val)
            throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, ShortBufferException {

        byte[] temp = new byte[48];

        for (int blockIndex = 0; blockIndex < 48 / 16; blockIndex++) {

            for (int valIndex = 16 - 1; valIndex >= 0; valIndex--) {
                if (val[valIndex] == (byte) 0xFF) {
                    val[valIndex] = (byte) 0x00;
                } else {
                    val[valIndex]++;
                    break;
                }
            }

            aes256ECB(key, val, temp, blockIndex * 16);

        }

        if (null != providedData) {
            for (int tempIndex = 0; tempIndex < 48; tempIndex++) {
                temp[tempIndex] ^= providedData[tempIndex];
            }
        }

        arraycopy(temp, 0, key, 0, 32);
        arraycopy(temp, 32, val, 0, 16);

    }

    public void generateRandomness(ByteBuffer randomness, int randomOffset, int len)
            throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, ShortBufferException {

        int randomIndex = 0;
        byte[] block = new byte[16];

        while (len > 0) {

            for (int valIndex = 16 - 1; valIndex >= 0; valIndex--) {
                if (this.value[valIndex] == (byte) 0xFF) {
                    this.value[valIndex] = (byte) 0x00;
                } else {
                    this.value[valIndex]++;
                    break;
                }
            }

            aes256ECB(this.key, this.value, block, 0);

            if (len > 16 - 1) {
                arraycopy(block, 0, randomness.array(), randomOffset + randomIndex, 16);
                randomIndex += 16;
                len -= 16;
            } else {
                arraycopy(block, 0, randomness.array(), randomOffset + randomIndex, len);
                len = 0;
            }

        }

        aes256CtrDRBGUpdate(null, this.key, this.value);
        this.reseedCounter++;

    }

}