package com.quantumCryptography.qTESLA.Pack;

import com.quantumCryptography.qTESLA.Parameter;
import com.quantumCryptography.qTESLA.ParameterSet;

import java.nio.ByteBuffer;
import java.nio.IntBuffer;

import static com.quantumCryptography.qTESLA.Parameter.HASHED_MSG_BYTE;
import static com.quantumCryptography.qTESLA.Parameter.K;
import static com.quantumCryptography.qTESLA.Parameter.N;
import static com.quantumCryptography.qTESLA.Parameter.SEED_BYTE;
import static com.quantumCryptography.qTESLA.Parameter.SK_BYTE;

public abstract class Pack {

    public Pack(ParameterSet parameterSet) {
        Parameter parameter = new Parameter(parameterSet);
    }

    /**
     * Encodes a secret key
     *
     * @param s          N-coefficient secret polynomial
     * @param e          K N-coefficient error polynomials
     * @param seed       32-byte seed
     * @param seedOffset Seed offset
     * @param hashedPK   Digested public key
     * @return Encoded secret key
     */
    public ByteBuffer encodeSK(int[] s, int[] e, ByteBuffer seed, int seedOffset, ByteBuffer hashedPK) {

        ByteBuffer sk = ByteBuffer.allocate(SK_BYTE);

        for (int skIndex = 0; skIndex < N; skIndex++) {
            sk.put((byte) s[skIndex]);
        }

        for (int polyIndex = 0; polyIndex < K; polyIndex++) {
            for (int dimIndex = 0; dimIndex < N; dimIndex++) {
                sk.put((byte) e[polyIndex * N + dimIndex]);
            }
        }

        seed.position(seedOffset);

        for (int skIndex = 0; skIndex < 2 * SEED_BYTE; skIndex++) {
            sk.put(seed.get());
        }

        for (int skIndex = 0; skIndex < HASHED_MSG_BYTE; skIndex++) {
            sk.put(hashedPK.get());
        }

        return sk;

    }

    /**
     * Encodes a public key
     *
     * @param t           K N-coefficient polynomials
     * @param seedA       A byte buffer including 32-byte seed to generate K N-coefficient public polynomial a_1, ..., a_k
     * @param seedAOffset Seed offset
     * @return Encoded public key
     */
    public abstract ByteBuffer encodePK(int[] t, ByteBuffer seedA, int seedAOffset);

    /**
     * Decodes a public key
     *
     * @param pkOut Decoded public key output in (N * K)-integer
     * @param seedA A 32-byte seed to generate K N-coefficient public polynomial a_1, ..., a_k
     * @param pkIn  Public key input
     */
    public abstract void decodePK(IntBuffer pkOut, ByteBuffer seedA, ByteBuffer pkIn);

    /**
     * Encodes a signature
     *
     * @param sig Encoded signature as output
     * @param c   32-byte input as a part of signature
     * @param z   N-dimensional signature vector
     */
    public abstract void encodeSig(ByteBuffer sig, ByteBuffer c, int[] z);

    /**
     * Decodes a signature
     *
     * @param c   32-byte output as a part of signature
     * @param z   N-dimensional signature vector
     * @param sig Signature input
     */
    public abstract void decodeSig(ByteBuffer c, int[] z, ByteBuffer sig);

}