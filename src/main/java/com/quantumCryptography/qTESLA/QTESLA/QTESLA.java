package com.quantumCryptography.qTESLA.QTESLA;

import com.quantumCryptography.RNG.RNG;
import com.quantumCryptography.SHA3.FIPS202;
import com.quantumCryptography.qTESLA.Pack.Pack;
import com.quantumCryptography.qTESLA.Parameter;
import com.quantumCryptography.qTESLA.ParameterSet;
import com.quantumCryptography.qTESLA.Poly.Poly;
import com.quantumCryptography.qTESLA.Sample;

import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import java.nio.ByteBuffer;
import java.nio.IntBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import static com.quantumCryptography.qTESLA.Parameter.B;
import static com.quantumCryptography.qTESLA.Parameter.C_BYTE;
import static com.quantumCryptography.qTESLA.Parameter.D;
import static com.quantumCryptography.qTESLA.Parameter.H;
import static com.quantumCryptography.qTESLA.Parameter.HASHED_MSG_BYTE;
import static com.quantumCryptography.qTESLA.Parameter.K;
import static com.quantumCryptography.qTESLA.Parameter.N;
import static com.quantumCryptography.qTESLA.Parameter.PK_BYTE;
import static com.quantumCryptography.qTESLA.Parameter.Q;
import static com.quantumCryptography.qTESLA.Parameter.RADIX32;
import static com.quantumCryptography.qTESLA.Parameter.RANDOM_BYTE;
import static com.quantumCryptography.qTESLA.Parameter.REJECTION;
import static com.quantumCryptography.qTESLA.Parameter.SEED_BYTE;
import static com.quantumCryptography.qTESLA.Parameter.SIG_BYTE;
import static com.quantumCryptography.qTESLA.Parameter.SK_BYTE;
import static java.lang.Math.abs;
import static java.lang.System.arraycopy;

public abstract class QTESLA {

    private final FIPS202 fips202;
    private final RNG rng;
    private final Sample sample;
    private Pack pack;
    private Poly poly;
    private ByteBuffer pk;
    private ByteBuffer sk;

    public QTESLA(ParameterSet parameterSet, FIPS202 fips202) {
        Parameter parameter = new Parameter(parameterSet);
        this.fips202 = fips202;
        this.rng = new RNG();
        this.sample = new Sample(parameterSet, fips202);
        this.pk = ByteBuffer.allocate(PK_BYTE);
        this.sk = ByteBuffer.allocate(SK_BYTE);
    }

    public ByteBuffer getPK() {
        return this.pk;
    }

    public ByteBuffer getSK() {
        return this.sk;
    }

    public void setPack(Pack pack) {
        this.pack = pack;
    }

    public void setPoly(Poly poly) {
        this.poly = poly;
    }

    /**
     * Checks bounds for signature vector z during signing <br>
     * Leaks no information about the coefficient that fails the test <br>
     *
     * @param z N-dimensional signature vector
     * @return 0: valid (accepted) <br> 1: invalid (rejected)
     */
    public int testRejection(int[] z) {

        int valid = 0;

        for (int zIndex = 0; zIndex < N; zIndex++) {
            valid |= (B - REJECTION) - abs(z[zIndex]);
        }

        return valid >>> 31;

    }

    /**
     * Check bounds for signature vector z during signature verification
     *
     * @param z N-dimensional signature vector
     * @return false: valid (accepted) <br> true: invalid (rejected)
     */
    public boolean testZ(int[] z) {

        for (int zIndex = 0; zIndex < N; zIndex++) {
            if (abs(z[zIndex]) > B - REJECTION) {
                return true;
            }
        }

        return false;

    }

    /**
     * Checks bounds for w = v - ec during signature verification <br><br>
     * - Leaks the position of the coefficient that fails the test <br>
     * - Independent of the secret data <br>
     * - Leaks no sign of the coefficients <br>
     *
     * @param v       N-coefficient polynomial
     * @param vOffset Polynomial offset
     * @return false: valid (accepted) <br> true: invalid (rejected)
     */
    public boolean testCorrectness(int[] v, int vOffset) {

        int test0;
        int test1;
        int mask;
        int value0;
        int value1;

        for (int vIndex = 0; vIndex < N; vIndex++) {

            mask = (int) (Q / 2 - v[vOffset + vIndex]) >> (RADIX32 - 1);
            value0 = (int) (((v[vOffset + vIndex] - Q) & mask) | (v[vOffset + vIndex] & ~mask));
            test0 = (int) (~(abs(value0) - (Q / 2 - REJECTION))) >>> (RADIX32 - 1);
            value1 = value0;
            value0 = (value0 + (1 << (D - 1)) - 1) >> D;
            value0 = value1 - (value0 << D);
            test1 = ~(abs(value0) - ((1 << (D - 1)) - REJECTION)) >>> (RADIX32 - 1);

            if ((test0 | test1) == 1) {
                return true;
            }

        }

        return false;

    }

    /**
     * Checks the validity of the generated error or secret polynomial e or s
     *
     * @param poly       Error or secret polynomial to check
     * @param polyOffset Polynomial offset
     * @param bound      Threshold
     * @return false: valid (accepted) <br> true: invalid (rejected)
     */
    public boolean checkBound(int[] poly, int polyOffset, int bound) {

        int limit = N;
        int mask;
        int temp;
        int sum = 0;
        int[] list = new int[N];

        for (int listIndex = 0; listIndex < N; listIndex++) {
            list[listIndex] = abs(poly[polyOffset + listIndex]);
        }

        for (int hIndex = 0; hIndex < H; hIndex++) {

            for (int listIndex = 0; listIndex < limit - 1; listIndex++) {
                mask = (list[listIndex + 1] - list[listIndex]) >> (RADIX32 - 1);
                temp = (list[listIndex + 1] & mask) | (list[listIndex] & ~mask);
                list[listIndex + 1] = (list[listIndex] & mask) | (list[listIndex + 1] & ~mask);
                list[listIndex] = temp;
            }

            sum += list[limit-- - 1];

        }

        Long unsignedSum = (long) sum & 0xFFFFFFFFL;

        return unsignedSum.compareTo((long) bound) > 0;

    }

    /**
     * Generates c in a hash-based function
     *
     * @param v               N-coefficient polynomial
     * @param hashedMsg       Hashed message
     * @param hashedMsgOffset Hashed message offset
     * @return c
     */
    public ByteBuffer generateC(int[] v, ByteBuffer hashedMsg, int hashedMsgOffset) {

        int cL;
        int index;
        int mask;
        int temp;
        ByteBuffer c = ByteBuffer.allocate(C_BYTE);
        ByteBuffer digest = ByteBuffer.allocate(N * K + HASHED_MSG_BYTE * 2);

        for (int polyIndex = 0; polyIndex < K; polyIndex++) {

            index = N * polyIndex;

            for (int vIndex = 0; vIndex < N; vIndex++) {
                temp = v[index];
                mask = (int) ((Q / 2 - temp) >> (RADIX32 - 1));
                temp = (int) (((temp - Q) & mask) | (temp & ~mask));
                cL = temp & ((1 << D) - 1);
                mask = ((1 << (D - 1)) - cL) >> (RADIX32 - 1);
                cL = ((cL - (1 << D)) & mask) | (cL & ~mask);
                digest.put(index++, (byte) ((temp - cL) >> D));
            }

        }

        digest.position(N * K);

        for (int digestIndex = 0; digestIndex < HASHED_MSG_BYTE * 2; digestIndex++) {
            digest.put(hashedMsg.get(hashedMsgOffset + digestIndex));
        }

        digest.rewind();

        this.fips202.shake(c, 0, c.limit(), digest, 0, digest.limit());

        return c;

    }

    /**
     * Generates a public and private key pair
     *
     * @throws InvalidKeyException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     * @throws ShortBufferException
     */
    public void generateKeyPair()
            throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, ShortBufferException {

        ByteBuffer randomness = ByteBuffer.allocate(RANDOM_BYTE);
        ByteBuffer extRandomness = ByteBuffer.allocate(SEED_BYTE * (K + 3));
        ByteBuffer hashedPK = ByteBuffer.allocate(HASHED_MSG_BYTE);
        int[] s = new int[N];
        int[] e = new int[K * N];
        int[] t = new int[K * N];
        int nonce = 0; // Initializes domain separator for error and secret polynomials

        // Computes extended_randomness <- seed_e, seed_s, seed_a, seed_y
        this.rng.generateRandomness(randomness, 0, RANDOM_BYTE);
        this.fips202.shake(
                extRandomness, 0, SEED_BYTE * (K + 3), randomness, 0, RANDOM_BYTE
        );

        // Samples the error polynomials
        for (int polyIndex = 0; polyIndex < K; polyIndex++) {
            do {
                this.sample.sampleGaussPoly(
                        e, N * polyIndex, extRandomness, SEED_BYTE * polyIndex, ++nonce
                );
            } while (checkBound(e, N * polyIndex, REJECTION) == true);
        }

        // Samples the secret polynomial
        do {
            this.sample.sampleGaussPoly(
                    s, 0, extRandomness, SEED_BYTE * K, ++nonce
            );
        } while (checkBound(s, 0, REJECTION) == true);

        // Generates uniform polynomials
        int[] a = this.poly.uniformPoly(extRandomness, SEED_BYTE * (K + 1));
        int[] sNTT = this.poly.polyFwdNTT(s);

        for (int polyIndex = 0; polyIndex < K; polyIndex++) {
            this.poly.multiply(t, N * polyIndex, a, N * polyIndex, sNTT, 0);
            this.poly.addWithCX(t, N * polyIndex, t, N * polyIndex, e, N * polyIndex);
        }

        // Computes the public key t = a * s + e
        this.pk = this.pack.encodePK(t, extRandomness, SEED_BYTE * (K + 1));
        this.fips202.shake(hashedPK, 0, HASHED_MSG_BYTE, this.pk, 0, PK_BYTE - SEED_BYTE);
        hashedPK.rewind();
        this.sk = this.pack.encodeSK(s, e, extRandomness, SEED_BYTE * (K + 1), hashedPK);

    }

    /**
     * Calculates a signature for a given message
     *
     * @param msg Given message
     * @return Signature
     * @throws InvalidKeyException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     * @throws ShortBufferException
     */
    public ByteBuffer sign(ByteBuffer msg)
            throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, ShortBufferException {

        ByteBuffer sig = ByteBuffer.allocate(SIG_BYTE + msg.limit());
        ByteBuffer inRandomness = ByteBuffer.allocate(RANDOM_BYTE + SEED_BYTE + HASHED_MSG_BYTE * 2);
        ByteBuffer randomness = ByteBuffer.allocate(SEED_BYTE);
        int nonce = 0; // Initializes domain separator to sample y
        boolean response = false;
        int[] posList = new int[H];
        int[] signList = new int[H];
        int[] sc = new int[N];
        int[] ec = new int[K * N];
        int[] v = new int[K * N];

        // Computes H(seed_y, randomness, H(m)) to sample y
        arraycopy(
                this.sk.array(), SK_BYTE - HASHED_MSG_BYTE - SEED_BYTE, inRandomness.array(), 0, SEED_BYTE
        );
        this.rng.generateRandomness(inRandomness, RANDOM_BYTE, RANDOM_BYTE);
        this.fips202.shake(inRandomness, RANDOM_BYTE + SEED_BYTE, HASHED_MSG_BYTE, msg, 0, msg.limit());
        this.fips202.shake(
                randomness, 0, SEED_BYTE, inRandomness, 0, RANDOM_BYTE + SEED_BYTE + HASHED_MSG_BYTE
        );
        arraycopy(
                this.sk.array(), SK_BYTE - HASHED_MSG_BYTE,
                inRandomness.array(), RANDOM_BYTE + SEED_BYTE + HASHED_MSG_BYTE,
                HASHED_MSG_BYTE
        );

        int[] a = this.poly.uniformPoly(this.sk, SK_BYTE - HASHED_MSG_BYTE - SEED_BYTE * 2);

        while (true) {

            // Samples y uniformly at random from the range [-B,B]
            int[] y = this.sample.sampleY(randomness, ++nonce);
            int[] yNTT = this.poly.polyFwdNTT(y);

            for (int polyIndex = 0; polyIndex < K; polyIndex++) {
                this.poly.multiply(v, N * polyIndex, a, N * polyIndex, yNTT, 0);
            }

            ByteBuffer c = generateC(v, inRandomness, RANDOM_BYTE + SEED_BYTE);
            // Generate c = encode_c(c'), where c' is the hashing of v together with message
            this.poly.encodeC(posList, signList, c);
            this.poly.sparseMulWithSK(sc, 0, this.sk, 0, posList, signList);
            int[] z = this.poly.add(y, sc);

            // Rejection sampling
            if (testRejection(z) != 0) {
                continue;
            }

            for (int polyIndex = 0; polyIndex < K; polyIndex++) {
                this.poly.sparseMulWithSK(
                        ec, N * polyIndex, this.sk, N * (polyIndex + 1), posList, signList
                );
                this.poly.subtract(
                        v, N * polyIndex, v, N * polyIndex, ec, N * polyIndex
                );
                response = testCorrectness(v, N * polyIndex);
                if (response) {
                    break;
                }
            }

            if (response) {
                continue;
            }

            // Copies message to signature package and packs signature
            arraycopy(msg.array(), 0, sig.array(), SIG_BYTE, msg.limit());
            this.pack.encodeSig(sig, c, z);

            return sig;

        }

    }

    /**
     * Verifies a given signature in the context of a given message
     *
     * @param msg Given message
     * @param sig Given signature
     * @return true: valid signature <br> false: invalid signature
     */
    public boolean verify(ByteBuffer msg, ByteBuffer sig) {

        if (sig.limit() != SIG_BYTE + msg.limit()) {
            return false;
        }

        sig.position(SIG_BYTE);

        for (int msgIndex = 0; msgIndex < msg.limit(); msgIndex++) {
            if (msg.get() != sig.get()) {
                return false;
            }
        }

        ByteBuffer c = ByteBuffer.allocate(C_BYTE);
        ByteBuffer seed = ByteBuffer.allocate(SEED_BYTE);
        ByteBuffer hashedMsg = ByteBuffer.allocate(HASHED_MSG_BYTE * 2);
        IntBuffer tempPK = IntBuffer.allocate(K * N);
        int[] z = new int[N];
        int[] posList = new int[H];
        int[] signList = new int[H];
        int[] tc = new int[K * N];
        int[] w = new int[K * N];

        this.pack.decodeSig(c, z, sig);

        // Checks the norm of z
        if (testZ(z)) {
            return false;
        }

        this.pack.decodePK(tempPK, seed, pk);

        // Computes digested message and hashed public key
        this.fips202.shake(hashedMsg, 0, HASHED_MSG_BYTE, sig, SIG_BYTE, sig.limit() - SIG_BYTE);
        this.fips202.shake(hashedMsg, HASHED_MSG_BYTE, HASHED_MSG_BYTE, this.pk, 0, PK_BYTE - SEED_BYTE);

        int[] a = this.poly.uniformPoly(seed, 0);
        this.poly.encodeC(posList, signList, c);
        int[] zNTT = this.poly.polyFwdNTT(z);

        // Computes w = a * z - t * c
        for (int polyIndex = 0; polyIndex < K; polyIndex++) {
            this.poly.sparseMulWithPK(
                    tc, N * polyIndex, tempPK.array(), N * polyIndex, posList, signList
            );
            this.poly.multiply(w, N * polyIndex, a, N * polyIndex, zNTT, 0);
            this.poly.subWithRed(w, N * polyIndex, w, N * polyIndex, tc, N * polyIndex);
        }

        // Checks whether the calculated c matches c as the signature part
        ByteBuffer cSig = generateC(w, hashedMsg, 0);
        cSig.rewind();

        return cSig.equals(c);

    }

}