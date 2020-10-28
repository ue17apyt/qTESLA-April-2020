package com.quantumCryptography.qTESLA.Poly;

import com.quantumCryptography.SHA3.SHAKE128;
import com.quantumCryptography.qTESLA.Parameter;
import com.quantumCryptography.qTESLA.ParameterSet;

import java.nio.ByteBuffer;
import java.util.Arrays;

import static com.quantumCryptography.SHA3.SHAKE128.BITRATE;
import static com.quantumCryptography.qTESLA.Parameter.BARRETO_DIV;
import static com.quantumCryptography.qTESLA.Parameter.BARRETO_MULT;
import static com.quantumCryptography.qTESLA.Parameter.GEN_A;
import static com.quantumCryptography.qTESLA.Parameter.H;
import static com.quantumCryptography.qTESLA.Parameter.K;
import static com.quantumCryptography.qTESLA.Parameter.N;
import static com.quantumCryptography.qTESLA.Parameter.Q;
import static com.quantumCryptography.qTESLA.Parameter.Q_INV;
import static com.quantumCryptography.qTESLA.Parameter.R2_INV;
import static com.quantumCryptography.qTESLA.Parameter.RADIX32;
import static com.quantumCryptography.qTESLA.Parameter.RANDOM_BYTE;
import static com.quantumCryptography.qTESLA.Parameter.ZETA;
import static com.quantumCryptography.qTESLA.Parameter.ZETA_INV;
import static java.lang.Integer.reverseBytes;
import static java.lang.System.arraycopy;

public abstract class Poly {

    private final Parameter parameter;

    public Poly(ParameterSet parameterSet) {
        this.parameter = new Parameter(parameterSet);
    }

    /**
     * Performs reduction named after Peter Lawrence Montgomery
     *
     * @param a Long number
     * @return
     */
    public int montgomeryReduce(long a) {
        return (int) ((a + (((a * Q_INV) & 0xFFFFFFFFL) * Q)) >> 32);
    }

    /**
     * Performs reduction named after Paulo Sérgio Licciardi Messeder Barreto
     *
     * @param a Long number
     * @return
     */
    public long barretoReduce(long a) {
        return a - ((a * BARRETO_MULT) >> BARRETO_DIV) * Q;
    }

    /**
     * Generate polynomials "a_k"
     *
     * @param seedA      32-byte seed to generate K N-coefficient public polynomial a_1, ..., a_k
     * @param seedOffset Seed offset
     * @return K N-coefficient polynomials a_1, ..., a_K
     */
    public int[] uniformPoly(ByteBuffer seedA, int seedOffset) {

        int[] a = new int[N * K];
        int index = 0;
        int qLog = (int) (Math.log(Q) / Math.log(2)) + 1;
        int byteNo = (qLog + 7) / 8;
        int blockNo = GEN_A;
        int[] val = new int[4];
        int mask = (1 << qLog) - 1;
        short domainSep = 0; // domain separation
        ByteBuffer byteBuffer = ByteBuffer.allocate(BITRATE * GEN_A);
        SHAKE128 shake128 = new SHAKE128();

        shake128.cShakeSimple(
                byteBuffer, 0, byteBuffer.limit(), domainSep++, seedA, seedOffset, RANDOM_BYTE
        );
        byteBuffer.rewind();

        while (index < N * K) {

            if (byteBuffer.position() > BITRATE * blockNo - 4 * byteNo) {
                blockNo = 1;
                byteBuffer.rewind();
                shake128.cShakeSimple(
                        byteBuffer, 0, BITRATE * blockNo, domainSep++, seedA, seedOffset, RANDOM_BYTE
                );
                byteBuffer.rewind();
            }

            for (int valIndex = 0; valIndex < 4; valIndex++) {
                val[valIndex] = reverseBytes(byteBuffer.getInt()) & mask;
                byteBuffer.position(byteBuffer.position() - 4 + byteNo);
            }

            for (int valIndex = 0; valIndex < 4; valIndex++) {
                if (val[valIndex] < Q && index < N * K) {
                    a[index++] = montgomeryReduce(val[valIndex] * R2_INV);
                }
            }

        }

        return a;

    }

    /**
     * Performs forward number theoretic transform
     *
     * @param a       K N-coefficient polynomials
     * @param aOffset Polynomial offset
     * @param omega
     */
    public abstract void fwdNTT(int[] a, int aOffset, int[] omega);

    /**
     * Performs inverse number theoretic transform
     *
     * @param a       N-coefficient polynomial
     * @param aOffset Polynomial offset
     * @param omega
     */
    public void invNTT(int[] a, int aOffset, int[] omega) {

        int jTwiddle = 0;

        for (int problemNo = 1; problemNo < N; problemNo <<= 1) {

            int j = 0;

            for (int jFirst = 0; jFirst < N; jFirst = j + problemNo) {

                long omegaValue = omega[jTwiddle++];

                for (j = jFirst; j < jFirst + problemNo; j++) {
                    int temp = a[aOffset + j];
                    a[aOffset + j] = (int) barretoReduce(temp + a[aOffset + j + problemNo]);
                    a[aOffset + j + problemNo] =
                            montgomeryReduce(omegaValue * (temp - a[aOffset + j + problemNo]));
                }

            }

        }

    }

    /**
     * Performs pointwise polynomial multiplication
     *
     * @param prod               N-coefficient pointwise multiplication product
     * @param prodOffset         Product-polynomial offset
     * @param multiplicand       N-coefficient multiplicand-polynomial
     * @param multiplicandOffset Multiplicand-polynomial offset
     * @param multiplier         N-coefficient multiplier-polynomial
     * @param multiplierOffset   Multiplier-polynomial offset
     */
    public void pointwiseMultiply(

            int[] prod, int prodOffset,
            int[] multiplicand, int multiplicandOffset,
            int[] multiplier, int multiplierOffset

    ) {
        for (int prodIndex = 0; prodIndex < N; prodIndex++) {
            prod[prodOffset + prodIndex] =
                    montgomeryReduce(
                            (long) multiplicand[multiplicandOffset + prodIndex] *
                                    multiplier[multiplierOffset + prodIndex]
                    );
        }

    }

    /**
     * Performs forward number theoretic transform of polynomials stably
     *
     * @param a N-coefficient polynomial
     * @return
     */
    public int[] polyFwdNTT(int[] a) {

        int[] aFwdNTT = new int[N];

        arraycopy(a, 0, aFwdNTT, 0, a.length);
        fwdNTT(aFwdNTT, 0, ZETA);

        return aFwdNTT;

    }

    /**
     * Performs polynomial multiplication with in-place reduction for (X^N + 1)
     *
     * @param prod               N-coefficient multiplication product
     * @param prodOffset         Product-polynomial offset
     * @param multiplicand       N-coefficient multiplicand-polynomial
     * @param multiplicandOffset Multiplicand-polynomial offset
     * @param multiplier         N-coefficient multiplier-polynomial
     * @param multiplierOffset   Multiplier-polynomial offset
     */
    public void multiply(

            int[] prod, int prodOffset,
            int[] multiplicand, int multiplicandOffset,
            int[] multiplier, int multiplierOffset

    ) {
        pointwiseMultiply(prod, prodOffset, multiplicand, multiplicandOffset, multiplier, multiplierOffset);
        invNTT(prod, prodOffset, ZETA_INV);
    }

    /**
     * Performs polynomial addition
     *
     * @param augend N-coefficient augend-polynomial
     * @param addend N-coefficient addend-polynomial
     * @return N-coefficient summation-polynomial
     */
    public int[] add(int[] augend, int[] addend) {

        int[] sum = new int[N];

        for (int sumIndex = 0; sumIndex < N; sumIndex++) {
            sum[sumIndex] = augend[sumIndex] + addend[sumIndex];
        }

        return sum;
    }

    /**
     * Performs polynomial addition with correction
     *
     * @param sum          N-coefficient summation-polynomial
     * @param sumOffset    Summation-polynomial offset
     * @param augend       N-coefficient augend-polynomial
     * @param augendOffset Augend-polynomial offset
     * @param addend       N-coefficient addend-polynomial
     * @param addendOffset Addend-polynomial offset
     */
    public void addWithCX(int[] sum, int sumOffset, int[] augend, int augendOffset, int[] addend, int addendOffset) {
        for (int sumIndex = 0; sumIndex < N; sumIndex++) {
            sum[sumOffset + sumIndex] = augend[augendOffset + sumIndex] + addend[addendOffset + sumIndex];
            sum[sumOffset + sumIndex] += (sum[sumOffset + sumIndex] >> (RADIX32 - 1)) & Q;
            sum[sumOffset + sumIndex] -= Q;
            sum[sumOffset + sumIndex] += (sum[sumOffset + sumIndex] >> (RADIX32 - 1)) & Q;
        }
    }

    /**
     * Performs polynomial subtraction
     *
     * @param diff             N-coefficient difference-polynomial
     * @param diffOffset       Difference-polynomial offset
     * @param minuend          N-coefficient minuend-polynomial
     * @param minuendOffset    Minuend-polynomial offset
     * @param subtrahend       N-coefficient subtrahend-polynomial
     * @param subtrahendOffset Subtrahend-polynomial offset
     */
    public void subtract(
            int[] diff, int diffOffset, int[] minuend, int minuendOffset, int[] subtrahend, int subtrahendOffset
    ) {
        for (int diffIndex = 0; diffIndex < N; diffIndex++) {
            diff[diffOffset + diffIndex] =
                    minuend[minuendOffset + diffIndex] - subtrahend[subtrahendOffset + diffIndex];
        }
    }

    /**
     * Performs polynomial subtraction with Barreto reduction
     *
     * @param diff             N-coefficient difference-polynomial
     * @param diffOffset       Difference-polynomial offset
     * @param minuend          N-coefficient minuend-polynomial
     * @param minuendOffset    Minuend-polynomial offset
     * @param subtrahend       N-coefficient subtrahend-polynomial
     * @param subtrahendOffset Subtrahend-polynomial offset
     */
    public void subWithRed(
            int[] diff, int diffOffset, int[] minuend, int minuendOffset, int[] subtrahend, int subtrahendOffset
    ) {
        for (int diffIndex = 0; diffIndex < N; diffIndex++) {
            diff[diffOffset + diffIndex] = (int) barretoReduce(
                    minuend[minuendOffset + diffIndex] - subtrahend[subtrahendOffset + diffIndex]
            );
        }
    }

    /**
     * Performs sparse polynomial multiplication with secret key
     *
     * @param prod       N-coefficient product-polynomial
     * @param prodOffset Product-polynomial offset
     * @param sk         Secret key
     * @param skOffset   Secret key offset
     * @param posList    List of indices of non-zero elements in c
     * @param signList   List of signs of nonzero elements in c
     */
    public void sparseMulWithSK(
            int[] prod, int prodOffset, ByteBuffer sk, int skOffset, int[] posList, int[] signList
    ) {
        Arrays.fill(prod, 0);

        for (int posIndex = 0; posIndex < H; posIndex++) {

            int pos = posList[posIndex];

            for (int prodIndex = 0; prodIndex < pos; prodIndex++) {
                prod[prodOffset + prodIndex] -= signList[posIndex] * sk.get(skOffset + prodIndex + N - pos);
            }

            for (int prodIndex = pos; prodIndex < N; prodIndex++) {
                prod[prodOffset + prodIndex] += signList[posIndex] * sk.get(skOffset + prodIndex - pos);
            }

        }

    }

    /**
     * Performs sparse polynomial multiplication with public key
     *
     * @param prod       N-coefficient product-polynomial
     * @param prodOffset Product-polynomial offset
     * @param pk         Public key
     * @param pkOffset   Public key offset
     * @param posList    List of indices of non-zero elements in c
     * @param signList   List of signs of nonzero elements in c
     */
    public void sparseMulWithPK(int[] prod, int prodOffset, int[] pk, int pkOffset, int[] posList, int[] signList) {

        long[] temp = new long[N];

        for (int posIndex = 0; posIndex < H; posIndex++) {

            int pos = posList[posIndex];

            for (int tempIndex = 0; tempIndex < pos; tempIndex++) {
                temp[tempIndex] -= (long) signList[posIndex] * (long) pk[pkOffset + tempIndex + N - pos];
            }

            for (int temporaryIndex = pos; temporaryIndex < N; temporaryIndex++) {
                temp[temporaryIndex] +=
                        (long) signList[posIndex] * (long) pk[pkOffset + temporaryIndex - pos];
            }

        }

        for (int productIndex = 0; productIndex < N; productIndex++) {
            prod[prodOffset + productIndex] = (int) barretoReduce(temp[productIndex]);
        }

    }

    /**
     * Encodes c by mapping the output of the hash function H to an N-element vector with entries {-1, 0, 1}
     *
     * @param posList  list of indices of non-zero elements in c'
     * @param signList list of signs of nonzero elements in c'
     * @param cIn      Part of signature c as input
     */
    public void encodeC(int[] posList, int[] signList, ByteBuffer cIn) {

        int entryIndex = 0;
        int entryPos = 0;
        short domainSeparator = 0;
        SHAKE128 shake128 = new SHAKE128();
        int[] entry = new int[N];
        ByteBuffer randomness = ByteBuffer.allocate(shake128.getBitrate());

        shake128.cShakeSimple(
                randomness, 0, shake128.getBitrate(), domainSeparator++, cIn, 0, cIn.limit()
        );
        randomness.rewind();

        while (entryIndex < H) {

            if (randomness.position() > shake128.getBitrate() - 3) {
                randomness.rewind();
                shake128.cShakeSimple(
                        randomness, 0, shake128.getBitrate(), domainSeparator++, cIn, 0, cIn.limit()
                );
                randomness.rewind();
            }

            entryPos = ((randomness.get() << 8) | (randomness.get() & 0xFF)) & (N - 1);

            if (entry[entryPos] == 0) {

                if ((randomness.get() & 1) == 1) {
                    entry[entryPos] = -1;
                } else {
                    entry[entryPos] = 1;
                }

                posList[entryIndex] = entryPos;
                signList[entryIndex] = entry[entryPos];
                entryIndex++;

            }

        }

    }

}