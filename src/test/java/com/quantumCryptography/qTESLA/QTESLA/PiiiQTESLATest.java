package com.quantumCryptography.qTESLA.QTESLA;

import org.junit.jupiter.api.Test;

import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import static com.quantumCryptography.SHA3.FIPS202Test.MSG_BYTE;
import static com.quantumCryptography.qTESLA.Parameter.C_BYTE;
import static com.quantumCryptography.qTESLA.Parameter.HASHED_MSG_BYTE;
import static com.quantumCryptography.qTESLA.Parameter.K;
import static com.quantumCryptography.qTESLA.Parameter.N;
import static com.quantumCryptography.qTESLA.Parameter.PK_BYTE;
import static com.quantumCryptography.qTESLA.Parameter.REJECTION;
import static com.quantumCryptography.qTESLA.Parameter.SIG_BYTE;
import static com.quantumCryptography.qTESLA.Parameter.SK_BYTE;
import static com.quantumCryptography.utility.Utility.getByteArrayFromResFile;
import static com.quantumCryptography.utility.Utility.getIntArrayFromResFile;
import static java.lang.System.arraycopy;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.util.ReflectionTestUtils.setField;

public class PiiiQTESLATest {

    private final QTESLA qTESLA = new PiiiQTESLA();

    @Test
    public void testRejectionTest() throws IOException {
        int[] z = getIntArrayFromResFile("qTESLA/Poly/PiiiPoly/a3.txt", N);
        assertEquals(1, this.qTESLA.testRejection(z));
    }

    @Test
    public void testZTest() throws IOException {
        int[] z = getIntArrayFromResFile("qTESLA/Poly/PiiiPoly/a3.txt", N);
        assertTrue(this.qTESLA.testZ(z));
    }

    @Test
    public void testCorrectnessTest() throws IOException {

        int[] partV = getIntArrayFromResFile("qTESLA/Poly/PiiiPoly/a3.txt", N);
        int[] v = new int[N * 3];

        arraycopy(partV, 0, v, N, N);
        for (int vIndex = N * 2; vIndex < N * 3; vIndex++) {
            v[vIndex] = vIndex - N * 2;
        }

        assertTrue(this.qTESLA.testCorrectness(v, N));
        assertFalse(this.qTESLA.testCorrectness(v, N * 2));

    }

    @Test
    public void checkBoundTest() throws IOException {

        int[] partPoly = getIntArrayFromResFile("qTESLA/Poly/PiiiPoly/a3.txt", N);
        int[] poly = new int[N * 3];

        arraycopy(partPoly, 0, poly, N, N);
        for (int polyIndex = N * 2; polyIndex < N * 3; polyIndex++) {
            poly[polyIndex] = (polyIndex - N * 2) / 128;
        }

        assertTrue(this.qTESLA.checkBound(poly, N, REJECTION));
        assertFalse(this.qTESLA.checkBound(poly, N * 2, REJECTION));

    }

    @Test
    public void generateCTest() throws IOException {

        byte[] partHashedMsg =
                getByteArrayFromResFile("qTESLA/QTESLA/hashedMsg.txt", HASHED_MSG_BYTE * 2);
        ByteBuffer hashedMsg = ByteBuffer.allocate(HASHED_MSG_BYTE * 4);
        int[] v = getIntArrayFromResFile("qTESLA/Pack/PiiiPack/pkDec3.txt", N * K);
        byte[] expC = getByteArrayFromResFile("qTESLA/QTESLA/QTESLA3/c3.txt", C_BYTE);

        arraycopy(partHashedMsg, 0, hashedMsg.array(), HASHED_MSG_BYTE, HASHED_MSG_BYTE * 2);
        ByteBuffer c = this.qTESLA.generateC(v, hashedMsg, HASHED_MSG_BYTE);

        assertArrayEquals(expC, c.array());

    }

    @Test
    public void generateKeyPairTest() throws
            InvalidKeyException, IOException, NoSuchAlgorithmException, NoSuchPaddingException, ShortBufferException {

        byte[] expPK = getByteArrayFromResFile("qTESLA/QTESLA/QTESLA3/genPK3.txt", PK_BYTE);
        byte[] expSK = getByteArrayFromResFile("qTESLA/QTESLA/QTESLA3/genSK3.txt", SK_BYTE);

        this.qTESLA.generateKeyPair();

        assertArrayEquals(expPK, this.qTESLA.getPK().array());
        assertArrayEquals(expSK, this.qTESLA.getSK().array());

    }

    @Test
    public void signTest() throws
            InvalidKeyException, IOException, NoSuchAlgorithmException, NoSuchPaddingException, ShortBufferException {

        ByteBuffer sk = ByteBuffer.wrap(
                getByteArrayFromResFile("qTESLA/QTESLA/QTESLA3/sk3.txt", SK_BYTE)
        );
        setField(this.qTESLA, "sk", sk);
        ByteBuffer msg = ByteBuffer.wrap(getByteArrayFromResFile("qTESLA/QTESLA/msg.txt", MSG_BYTE));
        byte[] expSig =
                getByteArrayFromResFile("qTESLA/QTESLA/QTESLA3/genSig3.txt", SIG_BYTE + MSG_BYTE);

        ByteBuffer sig = this.qTESLA.sign(msg);

        assertArrayEquals(expSig, sig.array());

    }

    @Test
    public void verifyTest() throws IOException {

        ByteBuffer pk = ByteBuffer.wrap(
                getByteArrayFromResFile("qTESLA/QTESLA/QTESLA3/pk3.txt", PK_BYTE)
        );
        setField(this.qTESLA, "pk", pk);
        ByteBuffer msg = ByteBuffer.wrap(getByteArrayFromResFile("qTESLA/QTESLA/msg.txt", MSG_BYTE));
        ByteBuffer sig = ByteBuffer.wrap(
                getByteArrayFromResFile("qTESLA/QTESLA/QTESLA3/genSig3.txt", SIG_BYTE + MSG_BYTE)
        );

        assertTrue(this.qTESLA.verify(msg, sig));

    }

}