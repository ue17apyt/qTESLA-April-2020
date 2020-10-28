package com.quantumCryptography.SHA3;

import com.quantumCryptography.qTESLA.Parameter;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.ByteBuffer;

import static com.quantumCryptography.qTESLA.Parameter.SEED_BYTE;
import static com.quantumCryptography.qTESLA.ParameterSet.P_I;
import static com.quantumCryptography.utility.Utility.getByteArrayFromResFile;
import static java.lang.System.arraycopy;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;

public class FIPS202Test {

    public static final byte PENDING = 0x1F;
    public static final short CUSTOMIZATION = (short) 0xABCD;
    public static final int MSG_BYTE = 3300;

    private final long[] state = {
            0xCE927EFC8FE97AAEL, 0x61EBA9DBC3EB4EFAL, 0xBAB68419488A0892L, 0x522F0DECD768C980L, 0x3E1868D72EDCBDC0L,
            0x5FC122FB4DD2147EL, 0xAABEB285C96699C7L, 0xE35AE1DEFCF41C37L, 0x17CEEFC7FD747A6CL, 0x2E252EA506B1657DL,
            0x7C100ED9646EAF47L, 0xE3DA8BFE219EED93L, 0x1564E54256E3150EL, 0xA3AAFF3095DB904FL, 0x5856F30BF9F65C8DL,
            0xA80191030B7CC566L, 0xD6EA2B2AD84C655FL, 0x29C5F3A8A5527B26L, 0x51A01D79B0B4FF91L, 0xB5DD9F2DD481665EL,
            0xBEDD74D23A546428L, 0x311242500467BC24L, 0x3066FE39D3C516E6L, 0x640C0B6D3A2DD7ACL, 0x7E049F986A5B4585L
    };

    @Test
    public void permuteStatesTest() {

        FIPS202 fips202 = new FIPS202(SHAKE128.BITRATE, SHAKE128.SEP);
        long[] expState = {
                0x541B0C845F097A4EL, 0xC649D7080E30113CL, 0xD4CDC391AAD178C5L, 0x42C1A298213578FEL, 0x3A8A1CBEACA07D9FL,
                0xF4FF630CA722D540L, 0xD05FCA9893178E27L, 0xB6513B020CC37BA8L, 0x082CEC25D2CD9B77L, 0x7F8FB63D2F522D4DL,
                0x52BD971AC463BC29L, 0xCF69B0A81C235BCFL, 0x44DCDFDF6BA9A3B8L, 0xFDF4B5E9C752CC1EL, 0xEE935255F9DC006BL,
                0x91387086FE6121D9L, 0x366D3EB23B230EF7L, 0x982013F83EFE0A78L, 0x7C9EF407FDF6BE14L, 0xFF98BD6EA36DEDE5L,
                0x062621E400C69242L, 0x0AD79365675E53FDL, 0x915CC6638F11BBF7L, 0x2F25AC09A66CEA27L, 0x03616200EC43BD69L
        };

        fips202.keccakPermuteStates(this.state);

        assertArrayEquals(expState, this.state);

    }

    @Test
    public void keccakAbsorbTest() throws IOException {

        FIPS202 fips202 = new FIPS202(SHAKE128.BITRATE, SHAKE128.SEP);
        ByteBuffer msg = ByteBuffer.allocate(3900);
        byte[] partMsg = getByteArrayFromResFile("qTESLA/QTESLA/msg.txt", MSG_BYTE);
        long[] expState = {
                0x2314F170E933E4ECL, 0xAB6F332DEE05B922L, 0xFD0C640E1003775CL, 0x2DC400129F5771E5L, 0x88F40B574F2DF127L,
                0xEDD8A7F3401142A5L, 0xA7841947D31011C0L, 0x97C923A31D1FC61CL, 0x3537118D33803793L, 0x3EED9A2D4E7416D0L,
                0x4278DCF00DBF158DL, 0x99101C961F6245DDL, 0x0B26F7F05CDFAF5DL, 0x86BB44AC226EDB77L, 0xB70883E25AAC97D8L,
                0x2FCA2E574837AA8FL, 0x0627DC5C612F4364L, 0x64F1E50CF54B6E6DL, 0x8B516A7C129933B1L, 0xAEBD2788E23267FCL,
                0x01B82665A596BED2L, 0x9ACED37904D08682L, 0x2B826AC6A2732B55L, 0x48352B34B0C9158EL, 0xA1E7AE5AC979B774L,
        };

        arraycopy(partMsg, 0, msg.array(), 300, partMsg.length);
        fips202.keccakAbsorb(this.state, SHAKE128.BITRATE, msg, 300, partMsg.length, PENDING);

        assertArrayEquals(expState, this.state);

    }

    @Test
    public void keccakSqueezeBlocksTest() throws IOException {

        FIPS202 fips202 = new FIPS202(SHAKE128.BITRATE, SHAKE128.SEP);
        ByteBuffer output = ByteBuffer.allocate(SEED_BYTE * (new Parameter(P_I).K + 5));
        byte[] partOut = new byte[SEED_BYTE * (new Parameter(P_I).K + 3)];
        byte[] expOut = getByteArrayFromResFile("FIPS202/outKeccakSqueezeBlocks.txt", partOut.length);

        fips202.keccakSqueezeBlocks(output, SEED_BYTE, 1L, this.state);
        arraycopy(output.array(), SEED_BYTE, partOut, 0, partOut.length);

        assertArrayEquals(expOut, partOut);

    }

    @Test
    public void shakeTest() throws IOException {

        FIPS202 fips202 = new SHAKE128();
        ByteBuffer output = ByteBuffer.allocate(SEED_BYTE * (new Parameter(P_I).K + 5));
        ByteBuffer seed = ByteBuffer.allocate(SEED_BYTE * 3);
        byte[] partSeed = getByteArrayFromResFile("FIPS202/seed.txt", SEED_BYTE);
        byte[] partOut = new byte[SEED_BYTE * (new Parameter(P_I).K + 3)];
        byte[] expOut = getByteArrayFromResFile("FIPS202/outSHAKE.txt", partOut.length);

        arraycopy(partSeed, 0, seed.array(), SEED_BYTE * 2, SEED_BYTE);
        fips202.shake(output, SEED_BYTE, partOut.length, seed, SEED_BYTE * 2, SEED_BYTE);
        arraycopy(output.array(), SEED_BYTE, partOut, 0, partOut.length);

        assertArrayEquals(expOut, partOut);

    }

    @Test
    public void cShakeSimpleAbsorbTest() throws IOException {

        FIPS202 fips202 = new FIPS202(SHAKE128.BITRATE, SHAKE128.SEP);
        ByteBuffer input = ByteBuffer.allocate(3900);
        byte[] partIn = getByteArrayFromResFile("qTESLA/QTESLA/msg.txt", MSG_BYTE);
        long[] expState = {
                0xA40109D4D0F06BF7L, 0x2F753A2F2BDC0734L, 0xAB0BCA260422ABBBL, 0x5AACB763C2306939L, 0x9B2CF37E83285DABL,
                0x4A999931F0FF8B16L, 0x80A1DDF24077E8E1L, 0x48B72ACCCEEA491EL, 0xFB248AE841E8BD81L, 0x80646ECFD8A876D5L,
                0xE5FF4B9ED43F2905L, 0x9141E992FADD19E8L, 0x53A1670027FFE428L, 0x13371DE91D69AB8DL, 0x74C63AFED0ECE60BL,
                0x8D5D28A3D08595F1L, 0x06DA2CB6CEDAEEA7L, 0xAE91DC840709D756L, 0x44BF6440159C787FL, 0x64F2DAB42D553FE5L,
                0xE1CBBF887F8A9CFAL, 0x3C12376C993DB0DEL, 0x6F603060F9BB140AL, 0xFED9B7EF70E36F45L, 0xEFCD639E1E3B0B21L
        };

        arraycopy(partIn, 0, input.array(), 300, partIn.length);
        fips202.cShakeSimpleAbsorb(this.state, CUSTOMIZATION, input, 300, partIn.length);

        assertArrayEquals(expState, this.state);

    }

    @Test
    public void cShakeSimpleTest() throws IOException {

        FIPS202 fips202 = new FIPS202(SHAKE128.BITRATE, SHAKE128.SEP);
        ByteBuffer output = ByteBuffer.allocate(SEED_BYTE * (new Parameter(P_I).K + 5));
        ByteBuffer input = ByteBuffer.allocate(3900);
        byte[] partOut = new byte[SEED_BYTE * (new Parameter(P_I).K + 3)];
        byte[] partIn = getByteArrayFromResFile("qTESLA/QTESLA/msg.txt", MSG_BYTE);
        byte[] expOut = getByteArrayFromResFile("FIPS202/outCSHAKESimple.txt", partOut.length);

        arraycopy(partIn, 0, input.array(), 300, partIn.length);
        fips202.cShakeSimple(output, SEED_BYTE, partOut.length, CUSTOMIZATION, input, 300, partIn.length);
        arraycopy(output.array(), SEED_BYTE, partOut, 0, partOut.length);

        assertArrayEquals(expOut, partOut);

    }

}