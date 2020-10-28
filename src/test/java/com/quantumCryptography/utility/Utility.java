package com.quantumCryptography.utility;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;

public class Utility {

    private static int decodeHexadecimalStringToInt(String hexadecimalString) {

        int value = 0;

        if (hexadecimalString.length() == 8) {
            for (int charIndex = 0; charIndex < 8; charIndex++) {
                value ^= Character.digit(hexadecimalString.charAt(charIndex), 16);
                if (charIndex < 7) {
                    value <<= 4;
                }
            }
        }

        return value;

    }

    private static byte decodeHexadecimalStringToByte(String hexadecimalString) {

        byte value = 0;

        if (hexadecimalString.length() == 2) {
            int firstDigit = Character.digit(hexadecimalString.charAt(0), 16);
            int secondDigit = Character.digit(hexadecimalString.charAt(1), 16);
            value = (byte) ((firstDigit << 4) ^ secondDigit);
        }

        return value;

    }

    public static byte[] decodeHexStrToByteArray(String hexadecimalString) {

        if (hexadecimalString.length() % 2 == 1) {
            throw new IllegalArgumentException("Invalid hexadecimal String.");
        }

        byte[] byteArray = new byte[hexadecimalString.length() / 2];

        for (int i = 0; i < hexadecimalString.length(); i += 2) {
            int firstDigit = Character.digit(hexadecimalString.charAt(i), 16);
            int secondDigit = Character.digit(hexadecimalString.charAt(i + 1), 16);
            byteArray[i / 2] = (byte) ((firstDigit << 4) ^ secondDigit);
        }

        return byteArray;

    }

    public static int[] decodeHexStrToIntArray(String hexadecimalString) {

        if (hexadecimalString.length() % 8 != 0) {
            throw new IllegalArgumentException("Invalid hexadecimal String.");
        }

        int[] intArray = new int[hexadecimalString.length() / 8];

        for (int stringIndex = 0; stringIndex < hexadecimalString.length(); stringIndex += 8) {
            for (int separatorIndex = stringIndex + 6; separatorIndex >= stringIndex; separatorIndex -= 2) {
                int firstDigit = Character.digit(hexadecimalString.charAt(separatorIndex), 16);
                int secondDigit = Character.digit(hexadecimalString.charAt(separatorIndex + 1), 16);
                intArray[stringIndex / 8] = (intArray[stringIndex / 8] << 8) ^ ((firstDigit << 4) ^ secondDigit);
            }
        }

        return intArray;

    }

    public static byte[] getByteArrayFromResFile(String relativeResFilePath, int capacity) throws IOException {

        InputStream inputStream = Utility.class.getClassLoader().getResourceAsStream(relativeResFilePath);
        BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(inputStream));
        byte[] byteArray = new byte[capacity];
        int index = 0;
        String line;

        while ((line = bufferedReader.readLine()) != null) {
            byteArray[index++] = decodeHexadecimalStringToByte(line);
        }

        return byteArray;

    }

    public static int[] getIntArrayFromResFile(String relativeResFilePath, int capacity) throws IOException {

        InputStream inputStream = Utility.class.getClassLoader().getResourceAsStream(relativeResFilePath);
        BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(inputStream));
        int[] intArray = new int[capacity];
        int index = 0;
        String line;

        while ((line = bufferedReader.readLine()) != null) {
            intArray[index++] = decodeHexadecimalStringToInt(line);
        }

        return intArray;

    }

}