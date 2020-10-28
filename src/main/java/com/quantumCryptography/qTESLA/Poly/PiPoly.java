package com.quantumCryptography.qTESLA.Poly;

import static com.quantumCryptography.qTESLA.Parameter.N;
import static com.quantumCryptography.qTESLA.Parameter.Q;
import static com.quantumCryptography.qTESLA.Parameter.RADIX32;
import static com.quantumCryptography.qTESLA.ParameterSet.P_I;

public class PiPoly extends Poly {

    public PiPoly() {
        super(P_I);
    }

    public void fwdNTT(int[] a, int aOffset, int[] omega) {

        int problemNo = N >>> 1;
        int jTwiddle = 0;

        while (problemNo > 0) {

            int j;

            for (int jFirst = 0; jFirst < N; jFirst = j + problemNo) {

                long omegaValue = omega[jTwiddle++];

                for (j = jFirst; j < jFirst + problemNo; j++) {
                    int temporary = montgomeryReduce(omegaValue * a[aOffset + j + problemNo]);
                    a[aOffset + j + problemNo] = a[aOffset + j] - temporary;
                    a[aOffset + j + problemNo] += (a[aOffset + j + problemNo] >> (RADIX32 - 1)) & Q;
                    a[aOffset + j] += temporary - Q;
                    a[aOffset + j] += (a[aOffset + j] >> (RADIX32 - 1)) & Q;
                }

            }

            problemNo >>= 1;

        }

    }

}