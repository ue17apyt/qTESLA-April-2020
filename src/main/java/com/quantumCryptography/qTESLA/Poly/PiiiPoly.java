package com.quantumCryptography.qTESLA.Poly;

import static com.quantumCryptography.qTESLA.Parameter.N;
import static com.quantumCryptography.qTESLA.ParameterSet.P_III;

public class PiiiPoly extends Poly {

    public PiiiPoly() {
        super(P_III);
    }

    @Override
    public void fwdNTT(int[] a, int aOffset, int[] omega) {

        int problemNo = N >>> 1;
        int jTwiddle = 0;

        while (problemNo > 0) {

            int j;

            for (int jFirst = 0; jFirst < N; jFirst = j + problemNo) {

                long omegaValue = omega[jTwiddle++];

                for (j = jFirst; j < jFirst + problemNo; j++) {
                    int temporary = montgomeryReduce(omegaValue * a[aOffset + j + problemNo]);
                    a[aOffset + j + problemNo] = (int) barretoReduce(a[aOffset + j] - temporary);
                    a[aOffset + j] = (int) barretoReduce(temporary + a[aOffset + j]);
                }

            }

            problemNo >>= 1;

        }

    }
}