package com.quantumCryptography.qTESLA.QTESLA;

import com.quantumCryptography.SHA3.SHAKE128;
import com.quantumCryptography.qTESLA.Pack.PiPack;
import com.quantumCryptography.qTESLA.Poly.PiPoly;

import static com.quantumCryptography.qTESLA.ParameterSet.P_I;

public class PiQTESLA extends QTESLA {

    public PiQTESLA() {
        super(P_I, new SHAKE128());
        super.setPack(new PiPack());
        super.setPoly(new PiPoly());
    }

}