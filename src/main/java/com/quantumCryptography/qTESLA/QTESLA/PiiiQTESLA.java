package com.quantumCryptography.qTESLA.QTESLA;

import com.quantumCryptography.SHA3.SHAKE256;
import com.quantumCryptography.qTESLA.Pack.PiiiPack;
import com.quantumCryptography.qTESLA.Poly.PiiiPoly;

import static com.quantumCryptography.qTESLA.ParameterSet.P_III;

public class PiiiQTESLA extends QTESLA {

    public PiiiQTESLA() {
        super(P_III, new SHAKE256());
        super.setPack(new PiiiPack());
        super.setPoly(new PiiiPoly());
    }

}