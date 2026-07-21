pragma circom 2.0.3;

include "../../node_modules/circomlib/circuits/comparators.circom";
include "../../node_modules/circomlib/circuits/bitify.circom";
include "../../node_modules/circomlib/circuits/gates.circom";

include "../../sha256.circom";

// Convert integer to octet string of length xLen (I2OSP)
template I2OSP(xLen) {
    signal input in;
    signal output out[xLen]; //returns an array of xLen bytes
    component bits = Num2Bits(xLen * 8);
    bits.in <== in;
    component pack[xLen];
    for (var i = 0; i < xLen; i++) pack[i] = Bits2Num(8);
    for (var i = 0; i < xLen; i++) {
        for (var j = 0; j < 8; j++) {
            pack[i].in[j] <== bits.out[(xLen - 1 - i) * 8 + j];
        }
        out[i] <== pack[i].out;
    }
}

// Convert octet string to integer (OS2IP)
template OS2IP(xLen) {
    signal input in[xLen];
    signal output out;
    signal allBits[xLen * 8];
    component unpack[xLen];
    for (var i = 0; i < xLen; i++) unpack[i] = Num2Bits(8);
    for (var i = 0; i < xLen; i++) {
        unpack[i].in <== in[i];
        for (var j = 0; j < 8; j++) {
            allBits[(xLen - 1 - i) * 8 + j] <== unpack[i].out[j];
        }
    }
    component combine = Bits2Num(xLen * 8);
    for (var b = 0; b < xLen * 8; b++) combine.in[b] <== allBits[b];
    out <== combine.out;
}

// MGF1 mask generation using SHA-256 
template MGF1(len, maskLen, count) {
    signal input seed[len];
    signal output mask[maskLen];
    var hashLen = len;

    // in theory, count = ceil(maskLen / hashLen) - 1, but we assume it is correct

    component ctr[count];
    component hsh[count];
    for (var i = 0; i < count; i++) {
        ctr[i] = I2OSP(4);
        hsh[i] = Sha256Bytes(len + 4);
    }
    for (var c = 0; c < count; c++) {
        ctr[c].in <== c;
        for (var j = 0; j < len; j++) hsh[c].in[j] <== seed[j];
        for (var j = 0; j < 4; j++) hsh[c].in[len + j] <== ctr[c].out[j];
        for (var j = 0; j < hashLen && c * hashLen + j < maskLen; j++) { // mask returns only the first maskLen bytes, if c * hashLen + j >= maskLen it does not go into the loop
            // mask is filled with the output of the hash function
            mask[c * hashLen + j] <== hsh[c].out[j];
        }
    }
}


// EMSA-PSS Encoding (bytes) with SHA-256
template EMSA_PSS_Encode(emBytes, hashLen, saltLen, mgfCount) {
    signal input hashed[hashLen];
    signal input salt[saltLen];
    signal output EM[emBytes];

    // Step1: PSS hash M': 8 zeros || mHash || salt
    component m1 = Sha256Bytes(8 + hashLen + saltLen);
    for (var i = 0; i < 8; i++) m1.in[i] <== 0;
    for (var i = 0; i < hashLen; i++) m1.in[8 + i] <== hashed[i];
    for (var i = 0; i < saltLen; i++) m1.in[8 + hashLen + i] <== salt[i];

    var psLen = emBytes - saltLen - hashLen - 2; //padding di questa lunghezza con byte tutti a 0
    var dbLen = emBytes - hashLen - 1; // dbLen is the length of the maskedDB part, es if emBytes=512, hashLen=32, dbLen=479

    // Step2: MGF1 mask generation
    component mgf = MGF1(hashLen, dbLen, mgfCount);
    for (var i = 0; i < hashLen; i++) mgf.seed[i] <== m1.out[i];

    // Step3: Create the maskedDB = DB XOR dbMask

    signal maskedDEB[dbLen];
    component convert2bits[dbLen];
    component convert2num[dbLen];
    component XOR_DB[dbLen*8];

    // component maskedBits[psLen * 8];
    // component constantBits[8];
    // component saltBits[saltLen * 8];

    for (var i = 0; i < psLen; i++) {
        convert2bits[i] = Num2Bits(8);
        convert2num[i] = Bits2Num(8);
        convert2bits[i].in <== mgf.mask[i];

        for (var j = 0; j < 8; j++) {
            XOR_DB[i * 8 + j] = XOR();
            XOR_DB[i * 8 + j].a <== 0; // PS - padding with zeros
            XOR_DB[i * 8 + j].b <== convert2bits[i].out[j];
            convert2num[i].in[j] <== XOR_DB[i * 8 + j].out;
        }

        maskedDEB[i] <== convert2num[i].out;
    }

    convert2bits[psLen] = Num2Bits(8);
    convert2num[psLen] = Bits2Num(8);
    convert2bits[psLen].in <== mgf.mask[psLen];
    component constantBits = Num2Bits(8);
    constantBits.in <== 1; // constant bits for padding with zeros
    for (var j = 0; j < 8; j++) {
            XOR_DB[psLen*8 + j] = XOR();
            XOR_DB[psLen*8 + j].a <== constantBits.out[j]; // PS - padding with zeros
            XOR_DB[psLen*8 + j].b <== convert2bits[psLen].out[j];
            convert2num[psLen].in[j] <== XOR_DB[psLen*8 + j].out;
    }
    maskedDEB[psLen] <== convert2num[psLen].out; // 1 byte with value 0x01

    component convertSalt2bits[saltLen];
    var k = psLen + 1; // index for the salt part in the mask
    
    for (var i = 0; i < saltLen; i++) {
        convert2bits[k+i] = Num2Bits(8);
        convert2num[k+i] = Bits2Num(8);
        convert2bits[k+i].in <== mgf.mask[k+i];

        convertSalt2bits[i] = Num2Bits(8);
        convertSalt2bits[i].in <== salt[i];

        for (var j = 0; j < 8; j++) {
            XOR_DB[(k+i) * 8 + j] = XOR();
            XOR_DB[(k+i) * 8 + j].a <== convertSalt2bits[i].out[j]; // salt part
            XOR_DB[(k+i) * 8 + j].b <== convert2bits[k+i].out[j];
            convert2num[k+i].in[j] <== XOR_DB[(k+i) * 8 + j].out;
        }

        maskedDEB[k+i] <== convert2num[k+i].out;
    }


    // first byte is always mask[0] & 0x7F
    component andMask[8];
    component convertMask = Num2Bits(8);
    convertMask.in <== maskedDEB[0];
    component convertMaskNum = Num2Bits(8);
    convertMaskNum.in <== 0x7f; // 0x7F = 01111111
    component convert2numMask = Bits2Num(8);
    for (var j = 0; j < 8; j++) {
            andMask[j] = AND();
            andMask[j].a <== convertMask.out[j]; // PS - padding with zeros
            andMask[j].b <== convertMaskNum.out[j];
            convert2numMask.in[j] <== andMask[j].out;
    }
    EM[0] <== convert2numMask.out;

    // Copy maskedDB part
    for (var i = 1; i < dbLen; i++) { 
        EM[i] <== maskedDEB[i];
    }
    for (var i = 0; i < hashLen; i++) EM[dbLen + i] <== m1.out[i];
    EM[emBytes - 1] <== 0xbc;
    for (var i = 0; i < emBytes; i++) {
        log("EM[" , i , "] = " , EM[i]);
    }
}

// 256-BYTE
component main = EMSA_PSS_Encode(256, 32, 32, 7);