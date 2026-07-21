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
            log("c: ", c , ", j: ", j , ", mask index: ", (c * hashLen + j), "output: ", hsh[c].out[j]);
            mask[c * hashLen + j] <== hsh[c].out[j];
        }
    }
}

component main = MGF1(32, 64, 2);


/* INPUT = {
    "seed": [1,2,3,4]
} */