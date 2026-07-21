pragma circom 2.0.3;

include "sha256.circom";
include "rsa_blind.circom";
/**
 * Combines SHA-256 hashing of an input byte sequence with RSA-PSS blinding.
 * @param messageLen  The length of the input message in bytes.
 */
template Sha256BlindRSAPSS(w, k, eBits, mgfCount, messageLen) {
    var bpl = w / 8; // bits per limb, es if w=64, bpl=8
    var emBytes = k * bpl; // total bytes in the encoded message, es if k=64, bpl=8, emBytes=512

    // Inputs
    signal input message[messageLen];    // message to hash
    signal input salt[k];               // PSS salt
    signal input r[k];                  // blinding factor (bigint limbs)
    signal input exp[k];                // public exponent (bigint limbs)
    signal input modulus[k];            // RSA modulus (bigint limbs)

    // Output
    signal output blinded[k*bpl];       // 32 limbs * 8 bytes per limb = 256-byte blinded output

    // 1) Hash the message
    component hasher = Sha256Bytes(messageLen);
    for (var i = 0; i < messageLen; i++) {
        hasher.in[i] <== message[i];
    }

    // 2) Blind using RSA-PSS
    component blinder = BlindRSAPSS(w, k, eBits, 32, 32, mgfCount);
    // feed hashed output
    for (var i = 0; i < 32; i++) {
        blinder.hashed[i] <== hasher.out[i];
    }
    // feed salt
    for (var i = 0; i < 32; i++) {
        blinder.salt[i] <== salt[i];
    }
    // feed blinding factor r, exponent, modulus
    for (var i = 0; i < 32; i++) {
        blinder.r[i] <== r[i];
        blinder.exp[i] <== exp[i];
        blinder.modulus[i] <== modulus[i];
    }

    // capture output
    for (var i = 0; i < 32 * 8; i++) {
        blinded[i] <== blinder.blinded[i];
    }
}

// component main { public [exp, modulus] } = Sha256BlindRSAPSS(64, 32, 17, 7, 5232);