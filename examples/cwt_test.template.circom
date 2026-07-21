pragma circom 2.0.3;

include "cbor_redact_verify.circom";
include "hash_and_blind.circom";

/**
 * CWT redaction experiment top level:
 *   COSE_Sign1(CWT) --> CborRedactVerify --> mdoc-style message
 *                                            --> Sha256BlindRSAPSS (unchanged)
 *
 * The mdoc-style message produced by CborRedactVerify is fed byte-per-byte,
 * unmodified, as the `message` input of the existing Sha256BlindRSAPSS
 * template, with messageLen = 2 + nsLen + nFields*(21 + maxKeyLen + maxValueLen).
 *
 * Placeholders ({{...}}) are replaced by cwt_redact/prepare.py, so the
 * circuit is re-compilable for any credential size (payload up to 4 KB by
 * default) without editing the templates.
 */
template CwtRedactBlind(w, k, eBits, mgfCount, payloadLen, protLen, nFields, maxKeyLen, maxValueLen, nsLen, placeholder) {
    var bpl = w / 8;
    var messageLen = 2 + nsLen + nFields * (21 + maxKeyLen + maxValueLen);

    // --- credential + issuer-verification inputs ---
    signal input payload[payloadLen];       // CWT claims payload (private)
    signal input prot[protLen];             // COSE protected header bytes
    signal input issuerSig[k];              // issuer RSA-PSS signature limbs (private)
    signal input issuerPssSalt[32];         // issuer PSS salt (private)
    signal input issuerExp[k];              // issuer public key (public)
    signal input issuerModulus[k];
    signal input mask[nFields];             // disclosure mask (public)
    signal input keyLen[nFields];           // CBOR parse witnesses (private)
    signal input valLen[nFields];
    signal input valMajor[nFields];
    signal input itemRandom[nFields][16];   // per-element mdoc salts (private)
    signal input namespace[nsLen];

    // --- blinding inputs (same as Sha256BlindRSAPSS) ---
    signal input blindSalt[k];              // PSS salt for the blind signature
    signal input r[k];                      // blinding factor (bigint limbs)
    signal input notaryExp[k];              // notary public key (public)
    signal input notaryModulus[k];

    // --- outputs ---
    signal output message[messageLen];      // redacted mdoc-style serialization
    signal output blinded[k * bpl];         // blinded PSS message for the notary

    // 1) verify issuer signature, parse CWT, build redacted mdoc-style message
    component red = CborRedactVerify(w, k, eBits, mgfCount, payloadLen, protLen, nFields, maxKeyLen, maxValueLen, nsLen, placeholder);
    for (var j = 0; j < payloadLen; j++) red.payload[j] <== payload[j];
    for (var j = 0; j < protLen; j++) red.prot[j] <== prot[j];
    for (var i = 0; i < k; i++) {
        red.issuerSig[i] <== issuerSig[i];
        red.issuerExp[i] <== issuerExp[i];
        red.issuerModulus[i] <== issuerModulus[i];
    }
    for (var j = 0; j < 32; j++) red.issuerPssSalt[j] <== issuerPssSalt[j];
    for (var i = 0; i < nFields; i++) {
        red.mask[i] <== mask[i];
        red.keyLen[i] <== keyLen[i];
        red.valLen[i] <== valLen[i];
        red.valMajor[i] <== valMajor[i];
        for (var j = 0; j < 16; j++) red.itemRandom[i][j] <== itemRandom[i][j];
    }
    for (var j = 0; j < nsLen; j++) red.namespace[j] <== namespace[j];

    // 2) hash + blind the mdoc-style message with the UNMODIFIED template
    component blinder = Sha256BlindRSAPSS(w, k, eBits, mgfCount, messageLen);
    for (var j = 0; j < messageLen; j++) blinder.message[j] <== red.message[j];
    for (var i = 0; i < k; i++) {
        blinder.salt[i] <== blindSalt[i];
        blinder.r[i] <== r[i];
        blinder.exp[i] <== notaryExp[i];
        blinder.modulus[i] <== notaryModulus[i];
    }

    for (var j = 0; j < messageLen; j++) message[j] <== red.message[j];
    for (var j = 0; j < k * bpl; j++) blinded[j] <== blinder.blinded[j];
}

component main { public [issuerExp, issuerModulus, mask, namespace, notaryExp, notaryModulus] } = CwtRedactBlind(64, 32, 17, 7, {{PAYLOAD_LEN}}, {{PROT_LEN}}, {{N_FIELDS}}, {{MAX_KEY_LEN}}, {{MAX_VALUE_LEN}}, {{NS_LEN}}, {{PLACEHOLDER}});
