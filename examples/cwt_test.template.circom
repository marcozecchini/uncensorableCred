pragma circom 2.0.3;

include "cbor_redact_verify.circom";
include "hash_and_blind.circom";

/**
 * CWT redaction experiment top level:
 *   COSE_Sign1(CWT) --> CborRedactVerify (issuer RSA-PSS verify + verified
 *   CBOR parse tree + path-selected subject map + MSO-style salted digest
 *   list) --> Sha256BlindRSAPSS (unchanged)
 *
 * The digest-list message produced by CborRedactVerify is fed byte-per-byte,
 * unmodified, as the `message` input of the existing Sha256BlindRSAPSS
 * template, with messageLen = 2 + nsLen + nFields*33. Disclosure happens
 * off-circuit (cwt_redact/present.py) by revealing item preimages against
 * the notary-signed digest list.
 *
 * Placeholders ({{...}}) are replaced by cwt_redact/prepare.py, so the
 * circuit is re-compilable for any credential size and shape (payload up to
 * 4 KB by default) without editing the templates. This same template serves
 * both the synthetic CWT example (pathDepth 0: the root claims map is the
 * subject) and real EU Digital COVID Certificates (path -260 -> 1 selects
 * the eu_dgc_v1 map).
 */
template CwtRedactBlind(w, k, eBits, mgfCount, payloadLen, protLen, maxItems, nFields, maxKeyLen, maxValueLen, pathDepth, maxPathKeyLen, nsLen) {
    var bpl = w / 8;
    var messageLen = 2 + nsLen + nFields * 33;
    var pdN = pathDepth < 1 ? 1 : pathDepth;

    // --- credential + issuer-verification inputs ---
    signal input payload[payloadLen];       // CWT claims payload (private)
    signal input prot[protLen];             // COSE protected header bytes
    signal input issuerSig[k];              // issuer RSA-PSS signature limbs (private)
    signal input issuerPssSalt[32];         // issuer PSS salt (private)
    signal input issuerExp[k];              // issuer public key (public)
    signal input issuerModulus[k];
    signal input itemRandom[nFields][16];   // per-element salts (private)
    signal input namespace[nsLen];

    // --- CBOR parse-tree witness + public path to the subject map ---
    signal input nItems;
    signal input itemOff[maxItems];
    signal input itemMajor[maxItems];
    signal input itemArg[maxItems];
    signal input itemHdrLen[maxItems];
    signal input itemParent[maxItems];
    signal input itemChildIdx[maxItems];
    signal input itemEnd[maxItems];
    signal input pathKeyLen[pdN];           // public
    signal input pathKey[pdN][maxPathKeyLen]; // public
    signal input pathKeyItem[pdN];          // witness
    signal input pathValItem[pdN];          // witness
    signal input entryKey[nFields];         // witness
    signal input entryVal[nFields];         // witness

    // --- blinding inputs (same as Sha256BlindRSAPSS) ---
    signal input blindSalt[k];              // PSS salt for the blind signature
    signal input r[k];                      // blinding factor (bigint limbs)
    signal input notaryExp[k];              // notary public key (public)
    signal input notaryModulus[k];

    // --- outputs ---
    signal output message[messageLen];      // redacted mdoc-style serialization
    signal output blinded[k * bpl];         // blinded PSS message for the notary

    // 1) verify issuer signature, parse tree, build redacted mdoc-style message
    component red = CborRedactVerify(w, k, eBits, mgfCount, payloadLen, protLen, maxItems, nFields, maxKeyLen, maxValueLen, pathDepth, maxPathKeyLen, nsLen);
    for (var j = 0; j < payloadLen; j++) red.payload[j] <== payload[j];
    for (var j = 0; j < protLen; j++) red.prot[j] <== prot[j];
    for (var i = 0; i < k; i++) {
        red.issuerSig[i] <== issuerSig[i];
        red.issuerExp[i] <== issuerExp[i];
        red.issuerModulus[i] <== issuerModulus[i];
    }
    for (var j = 0; j < 32; j++) red.issuerPssSalt[j] <== issuerPssSalt[j];
    for (var i = 0; i < nFields; i++) {
        for (var j = 0; j < 16; j++) red.itemRandom[i][j] <== itemRandom[i][j];
        red.entryKey[i] <== entryKey[i];
        red.entryVal[i] <== entryVal[i];
    }
    for (var j = 0; j < nsLen; j++) red.namespace[j] <== namespace[j];
    red.nItems <== nItems;
    for (var t = 0; t < maxItems; t++) {
        red.itemOff[t] <== itemOff[t];
        red.itemMajor[t] <== itemMajor[t];
        red.itemArg[t] <== itemArg[t];
        red.itemHdrLen[t] <== itemHdrLen[t];
        red.itemParent[t] <== itemParent[t];
        red.itemChildIdx[t] <== itemChildIdx[t];
        red.itemEnd[t] <== itemEnd[t];
    }
    for (var h = 0; h < pdN; h++) {
        red.pathKeyLen[h] <== pathKeyLen[h];
        for (var j = 0; j < maxPathKeyLen; j++) red.pathKey[h][j] <== pathKey[h][j];
        red.pathKeyItem[h] <== pathKeyItem[h];
        red.pathValItem[h] <== pathValItem[h];
    }

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

component main { public [issuerExp, issuerModulus, namespace, pathKeyLen, pathKey, notaryExp, notaryModulus] } = CwtRedactBlind(64, 32, 17, 7, {{PAYLOAD_LEN}}, {{PROT_LEN}}, {{MAX_ITEMS}}, {{N_FIELDS}}, {{MAX_KEY_LEN}}, {{MAX_VALUE_LEN}}, {{PATH_DEPTH}}, {{MAX_PATH_KEY_LEN}}, {{NS_LEN}});
