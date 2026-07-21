pragma circom 2.0.3;

include "node_modules/circomlib/circuits/comparators.circom";
include "node_modules/circomlib/circuits/bitify.circom";

// Reuses (via rsa_blind.circom): PowerMod (pow_mod.circom), Sha256Bytes
// (sha256.circom), EMSA_PSS_Encode / MGF1, BigIntI2OSP and the bigint
// machinery (bigint.circom / bigint_func.circom, which also provides log_ceil).
include "rsa_blind.circom";

// See cbor_redact_verify.DESIGN.md for the byte layouts implemented here.

// CBOR byte-string header length for a compile-time length n (RFC 8949):
// n < 24 -> 1 byte (0x40+n), n < 256 -> 2 bytes (0x58 n),
// n < 65536 -> 3 bytes (0x59 hi lo).
function cborBstrHdrLen(n) {
    if (n < 24) { return 1; }
    if (n < 256) { return 2; }
    assert(n < 65536);
    return 3;
}

/**
 * Variable left shift over a byte array: out[j] = in[shift + j], reading
 * zeros past the end of `in`. Implemented as a log-depth barrel shifter.
 * The caller must guarantee shift <= n (here shifts are running offsets whose
 * total is constrained to equal the payload length, so they are all bounded).
 */
template VarShiftLeft(n, outLen) {
    signal input in[n];
    signal input shift;
    signal output out[outLen];

    var nb = log_ceil(n);
    component bits = Num2Bits(nb);
    bits.in <== shift;

    signal stage[nb + 1][n + outLen];
    for (var j = 0; j < n; j++) stage[0][j] <== in[j];
    for (var j = n; j < n + outLen; j++) stage[0][j] <== 0;

    for (var b = 0; b < nb; b++) {
        var s = 1 << b;
        for (var j = 0; j < n + outLen; j++) {
            if (j + s >= n + outLen) {
                stage[b + 1][j] <== stage[b][j] - bits.out[b] * stage[b][j];
            } else {
                stage[b + 1][j] <== stage[b][j] + bits.out[b] * (stage[b][j + s] - stage[b][j]);
            }
        }
    }
    for (var j = 0; j < outLen; j++) out[j] <== stage[nb][j];
}

/**
 * Minimal CBOR "verified parse" of a CWT claims payload (RFC 8392 / RFC 8949).
 * The payload must be a single definite-length map with nFields entries whose
 * keys are text strings (major type 3) and whose values are byte or text
 * strings (major type 2 or 3), all lengths < 256 (short or 1-byte-extended
 * headers). The prover supplies keyLen/valLen/valMajor as witnesses and the
 * circuit checks them against the payload bytes; running offsets are computed
 * in-circuit and the parse must consume the whole payload, so the
 * decomposition is complete and unambiguous.
 *
 * NOTE: payload bytes are NOT range-checked to 8 bits here; in the full
 * circuit they flow into Sha256Bytes, which bit-decomposes every byte.
 */
template CborMapVerify(payloadLen, nFields, maxKeyLen, maxValueLen) {
    assert(nFields > 0);
    assert(nFields < 256);
    assert(maxKeyLen >= 1 && maxKeyLen <= 255);
    assert(maxValueLen >= 1 && maxValueLen <= 255);

    var W = 2 + maxKeyLen + 2 + maxValueLen; // max bytes of one map entry
    var VW = 2 + maxValueLen;                // max bytes of one value (header + content)

    signal input payload[payloadLen];
    signal input keyLen[nFields];   // witness: length of the i-th claim key (1..maxKeyLen)
    signal input valLen[nFields];   // witness: length of the i-th claim value (0..maxValueLen)
    signal input valMajor[nFields]; // witness: CBOR major type of the value (2 = bstr, 3 = tstr)

    signal output keyBytes[nFields][maxKeyLen];   // key bytes, zero-padded past keyLen
    signal output valBytes[nFields][maxValueLen]; // value bytes, zero-padded past valLen

    // --- map header (nFields is a compile-time parameter) ---
    var mapHdrLen = 1;
    if (nFields >= 24) { mapHdrLen = 2; }
    if (nFields < 24) {
        payload[0] === 160 + nFields;   // 0xA0 + n
    } else {
        payload[0] === 184;             // 0xB8
        payload[1] === nFields;
    }

    // --- range constraints on the witnessed lengths ---
    component keyLenBits[nFields];
    component valLenBits[nFields];
    component keyLenMax[nFields];
    component valLenMax[nFields];
    component keyLenNZ[nFields];
    component isShortKeyC[nFields];
    component isShortValC[nFields];
    signal isShortKey[nFields];
    signal isShortVal[nFields];

    for (var i = 0; i < nFields; i++) {
        keyLenBits[i] = Num2Bits(8);
        keyLenBits[i].in <== keyLen[i];
        valLenBits[i] = Num2Bits(8);
        valLenBits[i].in <== valLen[i];

        keyLenMax[i] = LessEqThan(8);
        keyLenMax[i].in[0] <== keyLen[i];
        keyLenMax[i].in[1] <== maxKeyLen;
        keyLenMax[i].out === 1;
        valLenMax[i] = LessEqThan(8);
        valLenMax[i].in[0] <== valLen[i];
        valLenMax[i].in[1] <== maxValueLen;
        valLenMax[i].out === 1;

        keyLenNZ[i] = IsZero();
        keyLenNZ[i].in <== keyLen[i];
        keyLenNZ[i].out === 0;

        (valMajor[i] - 2) * (valMajor[i] - 3) === 0;

        isShortKeyC[i] = LessThan(8);
        isShortKeyC[i].in[0] <== keyLen[i];
        isShortKeyC[i].in[1] <== 24;
        isShortKey[i] <== isShortKeyC[i].out;
        isShortValC[i] = LessThan(8);
        isShortValC[i].in[0] <== valLen[i];
        isShortValC[i].in[1] <== 24;
        isShortVal[i] <== isShortValC[i].out;
    }

    // --- running offsets: entry i starts at off[i]; the parse must consume
    // --- the whole payload (no gaps, no overlaps, no trailing bytes)
    signal off[nFields + 1];
    off[0] <== mapHdrLen;
    for (var i = 0; i < nFields; i++) {
        off[i + 1] <== off[i] + (2 - isShortKey[i]) + keyLen[i] + (2 - isShortVal[i]) + valLen[i];
    }
    off[nFields] === payloadLen;

    // --- per-field alignment and header/content checks ---
    component entryShift[nFields];
    component valShift[nFields];
    signal selK[nFields];
    signal selV[nFields];
    signal rawKey[nFields][maxKeyLen];
    signal rawVal[nFields][maxValueLen];
    component keyInRange[nFields][maxKeyLen];
    component valInRange[nFields][maxValueLen];

    for (var i = 0; i < nFields; i++) {
        // window aligned at the start of entry i
        entryShift[i] = VarShiftLeft(payloadLen, W);
        for (var j = 0; j < payloadLen; j++) entryShift[i].in[j] <== payload[j];
        entryShift[i].shift <== off[i];

        // key header: text string (major type 3), short (0x60+len, len < 24)
        // or 1-byte-extended (0x78 len) form. The two forms are disjoint, so
        // the parse is unambiguous.
        selK[i] <== isShortKey[i] * (keyLen[i] - 24);
        entryShift[i].out[0] === 96 + 24 + selK[i];
        (1 - isShortKey[i]) * (entryShift[i].out[1] - keyLen[i]) === 0;

        // key bytes start right after the 1- or 2-byte header
        for (var j = 0; j < maxKeyLen; j++) {
            rawKey[i][j] <== entryShift[i].out[2 + j]
                + isShortKey[i] * (entryShift[i].out[1 + j] - entryShift[i].out[2 + j]);
            keyInRange[i][j] = LessThan(8);
            keyInRange[i][j].in[0] <== j;
            keyInRange[i][j].in[1] <== keyLen[i];
            keyBytes[i][j] <== rawKey[i][j] * keyInRange[i][j].out;
        }

        // value region starts keyHdrLen + keyLen bytes into the entry window
        valShift[i] = VarShiftLeft(W, VW);
        for (var j = 0; j < W; j++) valShift[i].in[j] <== entryShift[i].out[j];
        valShift[i].shift <== (2 - isShortKey[i]) + keyLen[i];

        // value header: major type valMajor (2 = bstr, 3 = tstr)
        selV[i] <== isShortVal[i] * (valLen[i] - 24);
        valShift[i].out[0] === valMajor[i] * 32 + 24 + selV[i];
        (1 - isShortVal[i]) * (valShift[i].out[1] - valLen[i]) === 0;

        for (var j = 0; j < maxValueLen; j++) {
            rawVal[i][j] <== valShift[i].out[2 + j]
                + isShortVal[i] * (valShift[i].out[1 + j] - valShift[i].out[2 + j]);
            valInRange[i][j] = LessThan(8);
            valInRange[i][j].in[0] <== j;
            valInRange[i][j].in[1] <== valLen[i];
            valBytes[i][j] <== rawVal[i][j] * valInRange[i][j].out;
        }
    }
}

/**
 * Rebuilds the COSE_Sign1 Sig_structure ("ToBeSigned", RFC 9052 §4.4) from
 * the protected-header bytes and the CWT payload:
 *   84 6A "Signature1" bstr(prot) 40 bstr(payload)
 * All framing bytes are compile-time constants given payloadLen/protLen.
 */
template CoseSign1TBS(payloadLen, protLen) {
    assert(protLen < 256);
    var protHdrLen = cborBstrHdrLen(protLen);
    var plHdrLen = cborBstrHdrLen(payloadLen);
    var tbsLen = 12 + protHdrLen + protLen + 1 + plHdrLen + payloadLen;

    signal input prot[protLen];
    signal input payload[payloadLen];
    signal output tbs[tbsLen];

    var sigCtx[11] = [0x6A, 0x53, 0x69, 0x67, 0x6E, 0x61, 0x74, 0x75, 0x72, 0x65, 0x31]; // text(10) "Signature1"
    tbs[0] <== 0x84; // array(4)
    for (var j = 0; j < 11; j++) tbs[1 + j] <== sigCtx[j];

    var p = 12;
    if (protLen < 24) {
        tbs[p] <== 0x40 + protLen;
        p += 1;
    } else {
        tbs[p] <== 0x58;
        tbs[p + 1] <== protLen;
        p += 2;
    }
    for (var j = 0; j < protLen; j++) tbs[p + j] <== prot[j];
    p += protLen;

    tbs[p] <== 0x40; // external_aad = '' (empty bstr)
    p += 1;

    if (payloadLen < 24) {
        tbs[p] <== 0x40 + payloadLen;
        p += 1;
    } else {
        if (payloadLen < 256) {
            tbs[p] <== 0x58;
            tbs[p + 1] <== payloadLen;
            p += 2;
        } else {
            tbs[p] <== 0x59;
            tbs[p + 1] <== payloadLen >> 8;
            tbs[p + 2] <== payloadLen & 255;
            p += 3;
        }
    }
    for (var j = 0; j < payloadLen; j++) tbs[p + j] <== payload[j];
}

/**
 * Serializes the parsed claims into the fixed-size mdoc-style byte layout
 * (inspired by ISO/IEC 18013-5 IssuerSignedItem — NOT a standards-compliant
 * mdoc, just the data layout) and applies the disclosure mask:
 *
 *   message := nsLen(1) || namespace || nFields(1) || item[0] .. item[nFields-1]
 *   item[i] := digestID(1)=i || disclosed(1)=mask[i] || random(16)
 *              || valMajor(1) || idLen(1) || elementIdentifier(maxKeyLen)
 *              || valLen(1)   || elementValue(maxValueLen)
 *
 * mask[i] = 1 -> item i is disclosed: valMajor/valLen/elementValue/random are
 *                byte-per-byte the parsed CWT data (values zero-padded).
 * mask[i] = 0 -> item i is redacted: valMajor/valLen/elementValue/random are
 *                all set to `placeholder`. elementIdentifier and idLen stay
 *                visible in both cases (attribute *names* are public).
 *
 * `placeholder` is a CONFIGURABLE template parameter; the project default is
 * 0x00 (see cbor_redact_verify.DESIGN.md §3.1).
 */
template MdocRedact(nFields, maxKeyLen, maxValueLen, nsLen, placeholder) {
    assert(placeholder >= 0 && placeholder <= 255);
    var itemLen = 21 + maxKeyLen + maxValueLen;
    var messageLen = 2 + nsLen + nFields * itemLen;

    signal input mask[nFields];
    signal input keyLen[nFields];
    signal input valLen[nFields];
    signal input valMajor[nFields];
    signal input keyBytes[nFields][maxKeyLen];
    signal input valBytes[nFields][maxValueLen];
    signal input itemRandom[nFields][16];
    signal input namespace[nsLen];

    signal output message[messageLen];

    message[0] <== nsLen;
    for (var j = 0; j < nsLen; j++) message[1 + j] <== namespace[j];
    message[1 + nsLen] <== nFields;

    for (var i = 0; i < nFields; i++) {
        mask[i] * (mask[i] - 1) === 0;
        var base = 2 + nsLen + i * itemLen;
        message[base] <== i;            // digestID
        message[base + 1] <== mask[i];  // disclosed flag
        for (var j = 0; j < 16; j++) {  // per-element random salt
            message[base + 2 + j] <== placeholder + mask[i] * (itemRandom[i][j] - placeholder);
        }
        message[base + 18] <== placeholder + mask[i] * (valMajor[i] - placeholder);
        message[base + 19] <== keyLen[i]; // idLen: identifiers stay visible
        for (var j = 0; j < maxKeyLen; j++) {
            message[base + 20 + j] <== keyBytes[i][j];
        }
        message[base + 20 + maxKeyLen] <== placeholder + mask[i] * (valLen[i] - placeholder);
        for (var j = 0; j < maxValueLen; j++) {
            message[base + 21 + maxKeyLen + j] <== placeholder + mask[i] * (valBytes[i][j] - placeholder);
        }
    }
}

/**
 * Full credential-redaction circuit:
 *   1) rebuilds the COSE_Sign1 ToBeSigned bytes and hashes them (Sha256Bytes);
 *   2) verifies the issuer RSA-PSS signature by re-encoding EMSA-PSS with the
 *      witnessed salt (EMSA_PSS_Encode + MGF1, reused from rsa_blind.circom)
 *      and comparing byte-per-byte against issuerSig^e mod n (PowerMod);
 *   3) parses the CWT claims map (CborMapVerify);
 *   4) emits the mdoc-style message with placeholder redaction (MdocRedact).
 *
 * The output `message` is meant to be fed unchanged as the `message` input of
 * Sha256BlindRSAPSS(w, k, eBits, mgfCount, messageLen) in hash_and_blind.circom,
 * with messageLen = 2 + nsLen + nFields * (21 + maxKeyLen + maxValueLen).
 *
 * Repo bigint conventions: w = 64, k = 32 (RSA-2048), eBits = 17 (e = 65537),
 * mgfCount = 7 (emBytes = 256, SHA-256, 32-byte salt).
 */
template CborRedactVerify(w, k, eBits, mgfCount, payloadLen, protLen, nFields, maxKeyLen, maxValueLen, nsLen, placeholder) {
    var bpl = w / 8;
    var emBytes = k * bpl;
    var itemLen = 21 + maxKeyLen + maxValueLen;
    var messageLen = 2 + nsLen + nFields * itemLen;
    var tbsLen = 12 + cborBstrHdrLen(protLen) + protLen + 1 + cborBstrHdrLen(payloadLen) + payloadLen;

    signal input payload[payloadLen];       // CWT claims payload (private)
    signal input prot[protLen];             // COSE protected header bytes, e.g. A1013824 = {1: -37 (PS256)}
    signal input issuerSig[k];              // issuer signature (bigint limbs, private)
    signal input issuerPssSalt[32];         // PSS salt recovered from the signature (private)
    signal input issuerExp[k];              // issuer public exponent (bigint limbs)
    signal input issuerModulus[k];          // issuer RSA modulus (bigint limbs)
    signal input mask[nFields];             // disclosure mask (public): 1 = disclose, 0 = redact
    signal input keyLen[nFields];           // CBOR parse witnesses (private)
    signal input valLen[nFields];
    signal input valMajor[nFields];
    signal input itemRandom[nFields][16];   // per-element mdoc salts (private)
    signal input namespace[nsLen];          // mdoc-style namespace, e.g. "org.iso.18013.5.1.acts"

    signal output message[messageLen];      // mdoc-style serialization, ready for Sha256BlindRSAPSS

    // 1) ToBeSigned = Sig_structure(prot, payload), then mHash = SHA-256(ToBeSigned)
    component tbs = CoseSign1TBS(payloadLen, protLen);
    for (var j = 0; j < protLen; j++) tbs.prot[j] <== prot[j];
    for (var j = 0; j < payloadLen; j++) tbs.payload[j] <== payload[j];

    component hasher = Sha256Bytes(tbsLen);
    for (var j = 0; j < tbsLen; j++) hasher.in[j] <== tbs.tbs[j];

    // 2) EMSA-PSS re-encoding with the witnessed salt; equality with
    //    issuerSig^e mod n is equivalent to EMSA-PSS-Verify.
    component enc = EMSA_PSS_Encode(emBytes, 32, 32, mgfCount);
    for (var j = 0; j < 32; j++) enc.hashed[j] <== hasher.out[j];
    for (var j = 0; j < 32; j++) enc.salt[j] <== issuerPssSalt[j];

    component pm = PowerMod(w, k, eBits);
    for (var i = 0; i < k; i++) {
        pm.base[i] <== issuerSig[i];
        pm.exp[i] <== issuerExp[i];
        pm.modulus[i] <== issuerModulus[i];
    }

    component sigBytes = BigIntI2OSP(k, bpl);
    for (var i = 0; i < k; i++) sigBytes.in[i] <== pm.out[i];
    for (var j = 0; j < emBytes; j++) sigBytes.out[j] === enc.EM[j];

    // 3) minimal CBOR parse of the claims map
    component parser = CborMapVerify(payloadLen, nFields, maxKeyLen, maxValueLen);
    for (var j = 0; j < payloadLen; j++) parser.payload[j] <== payload[j];
    for (var i = 0; i < nFields; i++) {
        parser.keyLen[i] <== keyLen[i];
        parser.valLen[i] <== valLen[i];
        parser.valMajor[i] <== valMajor[i];
    }

    // 4) mdoc-style serialization with placeholder redaction
    component mdoc = MdocRedact(nFields, maxKeyLen, maxValueLen, nsLen, placeholder);
    for (var i = 0; i < nFields; i++) {
        mdoc.mask[i] <== mask[i];
        mdoc.keyLen[i] <== keyLen[i];
        mdoc.valLen[i] <== valLen[i];
        mdoc.valMajor[i] <== valMajor[i];
        for (var j = 0; j < maxKeyLen; j++) mdoc.keyBytes[i][j] <== parser.keyBytes[i][j];
        for (var j = 0; j < maxValueLen; j++) mdoc.valBytes[i][j] <== parser.valBytes[i][j];
        for (var j = 0; j < 16; j++) mdoc.itemRandom[i][j] <== itemRandom[i][j];
    }
    for (var j = 0; j < nsLen; j++) mdoc.namespace[j] <== namespace[j];
    for (var j = 0; j < messageLen; j++) message[j] <== mdoc.message[j];
}

/**
 * Parser + redaction only (no issuer-signature check): used by the unit test
 * in unit_test/cbor to validate the CBOR parse and the mdoc layout against a
 * Python reference without paying for SHA-256/PowerMod at compile time.
 */
template CborRedactNoSig(payloadLen, nFields, maxKeyLen, maxValueLen, nsLen, placeholder) {
    var itemLen = 21 + maxKeyLen + maxValueLen;
    var messageLen = 2 + nsLen + nFields * itemLen;

    signal input payload[payloadLen];
    signal input mask[nFields];
    signal input keyLen[nFields];
    signal input valLen[nFields];
    signal input valMajor[nFields];
    signal input itemRandom[nFields][16];
    signal input namespace[nsLen];

    signal output message[messageLen];

    component parser = CborMapVerify(payloadLen, nFields, maxKeyLen, maxValueLen);
    for (var j = 0; j < payloadLen; j++) parser.payload[j] <== payload[j];
    for (var i = 0; i < nFields; i++) {
        parser.keyLen[i] <== keyLen[i];
        parser.valLen[i] <== valLen[i];
        parser.valMajor[i] <== valMajor[i];
    }

    component mdoc = MdocRedact(nFields, maxKeyLen, maxValueLen, nsLen, placeholder);
    for (var i = 0; i < nFields; i++) {
        mdoc.mask[i] <== mask[i];
        mdoc.keyLen[i] <== keyLen[i];
        mdoc.valLen[i] <== valLen[i];
        mdoc.valMajor[i] <== valMajor[i];
        for (var j = 0; j < maxKeyLen; j++) mdoc.keyBytes[i][j] <== parser.keyBytes[i][j];
        for (var j = 0; j < maxValueLen; j++) mdoc.valBytes[i][j] <== parser.valBytes[i][j];
        for (var j = 0; j < 16; j++) mdoc.itemRandom[i][j] <== itemRandom[i][j];
    }
    for (var j = 0; j < nsLen; j++) mdoc.namespace[j] <== namespace[j];
    for (var j = 0; j < messageLen; j++) message[j] <== mdoc.message[j];
}
