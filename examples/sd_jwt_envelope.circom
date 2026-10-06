pragma circom 2.0.3;

include "node_modules/circomlib/circuits/comparators.circom";
include "node_modules/circomlib/circuits/bitify.circom";

/*
 * SD-JWT envelope (design: sd_jwt.DESIGN.md, steps 4-5).
 *
 * Takes the nFields in-circuit salted digests and assembles the JWS signing
 * input of an SD-JWT whose payload is
 *
 *     {"_sd":["<b64url(digest_0)>", ...],"_sd_alg":"sha-256"}
 *
 * i.e.  ASCII( b64url(header) || "." || b64url(payload) ).
 *
 * This is the exact message that Sha256BlindRSAPSS then hashes, PSS-encodes
 * and blinds, so the unblinded notary signature is directly the JWS (PS256)
 * signature of the SD-JWT. Pure byte-plumbing: base64url is a fixed 6-bit
 * lookup, no new cryptography.
 */

// unpadded base64url output length
function b64Len(n) {
    var r = n % 3;
    return 4 * (n \ 3) + (r == 2 ? 3 : (r == 1 ? 2 : 0));
}

// ASCII char for one 6-bit value, base64url alphabet (A-Za-z0-9-_)
template B64Char() {
    signal input in;   // 0..63 (guaranteed by construction from 6 bits)
    signal output out;

    component lt26 = LessThan(6);
    lt26.in[0] <== in;  lt26.in[1] <== 26;
    component lt52 = LessThan(6);
    lt52.in[0] <== in;  lt52.in[1] <== 52;
    component lt62 = LessThan(6);
    lt62.in[0] <== in;  lt62.in[1] <== 62;
    component eq62 = IsEqual();
    eq62.in[0] <== in;  eq62.in[1] <== 62;

    // ranges: [0,26) -> 'A'+v, [26,52) -> 'a'+v-26, [52,62) -> '0'+v-52,
    //         62 -> '-', 63 -> '_'
    signal selUpper <== lt26.out;
    signal selLower <== lt52.out - lt26.out;
    signal selDigit <== lt62.out - lt52.out;
    signal selDash  <== eq62.out;
    signal selUnder <== 1 - lt62.out - eq62.out;

    signal tUpper <== selUpper * (in + 65);
    signal tLower <== selLower * (in + 71);
    signal tDigit <== selDigit * (in - 4);
    out <== tUpper + tLower + tDigit + selDash * 45 + selUnder * 95;
}

// unpadded base64url of nBytes input bytes
template Base64UrlEncode(nBytes) {
    var full = nBytes \ 3;
    var rem = nBytes % 3;
    var outLen = b64Len(nBytes);

    signal input in[nBytes];
    signal output out[outLen];

    component bits[nBytes];
    for (var i = 0; i < nBytes; i++) {
        bits[i] = Num2Bits(8);
        bits[i].in <== in[i];
    }

    component ch[outLen];
    for (var c = 0; c < outLen; c++) ch[c] = B64Char();

    for (var g = 0; g < full; g++) {
        var b0 = 3 * g; var b1 = 3 * g + 1; var b2 = 3 * g + 2;
        // v0 = b0 >> 2
        ch[4*g].in     <== bits[b0].out[7]*32 + bits[b0].out[6]*16 + bits[b0].out[5]*8
                         + bits[b0].out[4]*4  + bits[b0].out[3]*2  + bits[b0].out[2];
        // v1 = (b0 & 3) << 4 | b1 >> 4
        ch[4*g + 1].in <== bits[b0].out[1]*32 + bits[b0].out[0]*16
                         + bits[b1].out[7]*8  + bits[b1].out[6]*4
                         + bits[b1].out[5]*2  + bits[b1].out[4];
        // v2 = (b1 & 15) << 2 | b2 >> 6
        ch[4*g + 2].in <== bits[b1].out[3]*32 + bits[b1].out[2]*16
                         + bits[b1].out[1]*8  + bits[b1].out[0]*4
                         + bits[b2].out[7]*2  + bits[b2].out[6];
        // v3 = b2 & 63
        ch[4*g + 3].in <== bits[b2].out[5]*32 + bits[b2].out[4]*16 + bits[b2].out[3]*8
                         + bits[b2].out[2]*4  + bits[b2].out[1]*2  + bits[b2].out[0];
    }
    if (rem == 2) {
        var b0 = 3 * full; var b1 = 3 * full + 1;
        ch[4*full].in     <== bits[b0].out[7]*32 + bits[b0].out[6]*16 + bits[b0].out[5]*8
                            + bits[b0].out[4]*4  + bits[b0].out[3]*2  + bits[b0].out[2];
        ch[4*full + 1].in <== bits[b0].out[1]*32 + bits[b0].out[0]*16
                            + bits[b1].out[7]*8  + bits[b1].out[6]*4
                            + bits[b1].out[5]*2  + bits[b1].out[4];
        ch[4*full + 2].in <== bits[b1].out[3]*32 + bits[b1].out[2]*16
                            + bits[b1].out[1]*8  + bits[b1].out[0]*4;
    }
    if (rem == 1) {
        var b0 = 3 * full;
        ch[4*full].in     <== bits[b0].out[7]*32 + bits[b0].out[6]*16 + bits[b0].out[5]*8
                            + bits[b0].out[4]*4  + bits[b0].out[3]*2  + bits[b0].out[2];
        ch[4*full + 1].in <== bits[b0].out[1]*32 + bits[b0].out[0]*16;
    }

    for (var c = 0; c < outLen; c++) out[c] <== ch[c].out;
}

// payload byte length for nFields 43-char digests:
// {"_sd":[  +  nFields * ("<43>") + (nFields-1) commas  +  ],"_sd_alg":"sha-256"}
function sdJwtPayloadLen(nFields) {
    return 8 + 45 * nFields + (nFields - 1) + 22;
}

function sdJwtSigningInputLen(nFields, hdrLen) {
    return hdrLen + 1 + b64Len(sdJwtPayloadLen(nFields));
}

/*
 * Assemble the SD-JWT JWS signing input from the salted digests.
 * hdrB64 is the (constant, public by construction) unpadded base64url of the
 * protected header JSON; the top-level template wires compile-time constants
 * into it.
 */
template SdJwtSigningInput(nFields, hdrLen) {
    var payloadLen = sdJwtPayloadLen(nFields);
    var payB64Len = b64Len(payloadLen);
    var outLen = sdJwtSigningInputLen(nFields, hdrLen);

    signal input digest[nFields][32];
    signal input hdrB64[hdrLen];
    signal output out[outLen];

    // {"_sd":[
    var PRE[8] = [123, 34, 95, 115, 100, 34, 58, 91];
    // ],"_sd_alg":"sha-256"}
    var SUF[22] = [93, 44, 34, 95, 115, 100, 95, 97, 108, 103, 34, 58,
                   34, 115, 104, 97, 45, 50, 53, 54, 34, 125];

    // 1) base64url of each digest (32 bytes -> 43 chars)
    component db64[nFields];
    for (var i = 0; i < nFields; i++) {
        db64[i] = Base64UrlEncode(32);
        for (var j = 0; j < 32; j++) db64[i].in[j] <== digest[i][j];
    }

    // 2) splice into the payload skeleton
    signal payload[payloadLen];
    var p = 0;
    for (var j = 0; j < 8; j++) { payload[p] <== PRE[j]; p++; }
    for (var i = 0; i < nFields; i++) {
        payload[p] <== 34; p++;                                   // '"'
        for (var j = 0; j < 43; j++) { payload[p] <== db64[i].out[j]; p++; }
        payload[p] <== 34; p++;                                   // '"'
        if (i < nFields - 1) { payload[p] <== 44; p++; }          // ','
    }
    for (var j = 0; j < 22; j++) { payload[p] <== SUF[j]; p++; }
    assert(p == payloadLen);

    // 3) signing input = hdrB64 || '.' || b64url(payload)
    component pb64 = Base64UrlEncode(payloadLen);
    for (var j = 0; j < payloadLen; j++) pb64.in[j] <== payload[j];

    for (var j = 0; j < hdrLen; j++) out[j] <== hdrB64[j];
    out[hdrLen] <== 46;                                           // '.'
    for (var j = 0; j < payB64Len; j++) out[hdrLen + 1 + j] <== pb64.out[j];
}
