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
 * The caller must guarantee shift <= n (here shifts are item offsets that the
 * tree constraints bound by the payload length).
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
 * Selects the row `idx` of the CBOR item table (see CborTreeVerify) and
 * exposes its columns. Also constrains that exactly one row matches and that
 * the selected row is an active item.
 */
template ItemRead(maxItems) {
    signal input idx;
    signal input act[maxItems];
    signal input off[maxItems];
    signal input end[maxItems];
    signal input parent[maxItems];
    signal input childIdx[maxItems];
    signal input major[maxItems];
    signal input arg[maxItems];

    signal output oOff;
    signal output oEnd;
    signal output oParent;
    signal output oChildIdx;
    signal output oMajor;
    signal output oArg;

    component eq[maxItems];
    signal pAct[maxItems];
    signal pOff[maxItems];
    signal pEnd[maxItems];
    signal pParent[maxItems];
    signal pChildIdx[maxItems];
    signal pMajor[maxItems];
    signal pArg[maxItems];

    var sumEq = 0;
    var sAct = 0;
    var sOff = 0;
    var sEnd = 0;
    var sParent = 0;
    var sChildIdx = 0;
    var sMajor = 0;
    var sArg = 0;
    for (var t = 0; t < maxItems; t++) {
        eq[t] = IsEqual();
        eq[t].in[0] <== idx;
        eq[t].in[1] <== t;
        pAct[t] <== eq[t].out * act[t];
        pOff[t] <== eq[t].out * off[t];
        pEnd[t] <== eq[t].out * end[t];
        pParent[t] <== eq[t].out * parent[t];
        pChildIdx[t] <== eq[t].out * childIdx[t];
        pMajor[t] <== eq[t].out * major[t];
        pArg[t] <== eq[t].out * arg[t];
        sumEq += eq[t].out;
        sAct += pAct[t];
        sOff += pOff[t];
        sEnd += pEnd[t];
        sParent += pParent[t];
        sChildIdx += pChildIdx[t];
        sMajor += pMajor[t];
        sArg += pArg[t];
    }
    sumEq === 1;   // idx in range
    sAct === 1;    // selected item is active
    oOff <== sOff;
    oEnd <== sEnd;
    oParent <== sParent;
    oChildIdx <== sChildIdx;
    oMajor <== sMajor;
    oArg <== sArg;
}

/**
 * Verified parse tree of a canonical CBOR payload (RFC 8949 subset: major
 * types 0-5, definite lengths, additional info <= 26, i.e. args < 2^32).
 *
 * The prover supplies the full item table in document (pre-order) order:
 *   off / major / arg / hdrLen / end / parent / childIdx  per item
 * and the circuit checks it is THE unique decomposition of the payload:
 *   - each item's head bytes encode (major, arg) with the minimal-length
 *     (canonical) form, matching the witnessed hdrLen;
 *   - offsets are strictly increasing (document order, distinct items);
 *   - leaf spans are head-determined (ints: hdrLen; strings: hdrLen + arg);
 *   - every container's children tile its content region exactly: child 0
 *     starts right after the container head, child i+1 starts where child i
 *     ends, the last child ends where the container ends, and the number of
 *     children equals the head count (2*arg for maps, arg for arrays);
 *   - the root (item 0) is a map at offset 0 spanning the whole payload.
 * Together these force complete, gap-free, unambiguous coverage: no byte of
 * the payload can be re-interpreted or skipped by a malicious prover.
 *
 * On top of the tree, a *path* of map keys (public: raw CBOR key bytes per
 * hop) selects the subject map (path [] = the root, e.g. a flat CWT claims
 * map; path [-260, 1] = the hcert/eu_dgc_v1 map of an EU Digital COVID
 * Certificate). The subject map must have exactly nFields entries; their key
 * and value items are exposed as raw CBOR byte strings (head included, so
 * values may be whole nested subtrees) for the redaction stage.
 *
 * NOTE: payload bytes are NOT range-checked to 8 bits here; in the full
 * circuit they flow into Sha256Bytes, which bit-decomposes every byte.
 */
template CborTreeVerify(payloadLen, maxItems, nFields, maxKeyLen, maxValueLen, pathDepth, maxPathKeyLen) {
    assert(maxItems >= 1 + 2 * nFields);
    assert(maxItems < 256);
    assert(nFields > 0 && nFields < 128);
    assert(maxKeyLen >= 1 && maxKeyLen <= 255);
    assert(maxValueLen >= 1 && maxValueLen <= 255);
    var pdN = pathDepth < 1 ? 1 : pathDepth;   // avoid zero-size arrays

    signal input payload[payloadLen];

    // --- item table (witness) ---
    signal input nItems;
    signal input itemOff[maxItems];
    signal input itemMajor[maxItems];
    signal input itemArg[maxItems];
    signal input itemHdrLen[maxItems];
    signal input itemParent[maxItems];
    signal input itemChildIdx[maxItems];
    signal input itemEnd[maxItems];

    // --- path to the subject map (public) and its witness item indices ---
    signal input pathKeyLen[pdN];              // raw CBOR length of each hop key
    signal input pathKey[pdN][maxPathKeyLen];  // raw CBOR bytes of each hop key
    signal input pathKeyItem[pdN];             // witness: key item of each hop
    signal input pathValItem[pdN];             // witness: value item of each hop

    // --- subject map entries (witness item indices) ---
    signal input entryKey[nFields];
    signal input entryVal[nFields];

    // --- outputs: raw CBOR bytes of each entry's key and value ---
    signal output keyRaw[nFields][maxKeyLen];
    signal output keyRawLen[nFields];
    signal output valRaw[nFields][maxValueLen];
    signal output valRawLen[nFields];

    var t;
    var c;
    var u;
    var j;

    // ================= per-item bounds and activity =================
    component nItemsBits = Num2Bits(8);
    nItemsBits.in <== nItems;
    component nItemsMax = LessEqThan(8);
    nItemsMax.in[0] <== nItems;
    nItemsMax.in[1] <== maxItems;
    nItemsMax.out === 1;

    signal act[maxItems];
    component actC[maxItems];
    component offBits[maxItems];
    component endBits[maxItems];
    component cIdxBits[maxItems];
    component argBits[maxItems];
    signal argByte[maxItems][4];
    component argByteB[maxItems][4];

    for (t = 0; t < maxItems; t++) {
        actC[t] = LessThan(8);
        actC[t].in[0] <== t;
        actC[t].in[1] <== nItems;
        act[t] <== actC[t].out;

        offBits[t] = Num2Bits(16);
        offBits[t].in <== itemOff[t];
        endBits[t] = Num2Bits(16);
        endBits[t].in <== itemEnd[t];
        cIdxBits[t] = Num2Bits(16);
        cIdxBits[t].in <== itemChildIdx[t];
        argBits[t] = Num2Bits(32);
        argBits[t].in <== itemArg[t];
        for (j = 0; j < 4; j++) {
            argByteB[t][j] = Bits2Num(8);
            for (var b = 0; b < 8; b++) argByteB[t][j].in[b] <== argBits[t].out[j * 8 + b];
            argByte[t][j] <== argByteB[t][j].out;
        }

        // padding rows are forced to all-zero so they stay out of every sum
        (1 - act[t]) * itemOff[t] === 0;
        (1 - act[t]) * itemEnd[t] === 0;
        (1 - act[t]) * itemMajor[t] === 0;
        (1 - act[t]) * itemArg[t] === 0;
        (1 - act[t]) * itemHdrLen[t] === 0;
        (1 - act[t]) * itemParent[t] === 0;
        (1 - act[t]) * itemChildIdx[t] === 0;
    }

    // ================= head decoding (canonical forms) =================
    component headW[maxItems];
    component isH1[maxItems];
    component isH2[maxItems];
    component isH3[maxItems];
    component isH5[maxItems];
    component isMj[maxItems][6];
    component lt24[maxItems];
    component lt256[maxItems];
    component lt65536[maxItems];
    signal ah1[maxItems];
    signal ah2[maxItems];
    signal ah3[maxItems];
    signal ah5[maxItems];
    signal selArg[maxItems];
    signal isString[maxItems];
    signal isCont[maxItems];
    signal contAct[maxItems];
    signal expCh[maxItems];
    signal strAdd[maxItems];
    signal notContAct[maxItems];
    component isEmptyArg[maxItems];
    signal emptyCont[maxItems];

    for (t = 0; t < maxItems; t++) {
        headW[t] = VarShiftLeft(payloadLen, 5);
        for (j = 0; j < payloadLen; j++) headW[t].in[j] <== payload[j];
        headW[t].shift <== itemOff[t];

        isH1[t] = IsEqual();
        isH1[t].in[0] <== itemHdrLen[t];
        isH1[t].in[1] <== 1;
        isH2[t] = IsEqual();
        isH2[t].in[0] <== itemHdrLen[t];
        isH2[t].in[1] <== 2;
        isH3[t] = IsEqual();
        isH3[t].in[0] <== itemHdrLen[t];
        isH3[t].in[1] <== 3;
        isH5[t] = IsEqual();
        isH5[t].in[0] <== itemHdrLen[t];
        isH5[t].in[1] <== 5;
        act[t] * (isH1[t].out + isH2[t].out + isH3[t].out + isH5[t].out - 1) === 0;

        ah1[t] <== act[t] * isH1[t].out;
        ah2[t] <== act[t] * isH2[t].out;
        ah3[t] <== act[t] * isH3[t].out;
        ah5[t] <== act[t] * isH5[t].out;

        // major type flags; exactly one of 0..5 (bans tags/floats)
        var mjSum = 0;
        for (j = 0; j < 6; j++) {
            isMj[t][j] = IsEqual();
            isMj[t][j].in[0] <== itemMajor[t];
            isMj[t][j].in[1] <== j;
            mjSum += isMj[t][j].out;
        }
        act[t] * (mjSum - 1) === 0;

        // head byte 0: major*32 + (arg | 24 | 25 | 26)
        selArg[t] <== isH1[t].out * itemArg[t];
        act[t] * (headW[t].out[0] - itemMajor[t] * 32 - selArg[t] - isH2[t].out * 24 - isH3[t].out * 25 - isH5[t].out * 26) === 0;

        // extended argument bytes (big-endian) and canonical minimality
        lt24[t] = LessThan(32);
        lt24[t].in[0] <== itemArg[t];
        lt24[t].in[1] <== 24;
        lt256[t] = LessThan(32);
        lt256[t].in[0] <== itemArg[t];
        lt256[t].in[1] <== 256;
        lt65536[t] = LessThan(32);
        lt65536[t].in[0] <== itemArg[t];
        lt65536[t].in[1] <== 65536;

        ah1[t] * (1 - lt24[t].out) === 0;
        ah2[t] * (headW[t].out[1] - itemArg[t]) === 0;
        ah2[t] * lt24[t].out === 0;
        ah3[t] * (headW[t].out[1] - argByte[t][1]) === 0;
        ah3[t] * (headW[t].out[2] - argByte[t][0]) === 0;
        ah3[t] * argByte[t][2] === 0;
        ah3[t] * argByte[t][3] === 0;
        ah3[t] * lt256[t].out === 0;
        ah5[t] * (headW[t].out[1] - argByte[t][3]) === 0;
        ah5[t] * (headW[t].out[2] - argByte[t][2]) === 0;
        ah5[t] * (headW[t].out[3] - argByte[t][1]) === 0;
        ah5[t] * (headW[t].out[4] - argByte[t][0]) === 0;
        ah5[t] * lt65536[t].out === 0;

        // type classes and head-determined spans
        isString[t] <== isMj[t][2].out + isMj[t][3].out;
        isCont[t] <== isMj[t][4].out + isMj[t][5].out;
        contAct[t] <== act[t] * isCont[t];
        expCh[t] <== itemArg[t] + isMj[t][5].out * itemArg[t]; // maps: 2*arg children
        strAdd[t] <== isString[t] * itemArg[t];
        notContAct[t] <== act[t] * (1 - isCont[t]);
        notContAct[t] * (itemEnd[t] - itemOff[t] - itemHdrLen[t] - strAdd[t]) === 0;
        isEmptyArg[t] = IsZero();
        isEmptyArg[t].in <== itemArg[t];
        emptyCont[t] <== contAct[t] * isEmptyArg[t].out;
        emptyCont[t] * (itemEnd[t] - itemOff[t] - itemHdrLen[t]) === 0;
    }

    // ================= document order and root =================
    component ordC[maxItems];
    for (t = 1; t < maxItems; t++) {
        ordC[t] = LessThan(16);
        ordC[t].in[0] <== itemOff[t - 1];
        ordC[t].in[1] <== itemOff[t];
        act[t] * (1 - ordC[t].out) === 0;
    }
    // root: item 0 is an active map at offset 0 covering the whole payload.
    // Its parent is the out-of-range sentinel maxItems, so the root never
    // matches any parent column and never counts as a child or a sibling.
    act[0] === 1;
    itemOff[0] === 0;
    itemParent[0] === maxItems;
    itemChildIdx[0] === 0;
    itemMajor[0] === 5;
    itemEnd[0] === payloadLen;

    // ================= parent relation =================
    component eP[maxItems][maxItems];   // eP[t][c] = (parent[t] == c)
    signal ae[maxItems][maxItems];
    signal pcOff[maxItems][maxItems];
    signal pcHdr[maxItems][maxItems];
    signal pcEnd[maxItems][maxItems];
    signal pcExp[maxItems][maxItems];
    signal pcCA[maxItems][maxItems];
    signal parOff[maxItems];
    signal parHdr[maxItems];
    signal parEnd[maxItems];
    signal parExpCh[maxItems];
    signal parContA[maxItems];
    signal chCntRhs[maxItems];

    for (t = 0; t < maxItems; t++) {
        var sEq = 0;
        var sO = 0;
        var sH = 0;
        var sE = 0;
        var sX = 0;
        var sC = 0;
        for (c = 0; c < maxItems; c++) {
            eP[t][c] = IsEqual();
            eP[t][c].in[0] <== itemParent[t];
            eP[t][c].in[1] <== c;
            ae[t][c] <== act[t] * eP[t][c].out;
            pcOff[t][c] <== eP[t][c].out * itemOff[c];
            pcHdr[t][c] <== eP[t][c].out * itemHdrLen[c];
            pcEnd[t][c] <== eP[t][c].out * itemEnd[c];
            pcExp[t][c] <== eP[t][c].out * expCh[c];
            pcCA[t][c] <== eP[t][c].out * contAct[c];
            sEq += eP[t][c].out;
            sO += pcOff[t][c];
            sH += pcHdr[t][c];
            sE += pcEnd[t][c];
            sX += pcExp[t][c];
            sC += pcCA[t][c];
        }
        if (t > 0) {
            sEq === 1;           // parent index in range (root uses the sentinel)
        }
        parOff[t] <== sO;
        parHdr[t] <== sH;
        parEnd[t] <== sE;
        parExpCh[t] <== sX;
        parContA[t] <== sC;
        if (t > 0) {
            // every active non-root item hangs off an active container
            act[t] * (1 - parContA[t]) === 0;
        }
    }

    // child count: for each container, #children == 2*arg (map) / arg (array)
    for (c = 0; c < maxItems; c++) {
        var sCh = 0;
        for (t = 1; t < maxItems; t++) sCh += ae[t][c];
        chCntRhs[c] <== contAct[c] * expCh[c];
        sCh === chCntRhs[c];
    }

    // ================= sibling adjacency (container tiling) =================
    component eSibP[maxItems][maxItems];
    component eSibD[maxItems][maxItems];
    signal sib[maxItems][maxItems];
    signal sibA[maxItems][maxItems];
    signal sibEnd[maxItems][maxItems];
    component isFirstC[maxItems];
    component isLastC[maxItems];
    component ltCIC[maxItems];
    signal aFirst[maxItems];
    signal aNotFirst[maxItems];
    signal aLast[maxItems];

    for (t = 1; t < maxItems; t++) {
        var sSib = 0;
        var sPE = 0;
        for (u = 0; u < maxItems; u++) {
            eSibP[t][u] = IsEqual();
            eSibP[t][u].in[0] <== itemParent[t];
            eSibP[t][u].in[1] <== itemParent[u];
            eSibD[t][u] = IsEqual();
            eSibD[t][u].in[0] <== itemChildIdx[t] - itemChildIdx[u];
            eSibD[t][u].in[1] <== 1;
            sib[t][u] <== eSibP[t][u].out * eSibD[t][u].out;
            sibA[t][u] <== sib[t][u] * act[u];
            sibEnd[t][u] <== sibA[t][u] * itemEnd[u];
            // the root's sentinel parent keeps it out of every sibling match
            sSib += sibA[t][u];
            sPE += sibEnd[t][u];
        }

        isFirstC[t] = IsZero();
        isFirstC[t].in <== itemChildIdx[t];
        aFirst[t] <== act[t] * isFirstC[t].out;
        aNotFirst[t] <== act[t] * (1 - isFirstC[t].out);

        // first child starts right after the parent head
        aFirst[t] * (itemOff[t] - parOff[t] - parHdr[t]) === 0;
        // child i+1 starts exactly where its unique predecessor sibling ends
        sSib === aNotFirst[t];
        aNotFirst[t] * (itemOff[t] - sPE) === 0;

        // last child ends where the parent ends
        isLastC[t] = IsEqual();
        isLastC[t].in[0] <== itemChildIdx[t] + 1;
        isLastC[t].in[1] <== parExpCh[t];
        aLast[t] <== act[t] * isLastC[t].out;
        aLast[t] * (itemEnd[t] - parEnd[t]) === 0;

        // childIdx < expected child count of the parent
        ltCIC[t] = LessThan(34);
        ltCIC[t].in[0] <== itemChildIdx[t];
        ltCIC[t].in[1] <== parExpCh[t] + (1 - act[t]);
        act[t] * (1 - ltCIC[t].out) === 0;
    }

    // ================= path to the subject map =================
    signal subj;
    component prK[pdN];
    component prV[pdN];
    component prKParity[pdN];
    component pkShift[pdN];
    component pkInRange[pdN][maxPathKeyLen];
    component prKNotC4[pdN];
    component prKNotC5[pdN];

    for (var h = 0; h < pdN; h++) {
        prK[h] = ItemRead(maxItems);
        prV[h] = ItemRead(maxItems);
        for (t = 0; t < maxItems; t++) {
            prK[h].act[t] <== act[t];
            prK[h].off[t] <== itemOff[t];
            prK[h].end[t] <== itemEnd[t];
            prK[h].parent[t] <== itemParent[t];
            prK[h].childIdx[t] <== itemChildIdx[t];
            prK[h].major[t] <== itemMajor[t];
            prK[h].arg[t] <== itemArg[t];
            prV[h].act[t] <== act[t];
            prV[h].off[t] <== itemOff[t];
            prV[h].end[t] <== itemEnd[t];
            prV[h].parent[t] <== itemParent[t];
            prV[h].childIdx[t] <== itemChildIdx[t];
            prV[h].major[t] <== itemMajor[t];
            prV[h].arg[t] <== itemArg[t];
        }
        prK[h].idx <== pathKeyItem[h];
        prV[h].idx <== pathValItem[h];

        if (pathDepth > 0) {
            // both hop items are children of the previous hop's value map
            if (h == 0) {
                prK[h].oParent === 0;
                prV[h].oParent === 0;
            } else {
                prK[h].oParent === pathValItem[h - 1];
                prV[h].oParent === pathValItem[h - 1];
            }
            // value item immediately follows its key item among the siblings,
            // and the key sits at an even child index (i.e. it IS a map key)
            prV[h].oChildIdx === prK[h].oChildIdx + 1;
            prKParity[h] = Num2Bits(16);
            prKParity[h].in <== prK[h].oChildIdx;
            prKParity[h].out[0] === 0;
            // intermediate hop values must be maps
            prV[h].oMajor === 5;
            // path keys are leaves
            prKNotC4[h] = IsEqual();
            prKNotC4[h].in[0] <== prK[h].oMajor;
            prKNotC4[h].in[1] <== 4;
            prKNotC5[h] = IsEqual();
            prKNotC5[h].in[0] <== prK[h].oMajor;
            prKNotC5[h].in[1] <== 5;
            prKNotC4[h].out + prKNotC5[h].out === 0;

            // the key's raw CBOR bytes match the public path key
            prK[h].oEnd - prK[h].oOff === pathKeyLen[h];
            pkShift[h] = VarShiftLeft(payloadLen, maxPathKeyLen);
            for (j = 0; j < payloadLen; j++) pkShift[h].in[j] <== payload[j];
            pkShift[h].shift <== prK[h].oOff;
            for (j = 0; j < maxPathKeyLen; j++) {
                pkInRange[h][j] = LessThan(8);
                pkInRange[h][j].in[0] <== j;
                pkInRange[h][j].in[1] <== pathKeyLen[h];
                pkInRange[h][j].out * (pkShift[h].out[j] - pathKey[h][j]) === 0;
            }
        } else {
            // unused dummy hop (pathDepth == 0): pin the inputs
            pathKeyItem[h] === 0;
            pathValItem[h] === 0;
            pathKeyLen[h] === 0;
            for (j = 0; j < maxPathKeyLen; j++) pathKey[h][j] === 0;
        }
    }
    if (pathDepth > 0) {
        subj <== pathValItem[pathDepth - 1];
    } else {
        subj <== 0;
    }

    // subject is a map with exactly nFields entries
    component srd = ItemRead(maxItems);
    for (t = 0; t < maxItems; t++) {
        srd.act[t] <== act[t];
        srd.off[t] <== itemOff[t];
        srd.end[t] <== itemEnd[t];
        srd.parent[t] <== itemParent[t];
        srd.childIdx[t] <== itemChildIdx[t];
        srd.major[t] <== itemMajor[t];
        srd.arg[t] <== itemArg[t];
    }
    srd.idx <== subj;
    srd.oMajor === 5;
    srd.oArg === nFields;

    // ================= subject entries extraction =================
    component erdK[nFields];
    component erdV[nFields];
    component eKNotC4[nFields];
    component eKNotC5[nFields];
    component kLenMax[nFields];
    component vLenMax[nFields];
    component kShift[nFields];
    component vShift[nFields];
    component kInRange[nFields][maxKeyLen];
    component vInRange[nFields][maxValueLen];

    for (var i = 0; i < nFields; i++) {
        erdK[i] = ItemRead(maxItems);
        erdV[i] = ItemRead(maxItems);
        for (t = 0; t < maxItems; t++) {
            erdK[i].act[t] <== act[t];
            erdK[i].off[t] <== itemOff[t];
            erdK[i].end[t] <== itemEnd[t];
            erdK[i].parent[t] <== itemParent[t];
            erdK[i].childIdx[t] <== itemChildIdx[t];
            erdK[i].major[t] <== itemMajor[t];
            erdK[i].arg[t] <== itemArg[t];
            erdV[i].act[t] <== act[t];
            erdV[i].off[t] <== itemOff[t];
            erdV[i].end[t] <== itemEnd[t];
            erdV[i].parent[t] <== itemParent[t];
            erdV[i].childIdx[t] <== itemChildIdx[t];
            erdV[i].major[t] <== itemMajor[t];
            erdV[i].arg[t] <== itemArg[t];
        }
        erdK[i].idx <== entryKey[i];
        erdV[i].idx <== entryVal[i];

        erdK[i].oParent === subj;
        erdV[i].oParent === subj;
        erdK[i].oChildIdx === 2 * i;
        erdV[i].oChildIdx === 2 * i + 1;

        // map keys must be leaves (ints or strings)
        eKNotC4[i] = IsEqual();
        eKNotC4[i].in[0] <== erdK[i].oMajor;
        eKNotC4[i].in[1] <== 4;
        eKNotC5[i] = IsEqual();
        eKNotC5[i].in[0] <== erdK[i].oMajor;
        eKNotC5[i].in[1] <== 5;
        eKNotC4[i].out + eKNotC5[i].out === 0;

        keyRawLen[i] <== erdK[i].oEnd - erdK[i].oOff;
        kLenMax[i] = LessEqThan(16);
        kLenMax[i].in[0] <== keyRawLen[i];
        kLenMax[i].in[1] <== maxKeyLen;
        kLenMax[i].out === 1;
        valRawLen[i] <== erdV[i].oEnd - erdV[i].oOff;
        vLenMax[i] = LessEqThan(16);
        vLenMax[i].in[0] <== valRawLen[i];
        vLenMax[i].in[1] <== maxValueLen;
        vLenMax[i].out === 1;

        kShift[i] = VarShiftLeft(payloadLen, maxKeyLen);
        vShift[i] = VarShiftLeft(payloadLen, maxValueLen);
        for (j = 0; j < payloadLen; j++) {
            kShift[i].in[j] <== payload[j];
            vShift[i].in[j] <== payload[j];
        }
        kShift[i].shift <== erdK[i].oOff;
        vShift[i].shift <== erdV[i].oOff;

        for (j = 0; j < maxKeyLen; j++) {
            kInRange[i][j] = LessThan(16);
            kInRange[i][j].in[0] <== j;
            kInRange[i][j].in[1] <== keyRawLen[i];
            keyRaw[i][j] <== kShift[i].out[j] * kInRange[i][j].out;
        }
        for (j = 0; j < maxValueLen; j++) {
            vInRange[i][j] = LessThan(16);
            vInRange[i][j].in[0] <== j;
            vInRange[i][j].in[1] <== valRawLen[i];
            valRaw[i][j] <== vShift[i].out[j] * vInRange[i][j].out;
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
 * COSE_Sign1 RSA-PSS verification (issuer side):
 *   rebuilds the ToBeSigned bytes (CoseSign1TBS), hashes them (Sha256Bytes),
 *   re-encodes EMSA-PSS with the witnessed salt (EMSA_PSS_Encode + MGF1) and
 *   compares byte-per-byte against sig^e mod n (PowerMod + BigIntI2OSP) —
 *   equivalent to EMSA-PSS-Verify. Works on any COSE_Sign1 with alg PS256
 *   (e.g. real EU Digital COVID Certificates, see unit_test/cose_real).
 */
template CoseSign1Verify(w, k, eBits, mgfCount, payloadLen, protLen) {
    var bpl = w / 8;
    var emBytes = k * bpl;
    var tbsLen = 12 + cborBstrHdrLen(protLen) + protLen + 1 + cborBstrHdrLen(payloadLen) + payloadLen;

    signal input payload[payloadLen];   // CWT claims payload
    signal input prot[protLen];         // COSE protected header bytes
    signal input sig[k];                // issuer signature (bigint limbs)
    signal input pssSalt[32];           // PSS salt recovered from the signature
    signal input exp[k];                // issuer public exponent (bigint limbs)
    signal input modulus[k];            // issuer RSA modulus (bigint limbs)

    signal output mHash[32];            // SHA-256(ToBeSigned)

    component tbs = CoseSign1TBS(payloadLen, protLen);
    for (var j = 0; j < protLen; j++) tbs.prot[j] <== prot[j];
    for (var j = 0; j < payloadLen; j++) tbs.payload[j] <== payload[j];

    component hasher = Sha256Bytes(tbsLen);
    for (var j = 0; j < tbsLen; j++) hasher.in[j] <== tbs.tbs[j];

    component enc = EMSA_PSS_Encode(emBytes, 32, 32, mgfCount);
    for (var j = 0; j < 32; j++) enc.hashed[j] <== hasher.out[j];
    for (var j = 0; j < 32; j++) enc.salt[j] <== pssSalt[j];

    component pm = PowerMod(w, k, eBits);
    for (var i = 0; i < k; i++) {
        pm.base[i] <== sig[i];
        pm.exp[i] <== exp[i];
        pm.modulus[i] <== modulus[i];
    }

    component sigBytes = BigIntI2OSP(k, bpl);
    for (var i = 0; i < k; i++) sigBytes.in[i] <== pm.out[i];
    for (var j = 0; j < emBytes; j++) sigBytes.out[j] === enc.EM[j];

    for (var j = 0; j < 32; j++) mHash[j] <== hasher.out[j];
}

/**
 * MSO-style salted digest list (inspired by the MobileSecurityObject
 * valueDigests of ISO/IEC 18013-5 — NOT a standards-compliant MSO, just the
 * disclosure model): for every entry of the subject map the circuit hashes a
 * fixed-width IssuerSignedItem-like preimage and emits the digest list.
 *
 *   preimage[i] := digestID(1)=i || random(16)
 *                  || idLen(1) || elementIdentifier(maxKeyLen)
 *                  || valLen(1) || elementValue(maxValueLen)
 *   message     := nsLen(1) || namespace || nFields(1)
 *                  || (digestID(1)=i || SHA256(preimage[i]))*   (33 bytes/item)
 *
 * elementIdentifier and elementValue carry the RAW CBOR encoding of the key
 * and value items (head included — so identifiers may be integer keys and
 * values may be whole nested subtrees), zero-padded to their fixed widths.
 *
 * There is NO disclosure mask in the circuit: the digest list commits to ALL
 * entries, and disclosure happens outside by revealing (or not) an item's
 * preimage data (identifier, value, random). The >=16-byte random salt makes
 * each digest a hiding commitment, so undisclosed entries stay secret and
 * the holder can derive many different presentations from one signed list.
 */
template MdocDigest(nFields, maxKeyLen, maxValueLen, nsLen) {
    var preLen = 19 + maxKeyLen + maxValueLen;
    var messageLen = 2 + nsLen + nFields * 33;

    signal input keyRawLen[nFields];
    signal input valRawLen[nFields];
    signal input keyRaw[nFields][maxKeyLen];
    signal input valRaw[nFields][maxValueLen];
    signal input itemRandom[nFields][16];
    signal input namespace[nsLen];

    signal output message[messageLen];

    message[0] <== nsLen;
    for (var j = 0; j < nsLen; j++) message[1 + j] <== namespace[j];
    message[1 + nsLen] <== nFields;

    component dig[nFields];
    for (var i = 0; i < nFields; i++) {
        dig[i] = Sha256Bytes(preLen);
        dig[i].in[0] <== i;                       // digestID
        for (var j = 0; j < 16; j++) dig[i].in[1 + j] <== itemRandom[i][j];
        dig[i].in[17] <== keyRawLen[i];
        for (var j = 0; j < maxKeyLen; j++) dig[i].in[18 + j] <== keyRaw[i][j];
        dig[i].in[18 + maxKeyLen] <== valRawLen[i];
        for (var j = 0; j < maxValueLen; j++) dig[i].in[19 + maxKeyLen + j] <== valRaw[i][j];

        var base = 2 + nsLen + i * 33;
        message[base] <== i;
        for (var j = 0; j < 32; j++) message[base + 1 + j] <== dig[i].out[j];
    }
}

/**
 * Full credential-redaction circuit:
 *   1) verifies the issuer RSA-PSS signature over the COSE_Sign1
 *      Sig_structure (CoseSign1Verify);
 *   2) verifies the prover-supplied CBOR parse tree of the claims payload and
 *      extracts the entries of the subject map selected by the public path
 *      (CborTreeVerify);
 *   3) hashes every subject entry into the MSO-style salted digest list
 *      (MdocDigest) — disclosure happens off-circuit by revealing preimages.
 *
 * The output `message` is meant to be fed unchanged as the `message` input of
 * Sha256BlindRSAPSS(w, k, eBits, mgfCount, messageLen) in hash_and_blind.circom,
 * with messageLen = 2 + nsLen + nFields * 33.
 *
 * Repo bigint conventions: w = 64, k = 32 (RSA-2048), eBits = 17 (e = 65537),
 * mgfCount = 7 (emBytes = 256, SHA-256, 32-byte salt).
 */
template CborRedactVerify(w, k, eBits, mgfCount, payloadLen, protLen, maxItems, nFields, maxKeyLen, maxValueLen, pathDepth, maxPathKeyLen, nsLen) {
    var messageLen = 2 + nsLen + nFields * 33;
    var pdN = pathDepth < 1 ? 1 : pathDepth;

    signal input payload[payloadLen];       // CWT claims payload (private)
    signal input prot[protLen];             // COSE protected header bytes
    signal input issuerSig[k];              // issuer signature (bigint limbs, private)
    signal input issuerPssSalt[32];         // PSS salt recovered from the signature (private)
    signal input issuerExp[k];              // issuer public exponent (bigint limbs)
    signal input issuerModulus[k];          // issuer RSA modulus (bigint limbs)
    signal input itemRandom[nFields][16];   // per-element salts (private, hiding commitments)
    signal input namespace[nsLen];          // mdoc-style namespace, e.g. "org.iso.18013.5.1.acts"

    // CBOR parse-tree witness (see CborTreeVerify)
    signal input nItems;
    signal input itemOff[maxItems];
    signal input itemMajor[maxItems];
    signal input itemArg[maxItems];
    signal input itemHdrLen[maxItems];
    signal input itemParent[maxItems];
    signal input itemChildIdx[maxItems];
    signal input itemEnd[maxItems];
    signal input pathKeyLen[pdN];           // public: path to the subject map
    signal input pathKey[pdN][maxPathKeyLen];
    signal input pathKeyItem[pdN];          // witness: hop item indices
    signal input pathValItem[pdN];
    signal input entryKey[nFields];         // witness: subject entry item indices
    signal input entryVal[nFields];

    signal output message[messageLen];      // mdoc-style serialization, ready for Sha256BlindRSAPSS

    // 1) verify the issuer RSA-PSS signature over the COSE Sig_structure
    component cose = CoseSign1Verify(w, k, eBits, mgfCount, payloadLen, protLen);
    for (var j = 0; j < payloadLen; j++) cose.payload[j] <== payload[j];
    for (var j = 0; j < protLen; j++) cose.prot[j] <== prot[j];
    for (var i = 0; i < k; i++) {
        cose.sig[i] <== issuerSig[i];
        cose.exp[i] <== issuerExp[i];
        cose.modulus[i] <== issuerModulus[i];
    }
    for (var j = 0; j < 32; j++) cose.pssSalt[j] <== issuerPssSalt[j];

    // 2) verified CBOR parse tree + subject extraction
    component parser = CborTreeVerify(payloadLen, maxItems, nFields, maxKeyLen, maxValueLen, pathDepth, maxPathKeyLen);
    for (var j = 0; j < payloadLen; j++) parser.payload[j] <== payload[j];
    parser.nItems <== nItems;
    for (var t = 0; t < maxItems; t++) {
        parser.itemOff[t] <== itemOff[t];
        parser.itemMajor[t] <== itemMajor[t];
        parser.itemArg[t] <== itemArg[t];
        parser.itemHdrLen[t] <== itemHdrLen[t];
        parser.itemParent[t] <== itemParent[t];
        parser.itemChildIdx[t] <== itemChildIdx[t];
        parser.itemEnd[t] <== itemEnd[t];
    }
    for (var h = 0; h < pdN; h++) {
        parser.pathKeyLen[h] <== pathKeyLen[h];
        for (var j = 0; j < maxPathKeyLen; j++) parser.pathKey[h][j] <== pathKey[h][j];
        parser.pathKeyItem[h] <== pathKeyItem[h];
        parser.pathValItem[h] <== pathValItem[h];
    }
    for (var i = 0; i < nFields; i++) {
        parser.entryKey[i] <== entryKey[i];
        parser.entryVal[i] <== entryVal[i];
    }

    // 3) MSO-style salted digest list over every subject entry
    component mdoc = MdocDigest(nFields, maxKeyLen, maxValueLen, nsLen);
    for (var i = 0; i < nFields; i++) {
        mdoc.keyRawLen[i] <== parser.keyRawLen[i];
        mdoc.valRawLen[i] <== parser.valRawLen[i];
        for (var j = 0; j < maxKeyLen; j++) mdoc.keyRaw[i][j] <== parser.keyRaw[i][j];
        for (var j = 0; j < maxValueLen; j++) mdoc.valRaw[i][j] <== parser.valRaw[i][j];
        for (var j = 0; j < 16; j++) mdoc.itemRandom[i][j] <== itemRandom[i][j];
    }
    for (var j = 0; j < nsLen; j++) mdoc.namespace[j] <== namespace[j];
    for (var j = 0; j < messageLen; j++) message[j] <== mdoc.message[j];
}

/**
 * Parser + digest list only (no issuer-signature check): used by the unit
 * test in unit_test/cbor to validate the CBOR parse tree and the MSO-style
 * digest layout against a Python reference without paying for PowerMod at
 * compile time.
 */
template CborRedactNoSig(payloadLen, maxItems, nFields, maxKeyLen, maxValueLen, pathDepth, maxPathKeyLen, nsLen) {
    var messageLen = 2 + nsLen + nFields * 33;
    var pdN = pathDepth < 1 ? 1 : pathDepth;

    signal input payload[payloadLen];
    signal input itemRandom[nFields][16];
    signal input namespace[nsLen];
    signal input nItems;
    signal input itemOff[maxItems];
    signal input itemMajor[maxItems];
    signal input itemArg[maxItems];
    signal input itemHdrLen[maxItems];
    signal input itemParent[maxItems];
    signal input itemChildIdx[maxItems];
    signal input itemEnd[maxItems];
    signal input pathKeyLen[pdN];
    signal input pathKey[pdN][maxPathKeyLen];
    signal input pathKeyItem[pdN];
    signal input pathValItem[pdN];
    signal input entryKey[nFields];
    signal input entryVal[nFields];

    signal output message[messageLen];

    component parser = CborTreeVerify(payloadLen, maxItems, nFields, maxKeyLen, maxValueLen, pathDepth, maxPathKeyLen);
    for (var j = 0; j < payloadLen; j++) parser.payload[j] <== payload[j];
    parser.nItems <== nItems;
    for (var t = 0; t < maxItems; t++) {
        parser.itemOff[t] <== itemOff[t];
        parser.itemMajor[t] <== itemMajor[t];
        parser.itemArg[t] <== itemArg[t];
        parser.itemHdrLen[t] <== itemHdrLen[t];
        parser.itemParent[t] <== itemParent[t];
        parser.itemChildIdx[t] <== itemChildIdx[t];
        parser.itemEnd[t] <== itemEnd[t];
    }
    for (var h = 0; h < pdN; h++) {
        parser.pathKeyLen[h] <== pathKeyLen[h];
        for (var j = 0; j < maxPathKeyLen; j++) parser.pathKey[h][j] <== pathKey[h][j];
        parser.pathKeyItem[h] <== pathKeyItem[h];
        parser.pathValItem[h] <== pathValItem[h];
    }
    for (var i = 0; i < nFields; i++) {
        parser.entryKey[i] <== entryKey[i];
        parser.entryVal[i] <== entryVal[i];
    }

    component mdoc = MdocDigest(nFields, maxKeyLen, maxValueLen, nsLen);
    for (var i = 0; i < nFields; i++) {
        mdoc.keyRawLen[i] <== parser.keyRawLen[i];
        mdoc.valRawLen[i] <== parser.valRawLen[i];
        for (var j = 0; j < maxKeyLen; j++) mdoc.keyRaw[i][j] <== parser.keyRaw[i][j];
        for (var j = 0; j < maxValueLen; j++) mdoc.valRaw[i][j] <== parser.valRaw[i][j];
        for (var j = 0; j < 16; j++) mdoc.itemRandom[i][j] <== itemRandom[i][j];
    }
    for (var j = 0; j < nsLen; j++) mdoc.namespace[j] <== namespace[j];
    for (var j = 0; j < messageLen; j++) message[j] <== mdoc.message[j];
}
