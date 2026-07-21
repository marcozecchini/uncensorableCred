# Design: CWT → mdoc-style redaction circuit (`cbor_redact_verify.circom`)

Status: **confirmed** (2026-07-17). Decisions: `PLACEHOLDER_BYTE = 0x00`
(configurable template parameter); `elementIdentifier`/`idLen` stay visible for
redacted fields; defaults `maxFields=16`, `maxKeyLen=32`, `maxValueLen=64`,
`random=16`; claim values restricted to tstr + bstr.

This document fixes the exact byte layouts and circuit interfaces for the new
experiment: verify an issuer RSA-PSS signature over a CWT (COSE_Sign1), apply a
disclosure mask, and emit an mdoc-style byte string that feeds *unchanged* into
the existing `Sha256BlindRSAPSS(w, k, eBits, mgfCount, messageLen)` template.

Everything below uses the repo's bigint conventions: `w = 64`, `k = 32`
(RSA-2048), `eBits = 17` (e = 65537), `mgfCount = 7`, SHA-256 with
`hashLen = saltLen = 32`. *Lengths are compile-time template parameters*: the
Python driver renders the top-level circuit from
`cwt_test.template.circom` by substituting the `{{...}}` placeholders, so the
circuit is recompiled for different credential sizes without editing any
template code.

---

## 1. Input credential: CWT in COSE_Sign1

### 1.1 COSE_Sign1 envelope (RFC 9052)

```
COSE_Sign1 = [ protected: bstr, unprotected: {}, payload: bstr, signature: bstr ]
```

The issuer signs `ToBeSigned = Sig_structure` (RFC 9052 §4.4), serialized as:

```
84                          ; array(4)
  6A 5369676E617475726531   ; text(10) "Signature1"
  <protHdr> <protBytes>     ; bstr, protected header (see below)
  40                        ; bstr(0), external_aad = ''
  <plHdr> <payload>         ; bstr, the CWT claims payload
```

* `protBytes` is fixed for the experiment: `A1 01 38 24` = `{1: -37}` (alg =
  PS256, RSASSA-PSS w/ SHA-256), so `<protHdr> <protBytes>` = `44 A1013824`
  (5 bytes). Passed as a compile-time constant; length `protLen = 4` is a
  template parameter so a different protected header can be swapped in.
* `<plHdr>` is the CBOR byte-string header for `payloadLen`, computed at
  compile time (payloadLen < 24 → 1 byte `0x40+len`; < 256 → `58 len`;
  < 65536 → `59 hi lo`). Max payload = **4 KB** (`payloadLen ≤ 4096`), but
  `payloadLen` is a template parameter, not a hardcoded bound.

The circuit *constructs* `ToBeSigned` from the payload signal + compile-time
constants (no witness needed for the envelope), hashes it with `Sha256Bytes`,
and verifies the issuer signature against that hash. The `unprotected` map and
the outer array framing never enter the circuit — only `ToBeSigned` matters
for signature verification.

### 1.2 CWT claims payload (RFC 8392) — the part the minimal parser covers

The payload is a single CBOR map with `nFields` entries (`nFields` is a
compile-time parameter, actual number of claims in the credential):

```
payload := mapHdr(nFields) || entry[0] || entry[1] || ... || entry[nFields-1]

mapHdr(n) :=  A0+n            if n < 24        (1 byte)
              B8 n             if 24 ≤ n < 256  (2 bytes)

entry[i]  :=  keyHdr[i] || keyBytes[i] || valHdr[i] || valBytes[i]

keyHdr    :=  60+len           text, len < 24   (1 byte)
              78 len           text, len < 256  (2 bytes)

valHdr    :=  40+len / 58 len  byte string (major type 2), len < 256
              60+len / 78 len  text string (major type 3), len < 256
```

Claim keys are **CBOR text strings** (valid CWT claim keys per RFC 8392 §1.2 —
we use text-keyed custom claims; registered integer-keyed claims like
`iss`/`exp` are out of scope for the minimal parser). Claim values are text
strings or byte strings, `≤ maxValueLen` bytes, keys `≤ maxKeyLen` bytes.
Nested maps/arrays are not supported (out of scope by design).

### 1.3 In-circuit "verified parse" (no general CBOR library)

Instead of a byte-by-byte state machine, the prover supplies per-field
witnesses and the circuit *checks* them against the payload bytes — this is the
minimal-parser strategy:

Private witnesses per field `i`:
* `keyLen[i]`  (1 ≤ keyLen[i] ≤ maxKeyLen ≤ 255)
* `valLen[i]`  (0 ≤ valLen[i] ≤ maxValueLen ≤ 255)
* `valMajor[i]` ∈ {2, 3} (bstr / tstr)

The circuit then:

1. Constrains `payload[0..mapHdrLen]` == `mapHdr(nFields)` (compile-time
   constant, since `nFields` is a parameter).
2. Computes running offsets *inside the circuit* (not witnessed), so coverage
   is guaranteed with no gaps or overlaps:
   `off[0] = mapHdrLen`;
   `off[i+1] = off[i] + keyHdrLen(i) + keyLen[i] + valHdrLen(i) + valLen[i]`,
   where `keyHdrLen(i) = 1 + (keyLen[i] ≥ 24)` (comparator), same for values.
3. Constrains `off[nFields] == payloadLen` (the parse consumes the whole map).
4. For each field, aligns the payload with a barrel shifter
   (`VarShiftLeft(payloadLen, window)`, log-depth mux network — the only new
   generic building block) and constrains at the aligned position:
   * the key header encodes major type 3 with length `keyLen[i]` (both the
     short and the 1-byte-extended form are accepted, selected by the
     `keyLen[i] < 24` comparator bit);
   * the value header encodes major type `valMajor[i]` with length `valLen[i]`;
   * exposes `keyBytes[i][0..maxKeyLen]` and `valBytes[i][0..maxValueLen]`
     windows for the redaction stage (bytes beyond `keyLen`/`valLen` are
     forced to 0x00 via range-mask).

Two shifts per field (one aligned at the key bytes, one at the value bytes);
each shift costs ~`payloadLen · log2(payloadLen)` constraints
(≈ 4096·12 ≈ 50k at 4 KB), i.e. ~100k per field — same order as the SHA-256
chain over the payload, so well within the scale the proving backends handle.

## 2. Issuer signature verification (reused components only)

Public inputs: `issuerModulus[k]`, `issuerExp[k]` (bigint limbs, `w=64, k=32`).
Private witnesses: `issuerSig[k]` (signature limbs), `issuerPssSalt[32]`
(the PSS salt, recovered off-circuit from the signature by the driver).

```
mHash  = Sha256Bytes(tbsLen)(ToBeSigned)                     // sha256.circom
EM'    = EMSA_PSS_Encode(256, 32, 32, 7)(mHash, issuerPssSalt) // rsa_blind.circom
S      = PowerMod(64, 32, 17)(issuerSig, issuerExp, issuerModulus) // pow_mod.circom
BigIntI2OSP(32, 8)(S) === EM'   (byte-per-byte, 256 constraints)
```

Re-encoding with the witnessed salt and comparing against `sig^e mod n` is
equivalent to EMSA-PSS-Verify (the encoding is injective given `(mHash, salt)`),
and it reuses `EMSA_PSS_Encode`/`MGF1` exactly as they are — no verify-side
re-implementation.

## 3. Output: mdoc-style byte layout (`IssuerSignedItem`-inspired)

**Not** a standards-compliant ISO/IEC 18013-5 mdoc — a fixed-size, deterministic
byte layout carrying the same information as `IssuerSignedItem`
(`digestID`, `random`, `elementIdentifier`, `elementValue`) plus a namespace,
designed to be hashed/blinded as an opaque message.

All sizes compile-time constants → `messageLen` is a pure function of the
template parameters:

```
message :=
  nsLen                  1 byte     = nsLen parameter
  namespace              nsLen bytes  e.g. "org.iso.18013.5.1.acts" (public input)
  nFields                1 byte     = nFields parameter
  item[0] ... item[nFields-1]

item[i] :=
  digestID               1 byte     = i
  disclosed              1 byte     = mask[i] (0x00 or 0x01)
  random                 16 bytes   per-element salt (private input random[i][16])
  valMajor               1 byte     = valMajor[i] (0x02/0x03), PLACEHOLDER if redacted
  idLen                  1 byte     = keyLen[i]
  elementIdentifier      maxKeyLen bytes   key bytes, zero-padded to maxKeyLen
  valLen                 1 byte     = valLen[i],  PLACEHOLDER if redacted
  elementValue           maxValueLen bytes value bytes zero-padded, PLACEHOLDER if redacted

messageLen = 2 + nsLen + nFields · (21 + maxKeyLen + maxValueLen)
```

Defaults proposed: `maxFields` (= max `nFields`) **16**, `maxKeyLen` **32**,
`maxValueLen` **64**, `random` **16 bytes** (mdoc mandates ≥ 16). With the
defaults and `nFields = 8`: `messageLen = 2 + 22 + 8·117 = 960` bytes.

### 3.1 Disclosure mask & redaction constraints

`mask[nFields]` is a **public input**, constrained boolean.

* `mask[i] = 1` (disclosed): `elementIdentifier`/`elementValue`/`valLen`/
  `valMajor` are constrained **byte-per-byte equal** to the parsed CWT windows
  (`out = parsedByte` for j < len, `out = 0x00` padding for j ≥ len);
  `random` is copied from the private input.
* `mask[i] = 0` (redacted): `valMajor`, `valLen`, every `elementValue` byte and
  every `random` byte are constrained `=== PLACEHOLDER_BYTE`.
  **`elementIdentifier` and `idLen` stay visible** even when redacted (attribute
  *names* are not treated as secret — only values are). ⚠ open point, see §5.

`PLACEHOLDER_BYTE = 0x00` — **explicitly a configurable constant** (a template
parameter with default 0, flagged in the code comments), as required by the
spec. ⚠ open point, see §5.

Implementation: each output byte is a single linear select
`out = mask[i]·real + (1-mask[i])·PLACEHOLDER` — 1 constraint per byte.

## 4. Integration & file plan

```
                       ┌───────────────────────────────────────────┐
 CWT (COSE_Sign1) ───► │ CborRedactVerify(payloadLen, nFields,     │
 issuer pk (public)    │   maxKeyLen, maxValueLen, nsLen, w,k,eBits│──► message[messageLen]
 mask (public)         │   , mgfCount, PLACEHOLDER)                │        │ unchanged
                       └───────────────────────────────────────────┘        ▼
                                              ┌──────────────────────────────────────────┐
 blinding r, salt (private) ────────────────► │ Sha256BlindRSAPSS(w,k,eBits,mgfCount,    │──► blinded[256]
 notary pk (public)                           │                  messageLen)  (UNTOUCHED)│
                                              └──────────────────────────────────────────┘
```

Project layout:

* `examples/cbor_redact_verify.circom` — `VarShiftLeft`, `CborMapVerify`
  (verified parse), `CoseSign1TBS` (envelope rebuild), `MdocRedact`
  (layout + mask), composed in `CborRedactVerify` (+ `CborRedactNoSig`
  for unit testing).
* `examples/cwt_test.template.circom` — top level `CwtRedactBlind` =
  `CborRedactVerify` + `Sha256BlindRSAPSS`, with `{{PAYLOAD_LEN}}`,
  `{{N_FIELDS}}` etc. placeholders rendered by `cwt_redact/prepare.py`.
* `examples/gen-cwt-r1cs-and-wtns.sh` — circuit compilation + witness
  generation (C++ witness generator, with wasm fallback).
* `cwt_redact/` (Python): `issue.py` (build a test CWT: minimal CBOR encoder
  + cryptography RSA-PSS sign, salt-recovery from the signature),
  `prepare.py` (input.json + template rendering), `validate.py` (recompute
  the expected message off-circuit and compare with the witness output),
  `finalize.py` (notary blind signature, unblinding, final PSS verify).
  Driver `main.py` in the repo root.
* `src/main.rs` — `cwt_prove` binary: VOLE-in-the-head prove+verify, or
  Groth16 via `examples/setup_groth_cwt.sh` / `examples/prove_groth_cwt.sh`.
* `examples/unit_test/cbor/` — unit test in the same style as the `emsa`/`mgf`
  ones (Python reference → `input.json`/`expected_output.json` → `test.sh`).

## 5. Open points (need confirmation)

1. **PLACEHOLDER_BYTE**: default `0x00` for every redacted byte (simple,
   clearly non-ambiguous since disclosed values always carry `disclosed=1`).
   Alternative: per-field SHA-256 digest of the hidden value (commitment-style,
   costlier: +1 SHA-256 per redacted field).
2. **Redacted identifiers**: keep `elementIdentifier` visible for redacted
   fields (proposed), or placeholder it too (hides *which* attributes exist).
3. **Default sizes**: `maxFields=16`, `maxKeyLen=32`, `maxValueLen=64`,
   `random=16`.
4. **Value types**: tstr + bstr only (proposed); integer claim values would
   need an extra encode path in the parser and the mdoc layout.
