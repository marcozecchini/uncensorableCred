# Design: CWT → mdoc-style redaction circuit (`cbor_redact_verify.circom`)

Status: **confirmed** (2026-07-17, revised twice: parse-tree generalization,
then MSO-style digest model). Decisions: identifier and value carry raw CBOR
item bytes, supporting integer keys and nested subtree values (canonical
CBOR, majors 0-5), with `maxItems`/`maxKeyLen`/`maxValueLen` auto-sized from
the credential; a public path of map keys selects the subject map (e.g.
`[-260, 1]` for real EU Digital COVID Certificates, `[]` for the flat
synthetic CWT); the circuit outputs a **salted digest list** (MSO-style,
`random=16`) committing to ALL entries, and disclosure is a purely
off-circuit presentation — the earlier in-circuit placeholder/mask model was
superseded.

This document fixes the exact byte layouts and circuit interfaces for the new
experiment: verify an issuer RSA-PSS signature over a CWT (COSE_Sign1),
commit to its claims with salted digests, and emit an MSO-style byte string
that feeds *unchanged* into the existing
`Sha256BlindRSAPSS(w, k, eBits, mgfCount, messageLen)` template.

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

* `protBytes` for the synthetic experiment is `A1 01 38 24` = `{1: -37}` (alg
  = PS256, RSASSA-PSS w/ SHA-256). The header is an input signal of
  parametric length `protLen`, so real-world headers work too (e.g. EU
  Digital COVID Certificates carry `{1: -37, 4: kid}`, 14 bytes).
* `<plHdr>` is the CBOR byte-string header for `payloadLen`, computed at
  compile time (payloadLen < 24 → 1 byte `0x40+len`; < 256 → `58 len`;
  < 65536 → `59 hi lo`). Max payload = **4 KB** (`payloadLen ≤ 4096`), but
  `payloadLen` is a template parameter, not a hardcoded bound.

The circuit *constructs* `ToBeSigned` from the payload signal + compile-time
constants (no witness needed for the envelope), hashes it with `Sha256Bytes`,
and verifies the issuer signature against that hash. The `unprotected` map and
the outer array framing never enter the circuit — only `ToBeSigned` matters
for signature verification.

### 1.2 CWT claims payload (RFC 8392) — what the parser covers

The payload is any **canonical CBOR** structure (RFC 8949 §4.2.1: definite
lengths, minimal heads, additional info ≤ 26 i.e. head arguments < 2^32) built
from major types 0–5: unsigned/negative integers, byte/text strings, arrays
and maps, nested to any depth. Tags and floats are rejected. This covers both
the synthetic flat text-keyed claims map and real EUDCC payloads (integer
keys such as `-260`, 4-byte timestamp heads, nested `hcert` maps and arrays).

The root item must be a map. A **path** of map keys (public input: the raw
CBOR encoding of each hop key) selects the *subject map* whose `nFields`
entries are redacted — path `[]` selects the root itself (synthetic flat CWT),
path `[-260, 1]` selects the `eu_dgc_v1` map of an EUDCC.

### 1.3 In-circuit "verified parse tree" (no general CBOR library)

Instead of a byte-by-byte state machine, the prover supplies the full **item
table** of the payload in document (pre-order) order and the circuit checks it
is *the* unique decomposition (template `CborTreeVerify`). Per item `t`:
`off / major / arg / hdrLen / end / parent / childIdx`. The checks:

1. **Head**: the bytes at `off[t]` (read through the `VarShiftLeft` barrel
   shifter) encode `(major, arg)` with the *minimal* (canonical) head length
   matching `hdrLen[t]` — 1, 2, 3 or 5 bytes; minimality makes each head
   encoding unique.
2. **Leaf spans**: for integers `end = off + hdrLen`; for strings
   `end = off + hdrLen + arg` (string *content* is opaque, as CBOR mandates).
3. **Document order**: offsets strictly increase with `t` (items distinct).
4. **Container tiling**: for every container, child `0` starts right after
   the container head, child `i+1` starts exactly where child `i` ends (the
   unique predecessor sibling is found via a parent/childIdx match matrix),
   the last child ends where the container ends, and the number of children
   equals the head count (`2·arg` items for maps, `arg` for arrays; empty
   containers end right after their head). The root (item 0) is a map at
   offset 0 whose `end` is `payloadLen`.

Together these force complete, gap-free, unambiguous coverage of every
payload byte: no boundary can be shifted, no item skipped or invented — the
classic "content bytes that look like headers" injection is structurally
impossible. (The root uses an out-of-range sentinel parent so it never
matches as a child or sibling.)

On top of the tree, the path hops and the subject entries are looked up with
`ItemRead` (a Σ-selector over the table): each hop's key item must be a leaf
at an even `childIdx`, its raw bytes must equal the public path key, and the
hop value (at `childIdx + 1`) must be a map; the subject's entry `j` has its
key at `childIdx 2j` and value at `2j+1`. Entry keys and values are exposed
as **raw CBOR spans** (`payload[off..end)`, head included), so values may be
whole nested subtrees (e.g. the entire `nam` name map of an EUDCC).

Costs: one 5-byte head window per item plus two content windows per entry
(`~payloadLen · log2(payloadLen)` constraints each) and an
`O(maxItems²)`-constraint structural block — ≈ 200k constraints for a real
307-byte EUDCC with 48 items, ≈ 48k for the synthetic unit-test vector.

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

The circuit follows the ISO/IEC 18013-5 **disclosure model** (MSO
valueDigests): the issuer-side commitment is a list of salted digests, one
per subject entry, and disclosure happens *outside* the circuit by revealing
(or not) an item's preimage. The circuit hashes, for every entry `i`, a
fixed-width `IssuerSignedItem`-like preimage:

```
preimage[i] :=
  digestID               1 byte     = i
  random                 16 bytes   per-element salt (private input random[i][16])
  idLen                  1 byte     = raw CBOR length of the key item
  elementIdentifier      maxKeyLen bytes   RAW CBOR key item, zero-padded
  valLen                 1 byte     = raw CBOR length of the value item
  elementValue           maxValueLen bytes RAW CBOR value item (possibly a whole
                                    nested subtree), zero-padded

message :=
  nsLen                  1 byte     = nsLen parameter
  namespace              nsLen bytes  e.g. "org.iso.18013.5.1.acts" (public input)
  nFields                1 byte     = nFields parameter
  ( digestID(1)=i || SHA256(preimage[i]) )*        33 bytes per entry

messageLen = 2 + nsLen + nFields · 33
```

`elementIdentifier`/`elementValue` carry the raw CBOR encoding of the key and
value items (head included): identifiers may be integer keys (`-260` →
`39 01 03`) or text keys (`"dob"` → `63 64 6F 62`), values may be scalars or
whole subtrees (the entire `nam` map of an EUDCC) — a verifier decodes them
with any CBOR library. `maxKeyLen`/`maxValueLen`/`maxItems` are auto-sized
from the credential by the driver unless overridden; `random` is **16 bytes**
(mdoc mandates ≥ 16), making each digest a *hiding* commitment. The message
length is independent of the value sizes: for the EUDCC demo (`nFields = 4`)
`messageLen = 2 + 22 + 4·33 = 156` bytes.

The preimage is a fixed-width serialization, NOT the standard
`IssuerSignedItemBytes` (`#6.24(bstr .cbor IssuerSignedItem)`) — hashing
genuine variable-length CBOR in-circuit would need a variable-length SHA-256;
this is a documented deviation (see §5).

### 3.1 Disclosure = off-circuit presentation (no mask in the circuit)

There is **no disclosure mask input**: the digest list commits to ALL
entries. The holder later builds a *presentation* (`cwt_redact/present.py`)
containing the notary-signed digest list plus the preimage data
(`elementIdentifier`, `elementValue`, `random`) of the disclosed entries
only. The verifier checks the notary RSA-PSS signature and recomputes the
digests of the disclosed items; undisclosed entries stay hidden behind their
salted digests. Many different presentations can be derived from a single
signed digest list, and the disclosure choice can be made *after* the proof
and the blind signature.

## 4. Integration & file plan

```
                       ┌───────────────────────────────────────────┐
 CWT (COSE_Sign1) ───► │ CborRedactVerify(payloadLen, maxItems,    │
 issuer pk (public)    │   nFields, maxKeyLen, maxValueLen,        │──► message[messageLen]
 path (public)         │   pathDepth, nsLen, w, k, eBits, mgfCount)│        │ unchanged
                       └───────────────────────────────────────────┘        ▼
                                              ┌──────────────────────────────────────────┐
 blinding r, salt (private) ────────────────► │ Sha256BlindRSAPSS(w,k,eBits,mgfCount,    │──► blinded[256]
 notary pk (public)                           │                  messageLen)  (UNTOUCHED)│
                                              └──────────────────────────────────────────┘
                                                            │ (after proof + blind sign)
                                                            ▼
                              present.py: signed digest list + disclosed
                              preimages → verifier recomputes digests
```

Project layout:

* `examples/cbor_redact_verify.circom` — `VarShiftLeft`, `ItemRead`,
  `CborTreeVerify` (verified parse tree), `CoseSign1TBS`/`CoseSign1Verify`
  (envelope rebuild + PSS check), `MdocDigest` (salted digest list),
  composed in `CborRedactVerify` (+ `CborRedactNoSig` for unit testing).
* `examples/cwt_test.template.circom` — top level `CwtRedactBlind` =
  `CborRedactVerify` + `Sha256BlindRSAPSS`, with `{{PAYLOAD_LEN}}`,
  `{{N_FIELDS}}` etc. placeholders rendered by `cwt_redact/prepare.py`.
* `examples/gen-cwt-r1cs-and-wtns.sh` — circuit compilation + witness
  generation (C++ witness generator, with wasm fallback).
* `cwt_redact/` (Python): `issue.py` (build a test CWT: minimal CBOR encoder
  + cryptography RSA-PSS sign, salt-recovery from the signature), `eudcc.py`
  (load a real dgc-testdata credential), `prepare.py` (input.json + template
  rendering; delegates the blinding to `cwt_notary blind`), `validate.py`
  (compare the witness against the crate's blind_msg and a python
  re-computation), `finalize.py` (independent re-verification of the final
  signature), `present.py` (off-circuit selective disclosure: build and
  verify presentations over the signed digest list). Driver `main.py` in the
  repo root.
* `src/main.rs` — `cwt_prove` binary: VOLE-in-the-head prove+verify, or
  Groth16 via `examples/setup_groth_cwt.sh` / `examples/prove_groth_cwt.sh`.
* `src/bin/cwt_notary.rs` — blind RSA-PSS round via the vendored ACTS fork of
  `rust-blind-rsa-signatures` (BlindingResult exposes the PSS salt): `blind`
  exports salt / `r = secret⁻¹` / blind_msg for the circuit, `finalize` does
  the notary blind signature, unblinding and verification.
* `examples/unit_test/cbor/` — unit test in the same style as the `emsa`/`mgf`
  ones (Python reference → `input.json`/`expected_output.json` → `test.sh`).
* `examples/unit_test/cose_real/` — in-circuit `CoseSign1Verify` run against a
  real EU Digital COVID Certificate (PS256, RSA-2048) from the official
  `dgc-testdata` dataset; signature verification only, since the EUDCC claims
  payload (integer keys, nested maps) is outside the minimal CBOR subset.

## 5. Resolved design points

1. **Disclosure model**: MSO-style digest omission (as in ISO/IEC 18013-5) —
   the circuit commits to ALL entries with salted digests and disclosure is
   an off-circuit presentation. This superseded the earlier placeholder/mask
   model, whose `PLACEHOLDER_BYTE`/`mask` inputs no longer exist.
2. **Preimage encoding**: fixed-width `IssuerSignedItem`-like serialization
   (digestID ‖ random16 ‖ idLen ‖ id ‖ valLen ‖ value, zero-padded), NOT the
   standard `#6.24(bstr .cbor ...)` wrapping — hashing genuine
   variable-length CBOR in-circuit would require a variable-length SHA-256
   template; possible future extension.
3. **Sizes**: auto-sized from the credential by the driver (`maxItems`,
   `maxKeyLen`, `maxValueLen`), overridable via CLI; `random = 16` bytes.
4. **Value types**: any canonical CBOR item (majors 0-5, nested to any
   depth), carried as its raw encoding in `elementValue`; map keys and path
   keys must be leaves (ints or strings). Tags, floats, indefinite lengths
   and non-minimal heads are rejected.
5. **Path hops**: map keys only (`[-260, 1]`-style); descending through array
   elements (e.g. into `v[0]`) is a possible future extension of the hop
   check.
