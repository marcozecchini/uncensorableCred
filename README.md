<div align="center">
<h2>Uncensorable Anonymous Credentials</h2>

This repository implements a pipeline in which the holder of a **CWT
credential (RFC 8392)** — encoded in CBOR and signed as a whole by its issuer
with **RSA-PSS** inside a **COSE_Sign1** envelope (RFC 9052) — selectively
discloses its claims **in zero knowledge** and obtains a **blind RSA-PSS
signature** from a notary over the redacted result.

</div>

---

## Overview

The issuer signs the credential in block: the CWT has no native selective
disclosure, every claim is in clear inside the signed payload. The holder
runs a Circom circuit that:

1. **verifies the issuer RSA-PSS signature** over the COSE_Sign1
   `Sig_structure` (SHA-256 + EMSA-PSS re-encoding compared against
   `sig^e mod n`);
2. **verifies a CBOR parse tree** of the claims payload (canonical CBOR,
   integer and text keys, values nested to any depth — see the design doc):
   the prover supplies the item table and the circuit checks it is the unique
   gap-free decomposition of the signed bytes; a public **path** of map keys
   selects the *subject map* to redact (`[]` = the flat claims map itself,
   `-260,1` = the `eu_dgc_v1` map of an EU Digital COVID Certificate);
3. commits to every subject entry with a **salted digest list** in the style
   of the ISO/IEC 18013-5 MobileSecurityObject `valueDigests` (*not* a
   standards-compliant MSO): each entry is hashed as an
   `IssuerSignedItem`-like preimage (digestID, 16-byte random salt,
   elementIdentifier and elementValue as raw CBOR items);
4. hashes and **blinds** the digest-list message with `Sha256BlindRSAPSS`,
   producing the blinded PSS message for the notary.

A VOLE-in-the-head or Groth16 proof attests that the blinded message was
computed honestly from a validly-issued credential. The notary blind-signs it
without learning anything about the claims; the holder unblinds and owns a
standard RSA-PSS signature over the digest list. **Selective disclosure then
happens entirely off-circuit**, exactly as in the mdoc model: the holder
builds a *presentation* revealing the preimages of the chosen entries only,
and the verifier recomputes their digests against the notary-signed list —
undisclosed entries stay hidden behind their salted digests, and many
different presentations can be derived from a single signed list.

```
┌──────────────────────┐      ┌─────────────────────────────────────────┐
│ CWT (COSE_Sign1,     │ ---> │ cwt_redact/ (issue.py + prepare.py)     │
│ RSA-PSS, CBOR claims)│      │  - sign test credential                 │
└──────────────────────┘      │  - recover PSS salt, build input.json   │
                              │  - render cwt_test.circom from template │
                              └───────────────────┬─────────────────────┘
                                                  ▼
                       ┌───────────────────────────────────────────────────┐
                       │ examples/cbor_redact_verify.circom                │
                       │  - COSE Sig_structure rebuild + SHA-256           │
                       │  - issuer RSA-PSS verify (PowerMod + EMSA-PSS)    │
                       │  - verified CBOR parse tree + subject path        │
                       │  - MSO-style salted digest list output            │
                       └───────────────────┬───────────────────────────────┘
                                           ▼
                       ┌───────────────────────────────────────────────────┐
                       │ Sha256BlindRSAPSS (hash_and_blind.circom)         │
                       │  → blinded PSS message for the notary             │
                       └───────────────────┬───────────────────────────────┘
                                           ▼
                       ┌───────────────────────────────────────────────────┐
                       │ ./target/release/cwt_prove [vole|snark]           │
                       └───────────────────┬───────────────────────────────┘
                                           ▼
                       ┌───────────────────────────────────────────────────┐
                       │ ./target/release/cwt_notary (blind-rsa-signatures)│
                       │ notary blind-sign → unblind → RSA-PSS verify      │
                       └───────────────────────────────────────────────────┘
```

The exact byte layouts (CBOR subset, item preimage format, digest-list
serialization) are documented in `examples/cbor_redact_verify.DESIGN.md`.

## From the Green Pass Bytes to Presentation Time: Code Map

The full chain — extracting the CBOR/COSE parameters of a real EU Digital
COVID Certificate, committing its field values into a salted digest list,
having the list blind-signed, and finally presenting a selective disclosure —
is spread across drivers and circuit; this is where each link lives:

### Background: the CBOR parse tree

CBOR (RFC 8949) is a binary serialization: every *item* starts with a 1-byte
head — 3 bits of **major type** (0 = uint, 1 = negative int, 2 = byte
string, 3 = text string, 4 = array, 5 = map) and 5 bits carrying the
**argument** (the integer value, the string byte-length, or the container
element count), possibly extended by 1/2/4 argument bytes for larger values.
Strings are followed by their content bytes; containers are followed by
their child items (maps alternate key, value).

*Canonical* CBOR (the only
form we accept) uses definite lengths and the shortest possible head, so
every value has exactly one encoding. The signed Green Pass payload is one
nested CBOR item like the following one:

```
a4                          map(4)                 ← root, the CWT claims
├─ 04 → 1a 6092dd20         key 4 (exp) → uint32 timestamp
├─ 06 → 1a 60903a20         key 6 (iat) → uint32 timestamp
├─ 01 → 62 4154             key 1 (iss) → tstr "AT"
└─ 39 0103 →                key -260 (hcert) →
   a1 01 →                    map(1), key 1 →
      a4                        map(4)             ← SUBJECT (eu_dgc_v1)
      ├─ 61 76   → 81 aa …        "v"   → array(1) of map(10) (vaccination)
      ├─ 63 6e616d → a4 …         "nam" → map(4)              (names)
      ├─ 63 766572 → 65 …         "ver" → tstr "1.2.1"
      └─ 63 646f62 → 6a …         "dob" → tstr "1998-02-26"
```

The **parse tree** is this structure flattened into an *item table* in
document order: one row per item with its byte offset, major type, argument,
head length, end-of-subtree offset, parent item and position among the
parent's children (48 rows for the Green Pass). 
A recursive parser is
impractical inside an arithmetic circuit, so the roles are split: the
*prover* supplies the table as an untrusted witness (step 1) and the
*circuit* verifies it is **the unique gap-free decomposition** of the signed
bytes (step 2) by checking, for every row, that the head bytes at `off`
really encode `(major, arg)` in minimal form, that offsets strictly
increase, that leaf spans match their heads, and that every container is
*exactly tiled* by its children (first child right after the head, each
child starting where the previous ends, last child ending at the container's
end, child count matching the head argument). Under these constraints no
boundary can be shifted and no item skipped or invented — a malicious prover
cannot, e.g., re-interpret bytes inside a name string as a fake `dob` field.

The *subject map* whose entries get committed is selected by a public path
of map keys (`-260, 1` above); its entry keys and values are exposed to the
digest stage as raw CBOR spans, so a value can be a whole subtree (the
entire `nam` map counts as one redactable value).

### The chain, link by link

0. **Extracting the credential parameters** — `load_eudcc()` in
   `cwt_redact/eudcc.py`. From the dgc-testdata JSON only two fields are
   used: `COSE` (hex of the COSE_Sign1 message) and `TESTCTX.CERTIFICATE`
   (DER signing certificate). `parse_cose_sign1()` walks the CBOR envelope —
   tag 18, then the 4-element array — and extracts the **protected header**
   bytes (14 B, `{4: kid, 1: -37 (PS256)}`), the **payload** (the 307-byte
   CWT claims map: this is the credential the circuit works on) and the
   **signature** (256 B). The issuer public key `(n, e)` comes from the
   certificate; the signature is sanity-verified off-circuit against the
   rebuilt RFC 9052 `Sig_structure` (`sig_structure()` in
   `cwt_redact/issue.py`), and `recover_pss_salt()` extracts the issuer's
   PSS salt from `sig^e mod n` (EMSA-PSS unmasking) — the circuit needs it
   as a witness to re-encode and verify the signature. (The synthetic
   credential path replaces this step with `issue()` in
   `cwt_redact/issue.py`, which signs a test CWT from scratch.)

1. **Parsing the payload into the item-table witness** — `tree_witness()` in
   `cwt_redact/cbor_tree.py`, called by `prepare.py`: decodes the payload
   into its CBOR parse tree (48 items for the CO1 Green Pass) and produces
   the witness columns (`itemOff/itemMajor/itemArg/itemHdrLen/itemParent/
   itemChildIdx/itemEnd`), the public path keys (`-260,1` → raw CBOR
   `390103`, `01`), the hop item indices and the subject-map entry indices
   (`v`, `nam`, `ver`, `dob` for the Green Pass). `prepare.py` assembles all
   of this — plus the issuer signature/key as 64-bit limbs and the recovered
   PSS salt — into `examples/cwt_input.json` and renders
   `examples/cwt_test.circom` for the actual sizes. The correctness of this
   codec is differentially tested against RFC 8949 vectors and `cbor2`
   (`examples/unit_test/cbor/cbor_diff.py`).

2. **Values are pinned to the issuer-signed bytes** — template
   `CborTreeVerify` (`examples/cbor_redact_verify.circom`): its outputs
   `keyRaw[i]`/`valRaw[i]` are the raw CBOR spans of the subject-map entries,
   read out of the same `payload` signal whose issuer RSA-PSS signature is
   verified by `CoseSign1Verify`. A prover cannot feed different values: the
   parse tree is verified against the signed bytes.

3. **Values are committed into salted digests** — template `MdocDigest`
   (`examples/cbor_redact_verify.circom`): for every entry `i` it computes
   in-circuit `digest[i] = SHA256( digestID(1)=i || random(16) || idLen(1) ||
   elementIdentifier || valLen(1) || elementValue )` via `Sha256Bytes`, and
   serializes the digest-list message `nsLen || namespace || nFields ||
   (digestID || digest)*`. SHA-256 makes the commitment *binding* to the
   values; the 16-byte `random` makes it *hiding*. The Python mirror of the
   preimage/list (used by the driver and the tests) is
   `item_preimage()` / `mso_message()` in `cwt_redact/cbor_tree.py`;
   `cwt_redact/prepare.py` writes the expected list to `mdoc_message.bin`.

4. **The digest list is hashed and blinded** — the unmodified
   `Sha256BlindRSAPSS` (`examples/hash_and_blind.circom`), instantiated in
   `examples/cwt_test.template.circom` with the digest-list message as its
   `message` input, computes `blinded = EMSA-PSS(SHA256(message)) · r^e mod n`
   in-circuit. The blinding factors (`blindSalt`, `r`) come from
   `cwt_notary blind` (`src/bin/cwt_notary.rs`, `pk.blind()` of the vendored
   `rust-blind-rsa-signatures` fork), and the ZK proof attests the whole
   chain 2→4 was computed honestly.

5. **The digest list is signed** — `cwt_notary finalize`
   (`src/bin/cwt_notary.rs`): the notary runs `sk.blind_sign()` on the
   circuit's blinded output (checked equal to the crate's `blind_msg`), the
   holder unblinds with `pk.finalize()`, and the result in
   `signature_cwt.bin` is a standard RSA-PSS signature over exactly the
   digest-list bytes of `mdoc_message.bin`. It is verified three times: by
   the crate itself, by `cryptography`
   (`verify_final_signature` in `cwt_redact/finalize.py`), and by the
   verifier during presentation checking.

6. **The commitment is opened at presentation time** —
   `verify_presentation()` in `cwt_redact/present.py`: the verifier checks
   the notary signature over the digest list, then recomputes
   `SHA256(preimage)` for every disclosed item and compares it with the
   committed digest at its `digestID` slot. Undisclosed items never leave
   the holder: only their salted digests appear in the signed list.

## Software Requirements

* **Rust toolchain** (`rustc` and `cargo`, stable is sufficient)
* **Python 3.10+** with the dependencies of `requirements.txt`:

  ```bash
  pip install -r requirements.txt
  ```
* **Circom 2.x**, **Node.js** and **snarkjs**
* circomlib, installed once with:

  ```bash
  cd examples && npm install
  ```

Issuer and notary RSA-2048 keys (`issuer_key.pem`, `notary_key.pem`) are
generated automatically on first run if missing. For Groth16 you additionally
need a powers-of-tau file (env var `PTAU`, default `~/28.ptau`) and,
optionally, rapidsnark (env var `RAPIDSNARK`).

## Building the Rust Components

From the repository root:

```bash
RUSTFLAGS="-Awarnings" cargo build --release
```

This produces the two executables invoked by the Python driver:

* `./target/release/cwt_prove` — the VOLE/SNARK prover;
* `./target/release/cwt_notary` — the blind RSA-PSS round (blinding with
  exported salt/`r`, notary blind signature, unblinding and verification),
  built on the ACTS fork of `rust-blind-rsa-signatures` vendored in
  `rust-blind-rsa-signatures/`, whose `BlindingResult` exposes the PSS salt
  the circuit needs as a witness. The crate's `blind_msg` doubles as an
  independent reference the circuit's blinded output is checked against.

## Running the Main Experiment

The entire pipeline (credential issuance, witness generation, proof, blind
signature and final verification) can be reproduced with a single command:

```bash
bash test.sh
```

which builds the Rust components and runs:

```bash
python main.py --proof vole
```

By default this signs a built-in sample credential (8 claims), discloses the
even-indexed claims and redacts the others, generates and validates the
witness, produces and verifies a VOLE proof, and completes the notary round
(blind sign → unblind → RSA-PSS verification), leaving:

* `cwt_credential.bin` — the issued COSE_Sign1 credential,
* `mdoc_message.bin` — the MSO-style salted digest list,
* `signature_cwt.bin` — the unblinded notary signature over it,
* `mdoc_presentation.json` — a verified presentation disclosing the
  mask-selected entries (signed digest list + their preimages).

## Running on a Real Credential (EU Digital COVID Certificate)

The same pipeline runs unchanged on a **real credential downloaded from the
internet**: the official EUDCC test vector `CO1` ("VALID: RSA 2048 key", alg
PS256) from the public
[`dgc-testdata`](https://github.com/eu-digital-green-certificates/dgc-testdata)
dataset, vendored in `examples/unit_test/cose_real/eudcc_CO1.json`:

```bash
python main.py --proof vole --eudcc examples/unit_test/cose_real/eudcc_CO1.json
```

The default path `-260,1` selects the `eu_dgc_v1` map, whose 4 entries become
the redactable fields (in document order): `v` (the whole vaccination record
subtree), `nam` (the whole name map subtree), `ver` and `dob`. The default
mask discloses `v` and `ver` and withholds `nam` and `dob` in the generated
presentation — pass e.g. `--mask 0,0,1,1` to hide the vaccination and name
data while disclosing version and birth date. Since the disclosure choice is
off-circuit, new presentations with different masks can be derived from the
same signed digest list without re-running the circuit. The
issuer signature of the real credential is verified in-circuit against the
public key of the official signing certificate.

## Custom Runs

```bash
python main.py \
  --proof vole|snark|none \
  --claims <claims.json> | --eudcc <dgc-testdata.json> \
  --path -260,1 \
  --mask 1,0,1,1 \
  --namespace org.iso.18013.5.1.acts \
  --max-key-len 8 --max-value-len 176
```

where:

* `--proof` selects the proof system (`vole`, `snark`, or `none` to stop after
  witness generation and validation),
* `--claims` is a JSON object mapping claim names to string values (or
  `{"hex": "..."}` for byte strings) for the synthetic credential, while
  `--eudcc` loads a real PS256 EUDCC test vector,
* `--path` is the comma-separated list of map keys (ints or strings) leading
  to the subject map (default: `''` for synthetic, `-260,1` for EUDCC),
* `--mask` selects which subject entries are disclosed (`1`) or withheld
  (`0`) in the off-circuit presentation (the signed digest list always
  commits to all of them),
* `--max-key-len` / `--max-value-len` bound the raw CBOR size of identifiers
  and values (auto-sized from the credential when omitted),
* `--namespace` labels the digest list.

All sizes are compile-time parameters of the circuit: the CBOR payload can be
up to 4 KB, and the circuit is re-rendered (from
`examples/cwt_test.template.circom`) and re-compiled automatically for the
actual credential sizes and shape, so no template code ever needs editing.

## Unit Tests

Each cryptographic building block has a standalone unit test that checks the
circuit against a Python reference implementation:

```bash
cd examples/unit_test/cbor      && bash test.sh   # CBOR parse + mdoc redaction
cd examples/unit_test/cose_real && bash test.sh   # COSE_Sign1 verify on a REAL credential
cd examples/unit_test/emsa      && bash test.sh   # EMSA-PSS encoding
cd examples/unit_test/mgf       && bash test.sh   # MGF1 mask generation
```

The CBOR test vector is a nested CWT-like payload exercising integer keys
(including the 2-byte negative key `-260`), 1/2/4-byte heads, scalar and
subtree values (a nested name map and a vaccination-style array), a 2-hop
path to the subject map, with the salted digest list checked byte-per-byte
against a Python reference.

The hand-rolled CBOR codec itself is differentially tested against
independent references (`examples/unit_test/cbor/cbor_diff.py`): the RFC 8949
Appendix A test vectors, head-size boundary roundtrips, 500 seeded random
structures compared with the `cbor2` library, and the real EUDCC payload
(decode agreement with `cbor2` plus byte-identical canonical re-encoding):

```bash
cd examples/unit_test/cbor && python cbor_diff.py
```

The `cose_real` test verifies **in-circuit** the issuer RSA-PSS signature of a
real-world credential downloaded from the internet: the official EU Digital
COVID Certificate test vector `CO1` ("VALID: RSA 2048 key", alg PS256) from
the public [`dgc-testdata`](https://github.com/eu-digital-green-certificates/dgc-testdata)
dataset, vendored in `examples/unit_test/cose_real/eudcc_CO1.json`. The EUDCC
is a production-format CWT in COSE_Sign1 signed with RSA-PSS/SHA-256, i.e.
exactly the issuer scheme of this pipeline. Only the signature-verification
stage runs on it: the EUDCC claims payload uses integer keys and nested maps,
which are outside the minimal CBOR subset supported by the redaction parser
(flat maps with text-string keys).

# Acknowledgements

This project builds upon open-source software including:

* [`vole-zk-prover`](https://github.com/holonym-foundation/vole-zk-prover)
  (Holonym Foundation), vendored in `vole_zk_prover/`;
* [`rust-blind-rsa-signatures`](https://github.com/jedisct1/rust-blind-rsa-signatures)
  (Frank Denis), vendored in `rust-blind-rsa-signatures/` as the ACTS fork
  that exposes the PSS salt in `BlindingResult`;
* the Circom bigint/RSA-PSS circuits and the blind RSA-PSS experiment
  pipeline of [`blindRSANotary`](https://github.com/marcozecchini/blindRSANotary)
  (NDSS 2026 paper "ACTS: Attestations of Contents in TLS Sessions"), from
  which this repository forks;
* [`circomlib`](https://github.com/iden3/circomlib) (iden3).
