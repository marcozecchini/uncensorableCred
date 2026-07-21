<div align="center">
<h2>Uncensorable Credentials: ZK Redaction of CWT Credentials with Blind RSA-PSS Notarization</h2>

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
2. **parses the CBOR claims map** with a minimal "verified parse" (definite
   lengths, text-string keys, text/byte-string values — see the design doc);
3. re-serializes the claims into an **mdoc-style layout** (inspired by the
   `IssuerSignedItem` of ISO/IEC 18013-5: namespace, elementIdentifier,
   elementValue, per-element random salt — *not* a standards-compliant mdoc),
   where every claim not selected by the public **disclosure mask** is
   replaced by a configurable placeholder byte (default `0x00`);
4. hashes and **blinds** the resulting byte string with `Sha256BlindRSAPSS`,
   producing the blinded PSS message for the notary.

A VOLE-in-the-head or Groth16 proof attests that the blinded message was
computed honestly from a validly-issued credential. The notary blind-signs it
without learning the disclosed or hidden claims; the holder unblinds and owns
a standard RSA-PSS signature over the redacted, mdoc-style credential.

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
                       │  - minimal CBOR parse (verified offsets/headers)  │
                       │  - mdoc-style output with placeholder redaction   │
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
                       │ cwt_redact/finalize.py: notary blind-sign →       │
                       │ unblind → RSA-PSS verify over the redacted mdoc   │
                       └───────────────────────────────────────────────────┘
```

The exact byte layouts (CBOR subset, mdoc-style item format, placeholder
semantics) are documented in `examples/cbor_redact_verify.DESIGN.md`.

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

This produces `./target/release/cwt_prove`, the VOLE/SNARK prover invoked by
the Python driver.

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
* `mdoc_message.bin` — the redacted mdoc-style serialization,
* `signature_cwt.bin` — the unblinded notary signature over it.

## Custom Runs

```bash
python main.py \
  --proof vole|snark|none \
  --claims <claims.json> \
  --mask 1,0,1,1,0,1,0,1 \
  --namespace org.iso.18013.5.1.acts \
  --max-key-len 32 --max-value-len 64 \
  --placeholder 0
```

where:

* `--proof` selects the proof system (`vole`, `snark`, or `none` to stop after
  witness generation and validation),
* `--claims` is a JSON object mapping claim names to string values (or
  `{"hex": "..."}` for byte strings),
* `--mask` selects which claims are disclosed (`1`) or redacted (`0`),
* `--max-key-len` / `--max-value-len` / `--namespace` / `--placeholder`
  control the mdoc-style layout.

All sizes are compile-time parameters of the circuit: the CBOR payload can be
up to 4 KB, and the circuit is re-rendered (from
`examples/cwt_test.template.circom`) and re-compiled automatically for the
actual credential sizes, so no template code ever needs editing.

## Unit Tests

Each cryptographic building block has a standalone unit test that checks the
circuit against a Python reference implementation:

```bash
cd examples/unit_test/cbor && bash test.sh   # CBOR parse + mdoc redaction
cd examples/unit_test/emsa && bash test.sh   # EMSA-PSS encoding
cd examples/unit_test/mgf  && bash test.sh   # MGF1 mask generation
```

The CBOR test vector exercises short and 1-byte-extended CBOR headers,
tstr/bstr values, an empty value and a partial disclosure mask.

# Acknowledgements

This project builds upon open-source software including:

* [`vole-zk-prover`](https://github.com/holonym-foundation/vole-zk-prover)
  (Holonym Foundation), vendored in `vole_zk_prover/`;
* the Circom bigint/RSA-PSS circuits and the blind RSA-PSS experiment
  pipeline of [`blindRSANotary`](https://github.com/marcozecchini/blindRSANotary)
  (NDSS 2026 paper "ACTS: Attestations of Contents in TLS Sessions"), from
  which this repository originates;
* [`circomlib`](https://github.com/iden3/circomlib) (iden3).
