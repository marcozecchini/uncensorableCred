# SD-JWT output encoding — design

Goal: make the credential produced by the pipeline a **standard SD-JWT**,
verifiable by any off-the-shelf JWT/SD-JWT library, while keeping the trust
model unchanged:

* the ZK proof still attests the full chain
  *issuer-signed CWT → extracted values → salted digests → signed message*;
* **the in-circuit blinding is still performed on the exact message that the
  notary will sign** — which now is the JWS signing input of the SD-JWT
  instead of the fixed-width digest list;
* claim values remain **raw CBOR**: each JSON claim value in a Disclosure is
  the base64url of the raw CBOR span extracted from the signed CWT (agreed
  simplification: the payload may stay CBOR-encoded, what matters is that
  the envelope is an SD-JWT).

The current pipeline stages 1–2 (COSE_Sign1 RSA-PSS verification,
`CborTreeVerify` + public path + raw `keyRaw[i]`/`valRaw[i]` extraction) are
untouched. Everything below replaces stages 3–4 (`MdocDigest` +
`Sha256BlindRSAPSS` message construction).

---

## 1. Byte formats

### 1.1 Disclosure (one per subject-map entry)

For entry `i` with claim name `name_i` (text of the CBOR tstr key, head
stripped) and raw CBOR value span `val_i`:

```
disc_json_i = [ "<b64url(salt_i)>" , "<name_i>" , "<b64url(val_i)>" <spaces> ]
disclosure_i = b64url( disc_json_i )
digest_i     = b64url( SHA-256( ASCII(disclosure_i) ) )        # 43 chars
```

* `salt_i`: 16 random bytes (the existing per-entry `random16`), rendered as
  22 base64url chars — satisfies SD-JWT's ≥128-bit salt requirement.
* `name_i`: constrained in-circuit to the JSON-safe ASCII subset (no `"`,
  `\`, no control bytes) so no escaping logic is needed. The eu_dgc_v1 keys
  (`v`, `nam`, `ver`, `dob`) trivially satisfy this.
* `b64url(val_i)`: base64url of the raw CBOR item bytes — always in the
  base64url alphabet, hence always JSON-safe. A verifier decodes the CBOR
  after checking the digest.
* **Length hiding via legal JSON padding**: `<spaces>` pads `disc_json_i`
  with ASCII 0x20 before the closing `]` up to the compile-time constant
  `discLen = jsonOverhead + 22 + maxKeyLen + ceil4(4·maxValueLen/3)`.
  Whitespace between JSON tokens is legal, the disclosure stays a valid
  JSON array, and every disclosure of every credential compiled with the
  same bounds has the same length — the presentation does not leak value
  sizes, matching the hiding property of the current fixed-width preimages.
  All disclosures therefore hash the same number of SHA-256 blocks.

### 1.2 Issuer-signed JWT payload (compile-time skeleton)

```
{"_sd":["<digest_1>", ... ,"<digest_N>"],"_sd_alg":"sha-256"}
```

* Rendered by `prepare.py` into the circuit template as a constant byte
  skeleton with `N` 43-char holes; the circuit writes the in-circuit
  digests (base64url-encoded) into the holes. Payload length is a
  compile-time constant.
* Optional registered claims (`iss`, `iat`, `vct`, `cnf` for key binding)
  are additional constant bytes in the skeleton — content known to the
  holder at prepare time, no circuit logic beyond bytes-equality. `cnf`
  (holder key) is where device/key binding lands later; out of scope now.
* Digest order in `_sd`: use document order initially; the spec recommends
  an order that does not leak (sorted digests) — a permutation network is
  future hardening, not required for validity.

### 1.3 JWS signing input (the message that gets blinded and signed)

```
header      = {"alg":"PS256","typ":"dc+sd-jwt"}          # constant bytes
signing_input = ASCII( b64url(header) ‖ "." ‖ b64url(payload) )
```

`Sha256BlindRSAPSS` is instantiated **unchanged** with
`message = signing_input` (new compile-time `messageLen`). EMSA-PSS
encoding, blinding with the holder's `r`, the notary blind-sign round
(`cwt_notary blind`/`finalize`) and the unblinding are all untouched.
`SALT_LEN = 32` already equals the SHA-256 output length, which is exactly
what RFC 7518 mandates for PS256 — the unblinded signature is a valid JWS
signature with no further changes.

### 1.4 Presentation (combined format, off-circuit)

```
<b64url(header)>.<b64url(payload)>.<b64url(signature)>~<disclosure_a>~<disclosure_b>~
```

`present.py` emits this string, including only the disclosures selected by
the mask. Verification = standard SD-JWT verification: check the PS256
signature with the notary public key (any JWT library), recompute
`b64url(SHA-256(disclosure))` for each presented disclosure, require
membership in `_sd`. Withheld entries stay hidden behind their salted
digests, unlinkability across presentations is unchanged.

---

## 2. Circuit changes (`examples/cbor_redact_verify.circom` + template)

New templates, all pure byte-plumbing (no new cryptography):

1. `Base64Url(nBytes)` — maps 3-byte groups to 4 alphabet chars via a 64-entry
   lookup; the tail is handled by compile-time padding choices so `nBytes` is
   always a multiple of 3 where convenient (pad CBOR values with the JSON
   spaces *outside* the b64 segment, never inside).
2. `SdJwtDisclosure(maxKeyLen, maxValueLen)` — assembles `disc_json_i`
   (constants + salt b64 + name + value b64 + space padding), b64url-encodes
   it, hashes it with the existing `Sha256Bytes`, outputs the 32-byte digest.
   Replaces the per-entry half of `MdocDigest`.
3. `SdJwtPayload(N, skeleton…)` — b64url-encodes each digest (43 chars),
   splices them into the payload skeleton, concatenates
   `b64url(header) ‖ "." ‖ b64url(payload)`, outputs `signing_input`.
   Replaces the list-serialization half of `MdocDigest`.

Wiring: `CborTreeVerify.{keyRaw,valRaw}` → `SdJwtDisclosure[i]` →
`SdJwtPayload` → `Sha256BlindRSAPSS.message`. Public IO unchanged (issuer
key, path, blinded output).

## 3. Python / Rust mirror changes

* `cwt_redact/cbor_tree.py`: `item_preimage()`/`mso_message()` →
  `disclosure()`/`jws_payload()`/`signing_input()` producing byte-identical
  references for witness building and tests.
* `prepare.py`: render skeleton constants + new lengths into the template;
  compute expected `signing_input` (replaces `mdoc_message.bin` →
  `sdjwt_signing_input.bin`); blinding delegation to `cwt_notary blind`
  unchanged (it blinds whatever message bytes it is given).
* `present.py`: emit/verify the `~`-combined format; verify with a stock
  JWT library (e.g. `pyjwt` or `python-jose`) *in addition to* the manual
  check, as an external-compliance test.
* `validate.py`/`finalize.py`: unchanged logic, new message file name.
* Naming cleanup rides along: `MdocDigest` → `SdJwtDigest`,
  `mdoc_*.bin/json` → `sdjwt_*`, default `--namespace` dropped (SD-JWT has
  no namespace; the payload skeleton takes over its role).

## 4. Cost estimate

Per entry, the hashed bytes grow from `18 + maxK + maxV` (current preimage)
to `≈ 4/3·(overhead + maxK + 4/3·maxV) · 4/3` (JSON + double b64 expansion):
roughly **2× the SHA-256 blocks per entry**, plus ~7 blocks for the signing
input (vs 2–3 for the current digest list). With SHA-256 ≈ 30k constraints
per block and the Green Pass sizes (4 entries, maxV = 176), the addition is
≈ 0.4–0.6 M constraints on top of 2.64 M (**+15–25%**, RSA verification at
992k still dominates). Expected impact on the M4 benchmarks: proving
~6 s → ~7–8 s, setup still within the 2^22 ptau (total constraints stay
below 4.19 M — to be confirmed at first compile; 2^23 ptau is the fallback).

## 5. Compliance notes / limits

* Values are CBOR-in-b64url strings: structurally valid SD-JWT, semantics
  documented in `vct` (verifier must CBOR-decode values). Full CBOR→JSON
  transcoding in-circuit remains future work.
* No key binding yet (`cnf` + KB-JWT are off-circuit additions).
* Decoy digests, sorted `_sd`: optional hardening, off/in-circuit later.

## 6. Work plan

1. `Base64Url` gadget + unit test vs Python `base64.urlsafe_b64encode`.
2. `SdJwtDisclosure` + byte-exact unit test vs Python reference.
3. `SdJwtPayload` + signing-input test.
4. Swap into `cwt_test.template.circom`, update `prepare.py` rendering.
5. `present.py` combined format + external verification with a JWT library.
6. Full EUDCC run (Groth16/rapidsnark) + refresh README numbers.
