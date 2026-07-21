"""End-to-end driver for the CWT redaction experiment:

  CWT (COSE_Sign1, RSA-PSS) -> in-circuit issuer-signature verification +
  verified CBOR parse tree + path-selected mdoc-style redaction
  (examples/cbor_redact_verify.circom) -> Sha256BlindRSAPSS -> VOLE / SNARK
  proof -> notary blind signature -> unblind -> RSA-PSS verification over the
  redacted mdoc-style message.

Two credential sources are supported:
  * a synthetic CWT signed on the fly (default; flat text-keyed claims map,
    subject path []);
  * a real EU Digital COVID Certificate test vector via --eudcc (PS256,
    RSA-2048; default subject path -260,1 = the eu_dgc_v1 map).
"""
import argparse
import json
import subprocess

from cwt_redact.eudcc import load_eudcc
from cwt_redact.finalize import verify_final_signature
from cwt_redact.issue import issue
from cwt_redact.prepare import DEFAULT_NAMESPACE, prepare
from cwt_redact.present import build_presentation, verify_presentation
from cwt_redact.validate import validate


def parse_args():
    parser = argparse.ArgumentParser(
        description="Redact a CWT credential in zero knowledge and have the "
                    "result blind-signed by a notary."
    )
    parser.add_argument("--proof", required=True,
                        help="Choose between 'vole', 'snark' or 'none' (witness only).")
    parser.add_argument("--claims", default=None,
                        help="JSON file with the claims map for the synthetic credential "
                             "(str values -> tstr, {\"hex\": \"...\"} -> bstr). "
                             "Default: built-in sample.")
    parser.add_argument("--eudcc", default=None,
                        help="dgc-testdata JSON file with a real PS256 EUDCC, e.g. "
                             "examples/unit_test/cose_real/eudcc_CO1.json. "
                             "Mutually exclusive with --claims.")
    parser.add_argument("--path", default=None,
                        help="Comma-separated map keys leading to the subject map "
                             "(ints or strings), e.g. '-260,1'. Default: '' for the "
                             "synthetic credential, '-260,1' with --eudcc.")
    parser.add_argument("--mask", default=None,
                        help="Comma-separated disclosure mask for the off-circuit "
                             "presentation, e.g. '1,0,1,1' (the signed digest list "
                             "commits to ALL entries regardless). Default: disclose "
                             "even-indexed entries.")
    parser.add_argument("--namespace", default=DEFAULT_NAMESPACE.decode(),
                        help="mdoc-style namespace string.")
    parser.add_argument("--max-key-len", type=int, default=None,
                        help="Max raw CBOR bytes per elementIdentifier (default: auto).")
    parser.add_argument("--max-value-len", type=int, default=None,
                        help="Max raw CBOR bytes per elementValue (default: auto).")
    parser.add_argument("--issuer-key", default="issuer_key.pem",
                        help="Issuer RSA-2048 PEM key for the synthetic credential "
                             "(generated if missing).")
    parser.add_argument("--notary-key", default="notary_key.pem",
                        help="Notary RSA-2048 PEM key (generated if missing).")
    parser.add_argument("--credential-out", default="cwt_credential.bin",
                        help="Where to store the signed synthetic COSE_Sign1 credential.")
    parser.add_argument("--signature-out", default="signature_cwt.bin",
                        help="Where to store the unblinded notary signature.")
    return parser.parse_args()


def load_claims(path):
    if path is None:
        return None
    with open(path) as f:
        raw = json.load(f)
    claims = {}
    for key, value in raw.items():
        if isinstance(value, dict) and "hex" in value:
            claims[key] = bytes.fromhex(value["hex"])
        else:
            claims[key] = str(value)
    return claims


def parse_path(s):
    if not s:
        return []
    hops = []
    for tok in s.split(","):
        tok = tok.strip()
        try:
            hops.append(int(tok))
        except ValueError:
            hops.append(tok)
    return hops


def main():
    args = parse_args()
    if args.proof not in ("vole", "snark", "none"):
        raise SystemExit("--proof must be 'vole', 'snark' or 'none'")
    if args.eudcc and args.claims:
        raise SystemExit("--eudcc and --claims are mutually exclusive")

    if args.eudcc:
        # [ISSUER] a real, already-issued EU Digital COVID Certificate
        cred = load_eudcc(args.eudcc)
        path = parse_path(args.path if args.path is not None else "-260,1")
    else:
        # [ISSUER] sign a synthetic CWT credential (COSE_Sign1, RSA-PSS)
        cred = issue(claims=load_claims(args.claims),
                     key_path=args.issuer_key,
                     out_path=args.credential_out)
        path = parse_path(args.path if args.path is not None else "")

    # [HOLDER] build the circuit inputs and render the circuit for these sizes
    ctx = prepare(cred, path=path,
                  namespace=args.namespace.encode(),
                  max_key_len=args.max_key_len,
                  max_value_len=args.max_value_len,
                  notary_key_path=args.notary_key)
    print(f"subject entries committed in the digest list: {ctx['n_fields']}")

    # [HOLDER] compile the circuit and generate the witness
    subprocess.run(["bash", "examples/gen-cwt-r1cs-and-wtns.sh"], check=True)

    message, blinded = validate(ctx)
    with open("blinded_cwt.bin", "wb") as f:
        f.write(blinded)

    # [HOLDER] prove that the blinded message was computed honestly
    if args.proof in ("vole", "snark"):
        subprocess.run(["./target/release/cwt_prove", args.proof], check=True)

    # [NOTARY] blind-sign the circuit's blinded output; [HOLDER] unblind and
    # verify — all via rust-blind-rsa-signatures (src/bin/cwt_notary.rs)
    subprocess.run([ctx["notary_bin"], "finalize", ctx["notary_key_path"],
                    ctx["message_out"], ctx["blind_ctx_path"],
                    "blinded_cwt.bin", args.signature_out], check=True)

    # independent re-verification of the final signature with `cryptography`
    sig = verify_final_signature(message, args.signature_out,
                                 notary_key_path=args.notary_key)

    # [HOLDER] off-circuit selective disclosure: build a presentation that
    # reveals only the masked entries, then [VERIFIER] check it
    if args.mask is not None:
        mask = [int(b) for b in args.mask.split(",")]
    else:
        mask = [1 if i % 2 == 0 else 0 for i in range(ctx["n_fields"])]
    build_presentation(ctx, mask, sig)
    verify_presentation(notary_key_path=args.notary_key)


if __name__ == "__main__":
    main()
