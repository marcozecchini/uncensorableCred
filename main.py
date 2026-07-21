"""End-to-end driver for the CWT redaction experiment:

  CWT (COSE_Sign1, RSA-PSS) -> in-circuit issuer-signature verification +
  minimal CBOR parse + mdoc-style redaction (examples/cbor_redact_verify.circom)
  -> Sha256BlindRSAPSS -> VOLE / SNARK proof -> notary blind signature ->
  unblind -> RSA-PSS verification over the redacted mdoc-style message.
"""
import argparse
import json
import subprocess

from cwt_redact.issue import issue
from cwt_redact.prepare import (DEFAULT_MAX_KEY_LEN, DEFAULT_MAX_VALUE_LEN,
                                DEFAULT_NAMESPACE, DEFAULT_PLACEHOLDER, prepare)
from cwt_redact.validate import validate
from cwt_redact.finalize import finalize


def parse_args():
    parser = argparse.ArgumentParser(
        description="Redact a CWT credential in zero knowledge and have the "
                    "result blind-signed by a notary."
    )
    parser.add_argument("--proof", required=True,
                        help="Choose between 'vole', 'snark' or 'none' (witness only).")
    parser.add_argument("--claims", default=None,
                        help="JSON file with the claims map (str values -> tstr, "
                             "{\"hex\": \"...\"} values -> bstr). Default: built-in sample.")
    parser.add_argument("--mask", default=None,
                        help="Comma-separated disclosure mask, e.g. '1,0,1,1'. "
                             "Default: disclose even-indexed claims.")
    parser.add_argument("--namespace", default=DEFAULT_NAMESPACE.decode(),
                        help="mdoc-style namespace string.")
    parser.add_argument("--max-key-len", type=int, default=DEFAULT_MAX_KEY_LEN)
    parser.add_argument("--max-value-len", type=int, default=DEFAULT_MAX_VALUE_LEN)
    parser.add_argument("--placeholder", type=int, default=DEFAULT_PLACEHOLDER,
                        help="Placeholder byte for redacted fields (default 0).")
    parser.add_argument("--issuer-key", default="issuer_key.pem",
                        help="Issuer RSA-2048 PEM key (generated if missing).")
    parser.add_argument("--notary-key", default="notary_key.pem",
                        help="Notary RSA-2048 PEM key (generated if missing).")
    parser.add_argument("--credential-out", default="cwt_credential.bin",
                        help="Where to store the signed COSE_Sign1 credential.")
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


def main():
    args = parse_args()
    if args.proof not in ("vole", "snark", "none"):
        raise SystemExit("--proof must be 'vole', 'snark' or 'none'")

    # [ISSUER] sign a CWT credential (COSE_Sign1, RSA-PSS)
    cred = issue(claims=load_claims(args.claims),
                 key_path=args.issuer_key,
                 out_path=args.credential_out)
    n_fields = len(cred["fields"])

    if args.mask is not None:
        mask = [int(b) for b in args.mask.split(",")]
    else:
        mask = [1 if i % 2 == 0 else 0 for i in range(n_fields)]

    # [HOLDER] build the circuit inputs and render the circuit for these sizes
    ctx = prepare(cred, mask,
                  namespace=args.namespace.encode(),
                  max_key_len=args.max_key_len,
                  max_value_len=args.max_value_len,
                  placeholder=args.placeholder,
                  notary_key_path=args.notary_key)

    # [HOLDER] compile the circuit and generate the witness
    subprocess.run(["bash", "examples/gen-cwt-r1cs-and-wtns.sh"], check=True)

    message, blinded = validate(ctx)

    # [HOLDER] prove that the blinded message was computed honestly
    if args.proof in ("vole", "snark"):
        subprocess.run(["./target/release/cwt_prove", args.proof], check=True)

    # [NOTARY] blind-sign; [HOLDER] unblind and verify the final signature
    finalize(ctx, message, blinded,
             notary_key_path=args.notary_key,
             sig_out=args.signature_out)


if __name__ == "__main__":
    main()
