"""Off-circuit selective disclosure over the notary-signed SD-JWT.

The circuit commits to ALL subject entries via salted digests and assembles
the JWS signing input of an SD-JWT whose `_sd` array carries those digests;
the notary blind-signs that signing input, so the unblinded signature is a
standard JWS (PS256) signature. Disclosure is then a purely local act, as in
SD-JWT: the holder builds a *presentation* containing the compact
`header.payload.signature` SD-JWT plus, for each disclosed entry only, its
preimage data (identifier, value, random salt). A verifier checks the JWS
signature and recomputes the digests of the disclosed items against `_sd`;
undisclosed entries stay hidden behind their salted digests. Many different
presentations can be derived from one signed SD-JWT.
"""
import base64
import hashlib
import json

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

from .cbor_tree import b64url, item_preimage

SALT_LEN = 32


def build_presentation(ctx, mask, sig_bytes, out_path="mdoc_presentation.json"):
    """`ctx` from prepare.prepare(); `mask[i]` = 1 discloses entry i."""
    if len(mask) != ctx["n_fields"]:
        raise ValueError(f"mask length must be {ctx['n_fields']}")
    disclosed = []
    for item, m in zip(ctx["items"], mask):
        if int(m):
            disclosed.append({
                "digestID": item["digest_id"],
                "random": item["random"].hex(),
                "elementIdentifier": item["key_raw"].hex(),
                "elementValue": item["value_raw"].hex(),
            })
    signing_input = ctx["expected_message"]
    sd_jwt = signing_input.decode() + "." + b64url(sig_bytes).decode()
    presentation = {
        "sdJwt": sd_jwt,
        "nFields": ctx["n_fields"],
        "maxKeyLen": ctx["max_key_len"],
        "maxValueLen": ctx["max_value_len"],
        "disclosedItems": disclosed,
    }
    with open(out_path, "w") as f:
        json.dump(presentation, f, indent=2)
    return presentation


def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def verify_presentation(pres_path="mdoc_presentation.json",
                        notary_key_path="notary_key.pem"):
    """Verifier side: checks the notary JWS (PS256) signature over the SD-JWT
    signing input and that every disclosed item hashes to a digest committed
    in the `_sd` array of the payload."""
    with open(pres_path) as f:
        pres = json.load(f)
    hdr_b64, pay_b64, sig_b64 = pres["sdJwt"].split(".")
    signing_input = (hdr_b64 + "." + pay_b64).encode("ascii")
    sig = _b64url_decode(sig_b64)
    n_fields = pres["nFields"]

    # JWS header and payload structure
    header = json.loads(_b64url_decode(hdr_b64))
    assert header["alg"] == "PS256", "unexpected JWS alg"
    payload = json.loads(_b64url_decode(pay_b64))
    assert payload["_sd_alg"] == "sha-256", "unexpected _sd_alg"
    sd = payload["_sd"]
    assert len(sd) == n_fields, "nFields mismatch"

    # notary JWS (PS256 = RSA-PSS, SHA-256, 32-byte salt) signature over the
    # signing input — verifiable by any off-the-shelf JWT library
    with open(notary_key_path, "rb") as f:
        pk = serialization.load_pem_private_key(f.read(), password=None).public_key()
    pk.verify(sig, signing_input,
              padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=SALT_LEN),
              hashes.SHA256())

    # each disclosed item must hash to its committed digest in _sd
    for item in pres["disclosedItems"]:
        did = item["digestID"]
        assert 0 <= did < n_fields, "digestID out of range"
        pre = item_preimage(did,
                            bytes.fromhex(item["random"]),
                            bytes.fromhex(item["elementIdentifier"]),
                            bytes.fromhex(item["elementValue"]),
                            pres["maxKeyLen"], pres["maxValueLen"])
        digest = hashlib.sha256(pre).digest()
        assert b64url(digest).decode() == sd[did], \
            f"digest mismatch for disclosed item {did}"

    print(f"Presentation verified: {len(pres['disclosedItems'])}/{n_fields} "
          "entries disclosed against the notary-signed SD-JWT")
    return pres
