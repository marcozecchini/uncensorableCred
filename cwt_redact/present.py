"""Off-circuit selective disclosure over the notary-signed digest list.

The circuit commits to ALL subject entries via salted digests (MdocDigest)
and the notary blind-signs that MSO-style list. Disclosure is then a purely
local act — mirroring the ISO/IEC 18013-5 model: the holder builds a
*presentation* containing the signed digest list plus, for each disclosed
entry only, its preimage data (identifier, value, random salt). A verifier
checks the notary RSA-PSS signature and recomputes the digests of the
disclosed items; undisclosed entries stay hidden behind their salted digests.
Many different presentations can be derived from one signed list.
"""
import hashlib
import json

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

from .cbor_tree import item_preimage

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
    presentation = {
        "namespace": ctx["namespace"].decode(),
        "nFields": ctx["n_fields"],
        "maxKeyLen": ctx["max_key_len"],
        "maxValueLen": ctx["max_value_len"],
        "msoMessage": ctx["expected_message"].hex(),
        "signature": sig_bytes.hex(),
        "disclosedItems": disclosed,
    }
    with open(out_path, "w") as f:
        json.dump(presentation, f, indent=2)
    return presentation


def verify_presentation(pres_path="mdoc_presentation.json",
                        notary_key_path="notary_key.pem"):
    """Verifier side: checks the notary signature over the digest list and
    that every disclosed item hashes to its committed digest."""
    with open(pres_path) as f:
        pres = json.load(f)
    message = bytes.fromhex(pres["msoMessage"])
    sig = bytes.fromhex(pres["signature"])
    ns = pres["namespace"].encode()
    n_fields = pres["nFields"]

    # digest-list structure
    assert message[0] == len(ns) and message[1:1 + len(ns)] == ns, "namespace mismatch"
    assert message[1 + len(ns)] == n_fields, "nFields mismatch"
    assert len(message) == 2 + len(ns) + 33 * n_fields, "malformed digest list"

    # notary RSA-PSS signature over the digest list
    with open(notary_key_path, "rb") as f:
        pk = serialization.load_pem_private_key(f.read(), password=None).public_key()
    pk.verify(sig, message,
              padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=SALT_LEN),
              hashes.SHA256())

    # each disclosed item must hash to its committed digest
    for item in pres["disclosedItems"]:
        did = item["digestID"]
        assert 0 <= did < n_fields, "digestID out of range"
        pre = item_preimage(did,
                            bytes.fromhex(item["random"]),
                            bytes.fromhex(item["elementIdentifier"]),
                            bytes.fromhex(item["elementValue"]),
                            pres["maxKeyLen"], pres["maxValueLen"])
        base = 2 + len(ns) + 33 * did
        assert message[base] == did, "digestID slot mismatch"
        assert hashlib.sha256(pre).digest() == message[base + 1:base + 33], \
            f"digest mismatch for disclosed item {did}"

    print(f"Presentation verified: {len(pres['disclosedItems'])}/{n_fields} "
          "entries disclosed against the notary-signed digest list")
    return pres
