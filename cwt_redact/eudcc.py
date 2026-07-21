"""Load a real EU Digital COVID Certificate test vector as the input
credential of the redaction pipeline.

Accepts the JSON format of the official dgc-testdata repository
(https://github.com/eu-digital-green-certificates/dgc-testdata): the COSE
field carries the COSE_Sign1 message, TESTCTX.CERTIFICATE the DER signing
certificate. Only PS256 (RSA-PSS/SHA-256, RSA-2048) vectors are supported —
e.g. common/2DCode/raw/CO1.json, vendored in
examples/unit_test/cose_real/eudcc_CO1.json.
"""
import base64
import json

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from .issue import SALT_LEN, recover_pss_salt, sig_structure


def _rd_head(b, i):
    ib = b[i]
    mt, ai = ib >> 5, ib & 31
    i += 1
    if ai < 24:
        return mt, ai, i
    if ai == 24:
        return mt, b[i], i + 1
    if ai == 25:
        return mt, int.from_bytes(b[i:i + 2], "big"), i + 2
    if ai == 26:
        return mt, int.from_bytes(b[i:i + 4], "big"), i + 4
    raise ValueError("unsupported CBOR head in COSE envelope")


def parse_cose_sign1(cose):
    """Extract (protected, payload, signature) from a COSE_Sign1 message."""
    i = 0
    mt, val, i = _rd_head(cose, i)
    if mt == 6:  # CBOR tag 18 (COSE_Sign1)
        mt, val, i = _rd_head(cose, i)
    if mt != 4 or val != 4:
        raise ValueError("not a COSE_Sign1 array")
    items = []
    for _ in range(4):
        mt, n, i = _rd_head(cose, i)
        if mt == 2:  # bstr
            items.append(cose[i:i + n])
            i += n
        elif mt == 5:  # unprotected header map: skip
            items.append(None)
            for _ in range(n):
                for _ in range(2):
                    mt2, n2, i = _rd_head(cose, i)
                    if mt2 in (2, 3):
                        i += n2
        else:
            raise ValueError("unexpected item in COSE_Sign1")
    prot, _, payload, sig = items
    return prot, payload, sig


def load_eudcc(path):
    """Returns the credential dict consumed by prepare.prepare()."""
    with open(path) as f:
        d = json.load(f)
    prot, payload, sig = parse_cose_sign1(bytes.fromhex(d["COSE"]))

    cert = x509.load_der_x509_certificate(base64.b64decode(d["TESTCTX"]["CERTIFICATE"]))
    pk = cert.public_key()
    if pk.key_size != 2048:
        raise ValueError(f"only RSA-2048 (PS256) vectors are supported, got {pk.key_size}")
    nums = pk.public_numbers()

    tbs = sig_structure(payload, prot)
    pk.verify(sig, tbs,
              padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=SALT_LEN),
              hashes.SHA256())
    salt = recover_pss_salt(sig, nums.e, nums.n, tbs)

    return {
        "payload": payload,
        "prot": prot,
        "sig": sig,
        "pss_salt": salt,
        "n": nums.n,
        "e": nums.e,
    }
