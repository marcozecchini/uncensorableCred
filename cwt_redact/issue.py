"""Issue a test CWT (RFC 8392) wrapped in COSE_Sign1 (RFC 9052), signed with
RSA-PSS (SHA-256, 32-byte salt, RSA-2048) — the credential format consumed by
examples/cbor_redact_verify.circom.
"""
import hashlib

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from .cbor_min import enc_head, encode_claims

# COSE protected header {1: -37} = alg PS256 (RSASSA-PSS with SHA-256)
PROT_BYTES = bytes.fromhex("a1013824")

HASH_LEN = 32
SALT_LEN = 32
EM_LEN = 256  # RSA-2048, matching the circuit parameters w=64, k=32

# Sample credential used by the experiment when no claims file is given.
# Values are str (CBOR tstr) or bytes (CBOR bstr).
DEFAULT_CLAIMS = {
    "family_name": "Rossi",
    "given_name": "Mario",
    "birth_date": "1985-03-01",
    "document_number": "CA00000AA",
    "nationality": "IT",
    "resident_city": "Rome",
    "portrait": bytes(range(48)),
    "driving_privileges": "AM/B",
}


def load_or_generate_key(path, bits=2048):
    """Load an unencrypted PEM RSA private key, generating it if missing."""
    try:
        with open(path, "rb") as f:
            key = serialization.load_pem_private_key(f.read(), password=None)
    except FileNotFoundError:
        key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
        with open(path, "wb") as f:
            f.write(key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            ))
    if key.key_size != bits:
        raise ValueError(f"{path}: expected an RSA-{bits} key, got RSA-{key.key_size}")
    return key


def sig_structure(payload: bytes, prot: bytes = PROT_BYTES) -> bytes:
    """COSE Sig_structure for Signature1 with empty external_aad (RFC 9052 §4.4)."""
    return (b"\x84"
            + enc_head(3, 10) + b"Signature1"
            + enc_head(2, len(prot)) + prot
            + b"\x40"
            + enc_head(2, len(payload)) + payload)


def cose_sign1(payload: bytes, sig: bytes, prot: bytes = PROT_BYTES) -> bytes:
    """Full COSE_Sign1 message: [protected, {}, payload, signature]."""
    return (b"\x84"
            + enc_head(2, len(prot)) + prot
            + b"\xa0"
            + enc_head(2, len(payload)) + payload
            + enc_head(2, len(sig)) + sig)


def mgf1(seed: bytes, mask_len: int) -> bytes:
    counter, output = 0, b""
    while len(output) < mask_len:
        output += hashlib.sha256(seed + counter.to_bytes(4, "big")).digest()
        counter += 1
    return output[:mask_len]


def recover_pss_salt(sig: bytes, e: int, n: int, tbs: bytes) -> bytes:
    """Recover the PSS salt from a signature (EMSA-PSS decode of sig^e mod n).

    The circuit verifies the signature by *re-encoding* EMSA-PSS with this
    salt as a witness and comparing against sig^e mod n, so the salt must be
    extracted here, outside the circuit.
    """
    em = pow(int.from_bytes(sig, "big"), e, n).to_bytes(EM_LEN, "big")
    assert em[-1] == 0xBC, "invalid PSS trailer"
    db_len = EM_LEN - HASH_LEN - 1
    masked_db, h = em[:db_len], em[db_len:db_len + HASH_LEN]
    db = bytes(a ^ b for a, b in zip(masked_db, mgf1(h, db_len)))
    db = bytes([db[0] & 0x7F]) + db[1:]
    ps_len = db_len - SALT_LEN - 1
    assert all(b == 0 for b in db[:ps_len]) and db[ps_len] == 0x01, "invalid PSS padding"
    salt = db[-SALT_LEN:]
    m_hash = hashlib.sha256(tbs).digest()
    assert hashlib.sha256(b"\x00" * 8 + m_hash + salt).digest() == h, "PSS hash mismatch"
    return salt


def issue(claims=None, key_path="issuer_key.pem", out_path="cwt_credential.bin"):
    """Build and sign a test credential; returns everything the prover needs."""
    sk = load_or_generate_key(key_path)
    pub = sk.public_key().public_numbers()

    payload, fields = encode_claims(claims if claims is not None else DEFAULT_CLAIMS)
    if len(payload) > 4096:
        raise ValueError("CWT payload exceeds the 4 KB experiment bound")

    tbs = sig_structure(payload)
    sig = sk.sign(
        tbs,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=SALT_LEN),
        hashes.SHA256(),
    )
    salt = recover_pss_salt(sig, pub.e, pub.n, tbs)

    with open(out_path, "wb") as f:
        f.write(cose_sign1(payload, sig))

    return {
        "payload": payload,
        "fields": fields,
        "prot": PROT_BYTES,
        "sig": sig,
        "pss_salt": salt,
        "n": pub.n,
        "e": pub.e,
    }
