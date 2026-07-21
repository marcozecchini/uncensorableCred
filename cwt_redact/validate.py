"""Check the generated witness against an off-circuit re-computation of the
mdoc-style message and of the blinded PSS output.
"""
import hashlib
import json

HASH_LEN = 32
SALT_LEN = 32
EM_LEN = 256
DB_LEN = EM_LEN - HASH_LEN - 1
PS_LEN = EM_LEN - SALT_LEN - HASH_LEN - 2


def mgf1(seed: bytes, mask_len: int) -> bytes:
    counter, output = 0, b""
    while len(output) < mask_len:
        output += hashlib.sha256(seed + counter.to_bytes(4, "big")).digest()
        counter += 1
    return output[:mask_len]


def emsa_pss_encode(mhash: bytes, salt: bytes) -> bytes:
    """Same encoding as examples/unit_test/emsa/emsa.py (emBits = 2047)."""
    h = hashlib.sha256(b"\x00" * 8 + mhash + salt).digest()
    db = b"\x00" * PS_LEN + b"\x01" + salt
    masked_db = bytes(a ^ b for a, b in zip(db, mgf1(h, DB_LEN)))
    masked_db = bytes([masked_db[0] & 0x7F]) + masked_db[1:]
    return masked_db + h + b"\xbc"


def validate(ctx, witness_path="examples/cwt_witness.json"):
    """`ctx` is the dict returned by prepare.prepare()."""
    with open(witness_path) as f:
        wit = json.load(f)

    expected = ctx["expected_message"]
    mlen = len(expected)
    message = bytes(int(x) for x in wit[1:1 + mlen])
    blinded = bytes(int(x) for x in wit[1 + mlen:1 + mlen + EM_LEN])

    assert message == expected, "circuit mdoc-style message does not match the reference"

    # independent reference #1: the blind_msg computed by rust-blind-rsa-signatures
    assert blinded == ctx["expected_blind_msg"], \
        "circuit blinded output does not match rust-blind-rsa-signatures' blind_msg"

    # independent reference #2: python re-computation of EM * r^e mod n
    mhash = hashlib.sha256(message).digest()
    em = int.from_bytes(emsa_pss_encode(mhash, ctx["blind_salt"]), "big")
    expected_blinded = (em * pow(ctx["r"], ctx["notary_e"], ctx["notary_n"])) % ctx["notary_n"]
    assert blinded == expected_blinded.to_bytes(EM_LEN, "big"), \
        "circuit blinded output does not match the python reference"

    print("mdoc-style message and blinded output match the circuit witness "
          "(cross-checked against rust-blind-rsa-signatures)")
    return message, blinded
