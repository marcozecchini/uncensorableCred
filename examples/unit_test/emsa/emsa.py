import os
import hashlib
import json
from pathlib import Path

HASH_LEN = 32        # SHA-256 output size
SALT_LEN = 32        # salt size = hashLen
EM_LEN = 256         # encoded message length (es. 2048 bit = 256 bytes)
DB_LEN = EM_LEN - HASH_LEN - 1
PS_LEN = EM_LEN - SALT_LEN - HASH_LEN - 2
MGF_COUNT = (DB_LEN + HASH_LEN - 1) // HASH_LEN  # ceil(DB_LEN / HASH_LEN)

def mgf1(seed: bytes, mask_len: int) -> bytes:
    counter = 0
    output = b""
    while len(output) < mask_len:
        C = counter.to_bytes(4, byteorder='big')
        output += hashlib.sha256(seed + C).digest()
        counter += 1
    return output[:mask_len]

def emsa_pss_encode(mhash: bytes, salt: bytes) -> bytes:
    assert len(mhash) == HASH_LEN
    assert len(salt) == SALT_LEN

    # Step 1: M' = 0x00 00 00 00 00 00 00 00 || mHash || salt
    prefix = b'\x00' * 8
    M_prime = prefix + mhash + salt
    H = hashlib.sha256(M_prime).digest()

    # Step 2: generate DB = PS || 0x01 || salt
    PS = b'\x00' * PS_LEN
    DB = PS + b'\x01' + salt

    # Step 3: generate dbMask
    dbMask = mgf1(H, DB_LEN)

    # Step 4: maskedDB = DB XOR dbMask
    maskedDB = bytes([db ^ m for db, m in zip(DB, dbMask)])

    # Step 5: zero out leftmost bits if emBits is not multiple of 8
    # In Circom usi 2047 bit (emBits), quindi MSB del primo byte va zerato
    maskedDB = bytes([maskedDB[0] & 0x7F]) + maskedDB[1:]

    # Step 6: EM = maskedDB || H || 0xbc
    EM = maskedDB + H + b'\xbc'
    assert len(EM) == EM_LEN
    return EM

def main():
    script_dir = Path(__file__).resolve().parent

    # Generate fixed message hash and random salt
    message = b"test message"
    mhash = hashlib.sha256(message).digest()
    salt = os.urandom(SALT_LEN)

    # Generate EMSA-PSS-ENCODE
    EM = emsa_pss_encode(mhash, salt)

    # Write input.json
    input_path = script_dir / "input.json"
    with open(input_path, "w") as f:
        json.dump({
            "hashed": list(mhash),
            "salt": list(salt)
        }, f, indent=2)

    # Write expected_output.json
    output_path = script_dir / "expected_output.json"
    with open(output_path, "w") as f:
        json.dump({
            "EM": list(EM)
        }, f, indent=2)

    print("✅ Files written:")
    print(f"- {input_path}")
    print(f"- {output_path}")

if __name__ == "__main__":
    main()
