import json
import hashlib
import math
import os
from pathlib import Path

HASH_LEN = 32
SALT_LEN = 32  # must match HASH_LEN
MASK_LEN = 64  # adjustable as needed

assert SALT_LEN == HASH_LEN, "saltLen and hashLen must be equal"

def mgf1(seed: bytes, mask_len: int) -> bytes:
    counter = 0
    output = b""
    while len(output) < mask_len:
        C = counter.to_bytes(4, 'big')
        digest = hashlib.sha256(seed + C).digest()
        output += digest
        counter += 1
    return output[:mask_len]

def main():
    # Directory of this script
    script_dir = Path(__file__).resolve().parent

    # Generate seed
    seed_bytes = os.urandom(SALT_LEN)
    seed_array = list(seed_bytes)

    # Compute MGF1 output
    mask_bytes = mgf1(seed_bytes, MASK_LEN)
    mask_array = list(mask_bytes)

    # Write input.json
    input_path = script_dir / "input.json"
    with open(input_path, "w") as f:
        json.dump({"seed": seed_array}, f, indent=2)

    # Write expected_output.json
    output_path = script_dir / "expected_output.json"
    with open(output_path, "w") as f:
        json.dump({"mask": mask_array}, f, indent=2)

    print(f"✅ Files generated:\n- {input_path}\n- {output_path}")

if __name__ == "__main__":
    main()
