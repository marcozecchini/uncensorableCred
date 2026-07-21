"""Build examples/cwt_input.json and render examples/cwt_test.circom.

Circuit sizes are baked at compile time by replacing the {{...}} placeholders
of examples/cwt_test.template.circom, so the circuit is re-compilable for any
credential size without editing the templates.
"""
import json
import math
import secrets
from pathlib import Path

from .issue import load_or_generate_key

W_LIMB = 64
K_LIMBS = 32
E_BITS = 17
MGF_COUNT = 7

DEFAULT_NAMESPACE = b"org.iso.18013.5.1.acts"
DEFAULT_MAX_KEY_LEN = 32
DEFAULT_MAX_VALUE_LEN = 64
DEFAULT_PLACEHOLDER = 0x00  # redaction placeholder byte (configurable)


def limbs(n: int, k: int = K_LIMBS, w: int = W_LIMB):
    """Split n into k limbs of w bits (little-endian limbs, decimal strings),
    the bigint convention expected by the circuits."""
    mask = (1 << w) - 1
    return [str((n >> (w * i)) & mask) for i in range(k)]


def message_len(n_fields, max_key_len, max_value_len, ns_len):
    return 2 + ns_len + n_fields * (21 + max_key_len + max_value_len)


def expected_message(fields, mask, randoms, namespace,
                     max_key_len=DEFAULT_MAX_KEY_LEN,
                     max_value_len=DEFAULT_MAX_VALUE_LEN,
                     placeholder=DEFAULT_PLACEHOLDER) -> bytes:
    """Reference (off-circuit) computation of the mdoc-style message produced
    by MdocRedact — must stay byte-per-byte in sync with the circuit."""
    msg = bytes([len(namespace)]) + bytes(namespace) + bytes([len(fields)])
    for i, f in enumerate(fields):
        disclosed = mask[i]
        item = bytes([i, disclosed])
        item += bytes(randoms[i]) if disclosed else bytes([placeholder]) * 16
        item += bytes([f["valMajor"] if disclosed else placeholder])
        item += bytes([f["keyLen"]])
        item += f["key"] + b"\x00" * (max_key_len - f["keyLen"])
        item += bytes([f["valLen"] if disclosed else placeholder])
        if disclosed:
            item += f["value"] + b"\x00" * (max_value_len - f["valLen"])
        else:
            item += bytes([placeholder]) * max_value_len
        msg += item
    return msg


def prepare(cred, mask,
            namespace=DEFAULT_NAMESPACE,
            max_key_len=DEFAULT_MAX_KEY_LEN,
            max_value_len=DEFAULT_MAX_VALUE_LEN,
            placeholder=DEFAULT_PLACEHOLDER,
            notary_key_path="notary_key.pem",
            examples_dir="examples"):
    """Write cwt_input.json and render cwt_test.circom from the template.

    `cred` is the dict returned by issue.issue(); `mask` is a list of 0/1.
    Returns the context needed by validate.validate().
    """
    fields = cred["fields"]
    n_fields = len(fields)
    if len(mask) != n_fields:
        raise ValueError("mask length must equal the number of claims")
    for f in fields:
        if f["keyLen"] > max_key_len:
            raise ValueError(f"claim key longer than maxKeyLen={max_key_len}")
        if f["valLen"] > max_value_len:
            raise ValueError(f"claim value longer than maxValueLen={max_value_len}")

    # blinding side (same inputs Sha256BlindRSAPSS already takes)
    notary = load_or_generate_key(notary_key_path).public_key().public_numbers()
    while True:
        r = secrets.randbelow(notary.n - 2) + 2
        if math.gcd(r, notary.n) == 1:
            break
    blind_salt = secrets.token_bytes(32)
    randoms = [secrets.token_bytes(16) for _ in fields]

    inputs = {
        "payload": list(cred["payload"]),
        "prot": list(cred["prot"]),
        "issuerSig": limbs(int.from_bytes(cred["sig"], "big")),
        "issuerPssSalt": list(cred["pss_salt"]),
        "issuerExp": limbs(cred["e"]),
        "issuerModulus": limbs(cred["n"]),
        "mask": [int(m) for m in mask],
        "keyLen": [f["keyLen"] for f in fields],
        "valLen": [f["valLen"] for f in fields],
        "valMajor": [f["valMajor"] for f in fields],
        "itemRandom": [list(rb) for rb in randoms],
        "namespace": list(namespace),
        "blindSalt": list(blind_salt),
        "r": limbs(r),
        "notaryExp": limbs(notary.e),
        "notaryModulus": limbs(notary.n),
    }

    examples = Path(examples_dir)
    (examples / "cwt_input.json").write_text(json.dumps(inputs, indent=2))

    template = (examples / "cwt_test.template.circom").read_text()
    circuit = (template
               .replace("{{PAYLOAD_LEN}}", str(len(cred["payload"])))
               .replace("{{PROT_LEN}}", str(len(cred["prot"])))
               .replace("{{N_FIELDS}}", str(n_fields))
               .replace("{{MAX_KEY_LEN}}", str(max_key_len))
               .replace("{{MAX_VALUE_LEN}}", str(max_value_len))
               .replace("{{NS_LEN}}", str(len(namespace)))
               .replace("{{PLACEHOLDER}}", str(placeholder)))
    (examples / "cwt_test.circom").write_text(circuit)

    return {
        "expected_message": expected_message(
            fields, [int(m) for m in mask], randoms, namespace,
            max_key_len, max_value_len, placeholder),
        "blind_salt": blind_salt,
        "r": r,
        "notary_n": notary.n,
        "notary_e": notary.e,
    }
