"""Build examples/cwt_input.json and render examples/cwt_test.circom.

Circuit sizes are baked at compile time by replacing the {{...}} placeholders
of examples/cwt_test.template.circom, so the circuit is re-compilable for any
credential size without editing the templates. Unless overridden, the layout
bounds (maxItems, maxKeyLen, maxValueLen) are auto-sized from the actual
credential.
"""
import json
import secrets
import subprocess
from pathlib import Path

from .cbor_tree import mso_message, raw, tree_witness
from .issue import load_or_generate_key

W_LIMB = 64
K_LIMBS = 32
E_BITS = 17
MGF_COUNT = 7

DEFAULT_NAMESPACE = b"org.iso.18013.5.1.acts"
DEFAULT_MAX_PATH_KEY_LEN = 8


def limbs(n: int, k: int = K_LIMBS, w: int = W_LIMB):
    """Split n into k limbs of w bits (little-endian limbs, decimal strings),
    the bigint convention expected by the circuits."""
    mask = (1 << w) - 1
    return [str((n >> (w * i)) & mask) for i in range(k)]


def message_len(n_fields, ns_len):
    return 2 + ns_len + n_fields * 33


def prepare(cred, path=(),
            namespace=DEFAULT_NAMESPACE,
            max_key_len=None,
            max_value_len=None,
            max_path_key_len=DEFAULT_MAX_PATH_KEY_LEN,
            notary_key_path="notary_key.pem",
            notary_bin="./target/release/cwt_notary",
            message_out="mdoc_message.bin",
            blind_ctx_path="blind_ctx.json",
            examples_dir="examples"):
    """Write cwt_input.json and render cwt_test.circom from the template.

    `cred` is the dict returned by issue.issue() or eudcc.load_eudcc();
    `path` is the list of map keys (ints or strs) leading to the subject map
    ([] = the root claims map). The circuit commits to ALL subject entries
    (no disclosure mask in-circuit); disclosure happens later via present.py.
    Returns the context needed by validate.validate() and present.py.
    """
    payload = cred["payload"]
    if len(payload) > 4096:
        raise ValueError("CWT payload exceeds the 4 KB experiment bound")

    tree_inputs, items, subj, entries = tree_witness(
        payload, list(path), max_path_key_len=max_path_key_len)
    n_fields = len(entries)

    key_need = max(items[k]["end"] - items[k]["off"] for k, _ in entries)
    val_need = max(items[v]["end"] - items[v]["off"] for _, v in entries)
    if max_key_len is None:
        max_key_len = max(key_need, 8)
    elif key_need > max_key_len:
        raise ValueError(f"an entry key needs {key_need} bytes > maxKeyLen={max_key_len}")
    if max_value_len is None:
        max_value_len = max(val_need, 16)
    elif val_need > max_value_len:
        raise ValueError(f"an entry value needs {val_need} bytes > maxValueLen={max_value_len}")

    notary = load_or_generate_key(notary_key_path).public_key().public_numbers()
    randoms = [secrets.token_bytes(16) for _ in range(n_fields)]

    # The MSO-style digest list is deterministic given the randoms, so it can
    # be computed BEFORE running the circuit and blinded with the fork of
    # rust-blind-rsa-signatures (which exposes the PSS salt and the blinding
    # secret): the crate's blind_msg is the independent reference the circuit
    # output is checked against, exactly as in the original experiment.
    message = mso_message(payload, items, entries, randoms, namespace,
                          max_key_len, max_value_len)
    Path(message_out).write_bytes(message)

    if not Path(notary_bin).exists():
        raise SystemExit(f"{notary_bin} not found: run RUSTFLAGS=-Awarnings cargo build --release first")
    subprocess.run([notary_bin, "blind", notary_key_path, message_out, blind_ctx_path],
                   check=True)
    with open(blind_ctx_path) as f:
        blind_ctx = json.load(f)
    blind_salt = bytes(blind_ctx["salt"])
    r_limbs = blind_ctx["r"]
    r = sum(int(l) << (W_LIMB * i) for i, l in enumerate(r_limbs))

    inputs = {
        "payload": list(payload),
        "prot": list(cred["prot"]),
        "issuerSig": limbs(int.from_bytes(cred["sig"], "big")),
        "issuerPssSalt": list(cred["pss_salt"]),
        "issuerExp": limbs(cred["e"]),
        "issuerModulus": limbs(cred["n"]),
        "itemRandom": [list(rb) for rb in randoms],
        "namespace": list(namespace),
        "blindSalt": list(blind_salt),
        "r": r_limbs,
        "notaryExp": limbs(notary.e),
        "notaryModulus": limbs(notary.n),
    }
    inputs.update(tree_inputs)

    examples = Path(examples_dir)
    (examples / "cwt_input.json").write_text(json.dumps(inputs, indent=2))

    template = (examples / "cwt_test.template.circom").read_text()
    circuit = (template
               .replace("{{PAYLOAD_LEN}}", str(len(payload)))
               .replace("{{PROT_LEN}}", str(len(cred["prot"])))
               .replace("{{MAX_ITEMS}}", str(len(items)))
               .replace("{{N_FIELDS}}", str(n_fields))
               .replace("{{MAX_KEY_LEN}}", str(max_key_len))
               .replace("{{MAX_VALUE_LEN}}", str(max_value_len))
               .replace("{{PATH_DEPTH}}", str(len(path)))
               .replace("{{MAX_PATH_KEY_LEN}}", str(max_path_key_len))
               .replace("{{NS_LEN}}", str(len(namespace))))
    (examples / "cwt_test.circom").write_text(circuit)

    return {
        "expected_message": message,
        "expected_blind_msg": bytes(blind_ctx["blind_msg"]),
        "n_fields": n_fields,
        "namespace": bytes(namespace),
        "max_key_len": max_key_len,
        "max_value_len": max_value_len,
        "items": [{
            "digest_id": i,
            "random": randoms[i],
            "key_raw": raw(payload, items, ki),
            "value_raw": raw(payload, items, vi),
        } for i, (ki, vi) in enumerate(entries)],
        "blind_salt": blind_salt,
        "r": r,
        "notary_n": notary.n,
        "notary_e": notary.e,
        "message_out": message_out,
        "blind_ctx_path": blind_ctx_path,
        "notary_bin": notary_bin,
        "notary_key_path": notary_key_path,
    }
