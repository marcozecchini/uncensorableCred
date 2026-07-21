"""Differential test of the hand-rolled CBOR codec (cwt_redact.cbor_tree)
against independent references:

  1. RFC 8949 Appendix A test vectors (the subset within our grammar):
     encode() must produce the official hex, and the item table must decode
     it back to the original value.
  2. Round-trip: rebuild(build_item_table(encode(x))) == x on edge cases
     (head-size boundaries 23/24/255/256/65535/65536/2^32-1, empty
     strings/containers, deep nesting) and on the experiment credentials.
  3. Differential vs the `cbor2` reference library (pip install cbor2,
     test-only dependency): encode() == cbor2.dumps() and our item-table
     decoding == cbor2.loads(), on the edge cases, on seeded random fuzz
     structures, and on the real EUDCC payload (whose canonical re-encoding
     must also round-trip byte-identical).

Usage:  python3 cbor_diff.py
"""
import json
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
from cwt_redact.cbor_tree import build_item_table, encode, raw

# ---------------------------------------------------------------- rebuild
def rebuild(buf, items=None, t=0):
    """Decode item t (and its subtree) of the item table back into a python
    value — this is our *decoder*, checked against independent references."""
    if items is None:
        items = build_item_table(buf)
    it = items[t]
    if it["major"] == 0:
        return it["arg"]
    if it["major"] == 1:
        return -1 - it["arg"]
    content = buf[it["off"] + it["hdrLen"]:it["end"]]
    if it["major"] == 2:
        return content
    if it["major"] == 3:
        return content.decode("utf-8")
    children = sorted((u for u in range(len(items))
                       if u != t and items[u]["parent"] == t),
                      key=lambda u: items[u]["childIdx"])
    vals = [rebuild(buf, items, u) for u in children]
    if it["major"] == 4:
        return vals
    return {vals[i]: vals[i + 1] for i in range(0, len(vals), 2)}


# ------------------------------------------- 1. RFC 8949 Appendix A vectors
RFC8949_VECTORS = [
    (0, "00"), (1, "01"), (10, "0a"), (23, "17"), (24, "1818"), (25, "1819"),
    (100, "1864"), (1000, "1903e8"), (1000000, "1a000f4240"),
    (-1, "20"), (-10, "29"), (-100, "3863"), (-1000, "3903e7"),
    (b"", "40"), (bytes.fromhex("01020304"), "4401020304"),
    ("", "60"), ("a", "6161"), ("IETF", "6449455446"),
    ("ü", "62c3bc"), ("水", "63e6b0b4"),
    ([], "80"), ([1, 2, 3], "83010203"),
    ([1, [2, 3], [4, 5]], "8301820203820405"),
    ({}, "a0"), ({1: 2, 3: 4}, "a201020304"),
    ({"a": 1, "b": [2, 3]}, "a26161016162820203"),
    (["a", {"b": "c"}], "826161a161626163"),
]


def test_rfc8949():
    for value, hexa in RFC8949_VECTORS:
        assert encode(value) == bytes.fromhex(hexa), f"encode mismatch for {value!r}"
        assert rebuild(bytes.fromhex(hexa)) == value, f"decode mismatch for {hexa}"
    print(f"1. RFC 8949 Appendix A vectors: {len(RFC8949_VECTORS)} PASSED")


# ---------------------------------------------------- 2. edge-case roundtrip
EDGE_CASES = [
    23, 24, 255, 256, 65535, 65536, 2**32 - 1,
    -24, -25, -256, -257, -65536, -65537, -(2**32),
    "x" * 23, "x" * 24, "x" * 255, "x" * 256,
    b"\x00" * 23, b"\xff" * 24,
    [], {}, [[]], {0: {}}, [0] * 23, [0] * 24,
    {i: str(i) for i in range(24)},
    {1: "AT", 4: 1620000000, -260: {1: {"ver": "1.2.1",
        "nam": {"fn": "Rossi", "gn": "Mario"}, "dob": "1990-01-01",
        "v": [{"tg": "840539006", "dn": 2}]}}},
]


def test_roundtrip():
    for value in EDGE_CASES:
        assert rebuild(encode(value)) == value, f"roundtrip failed for {value!r}"
    print(f"2. edge-case roundtrips: {len(EDGE_CASES)} PASSED")


# ------------------------------------------------- 3. differential vs cbor2
def rand_value(rng, depth=0):
    kinds = ["int", "str", "bytes"] + (["list", "dict"] if depth < 3 else [])
    kind = rng.choice(kinds)
    if kind == "int":
        v = rng.choice([0, 23, 24, 255, 256, 65535, 65536,
                        rng.randrange(2**32)])
        return v if rng.random() < 0.5 else -1 - v
    if kind == "str":
        return "s" * rng.choice([0, 1, 23, 24, 40])
    if kind == "bytes":
        return bytes(rng.randrange(256) for _ in range(rng.choice([0, 5, 24])))
    if kind == "list":
        return [rand_value(rng, depth + 1) for _ in range(rng.randrange(4))]
    keys = list({rng.choice([rng.randrange(1000) - 500, "k" + str(rng.randrange(100))])
                 for _ in range(rng.randrange(4))})
    return {k: rand_value(rng, depth + 1) for k in keys}


def test_cbor2(script_dir):
    try:
        import cbor2
    except ImportError:
        print("3. cbor2 differential: SKIPPED (pip install cbor2 to enable)")
        return

    cases = list(EDGE_CASES)
    rng = random.Random(18013)
    cases += [{0: rand_value(rng)} for _ in range(500)]
    for value in cases:
        ours = encode(value)
        theirs = cbor2.dumps(value)
        assert ours == theirs, f"encode differs from cbor2 for {value!r}"
        assert rebuild(ours) == cbor2.loads(ours), f"decode differs from cbor2 for {value!r}"
    print(f"3a. cbor2 differential (edge + 500 fuzz): {len(cases)} PASSED")

    # real EUDCC payload: decode agreement + canonical re-encoding roundtrip
    eudcc = script_dir.parent / "cose_real" / "eudcc_CO1.json"
    d = json.loads(eudcc.read_text())
    cose = bytes.fromhex(d["COSE"])
    # extract the payload bstr from the COSE_Sign1 envelope via cbor2
    payload = cbor2.loads(cose).value[2]
    assert rebuild(payload) == cbor2.loads(payload), "EUDCC decode differs from cbor2"
    assert encode(cbor2.loads(payload)) == payload, \
        "re-encoding the EUDCC payload is not byte-identical (non-canonical?)"
    print("3b. real EUDCC payload: decode == cbor2, re-encode byte-identical PASSED")


if __name__ == "__main__":
    here = Path(__file__).resolve().parent
    test_rfc8949()
    test_roundtrip()
    test_cbor2(here)
    print("CBOR codec differential test PASSED")
