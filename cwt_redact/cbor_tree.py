"""Canonical-CBOR item-table builder (RFC 8949 subset).

Decodes a canonical CBOR buffer (major types 0-5, definite lengths,
additional-info <= 26, i.e. args up to 2^32-1) into a flat *item table* in
document order — the witness format consumed by CborTreeVerify:

  off      byte offset of the item head
  major    CBOR major type (0=uint, 1=nint, 2=bstr, 3=tstr, 4=array, 5=map)
  arg      head argument (value for ints, byte length for strings,
           element count for containers)
  hdrLen   head length in bytes (1, 2, 3 or 5)
  end      one past the last byte of the item (subtree included)
  parent   index of the parent container item (0 for the root itself)
  childIdx position among the parent's children in document order
           (maps contribute 2*arg children: key0, value0, key1, ...)

Also provides path-based subject selection: a path is a list of map keys
(python ints or strs) leading from the root map to the subject map whose
entries are redacted.
"""


def _head(buf, i):
    ib = buf[i]
    major, ai = ib >> 5, ib & 31
    if ai < 24:
        return major, ai, 1
    if ai == 24:
        arg = buf[i + 1]
        if arg < 24:
            raise ValueError("non-canonical CBOR (1-byte arg < 24)")
        return major, arg, 2
    if ai == 25:
        arg = int.from_bytes(buf[i + 1:i + 3], "big")
        if arg < 256:
            raise ValueError("non-canonical CBOR (2-byte arg < 256)")
        return major, arg, 3
    if ai == 26:
        arg = int.from_bytes(buf[i + 1:i + 5], "big")
        if arg < 65536:
            raise ValueError("non-canonical CBOR (4-byte arg < 65536)")
        return major, arg, 5
    raise ValueError(f"unsupported CBOR additional info {ai}")


def build_item_table(buf):
    """Parse `buf` (a single CBOR item spanning the whole buffer, typically a
    map) and return the item table as a list of dicts in document order."""
    items = []
    # stack of [item index, remaining children]
    stack = []
    i = 0
    while True:
        if i >= len(buf):
            raise ValueError("truncated CBOR")
        major, arg, hdr = _head(buf, i)
        if major > 5:
            raise ValueError("tags/floats not supported inside the payload")
        t = len(items)
        if stack:
            parent = stack[-1][0]
            child_idx = items[parent]["_nchild"]
            items[parent]["_nchild"] += 1
            stack[-1][1] -= 1
        else:
            parent, child_idx = 0, 0
            if t != 0:
                raise ValueError("trailing bytes after root item")
        item = {"off": i, "major": major, "arg": arg, "hdrLen": hdr,
                "parent": parent, "childIdx": child_idx, "end": None,
                "_nchild": 0}
        items.append(item)
        if major in (4, 5):  # container
            nchild = arg * 2 if major == 5 else arg
            i += hdr
            if nchild == 0:
                item["end"] = i
            else:
                stack.append([t, nchild])
                continue
        else:  # leaf: ints have no content, strings have arg bytes
            i += hdr + (arg if major in (2, 3) else 0)
            item["end"] = i
        # close finished containers
        while stack and stack[-1][1] == 0:
            c, _ = stack.pop()
            items[c]["end"] = i
        if not stack:
            break
    if i != len(buf):
        raise ValueError("trailing bytes after root item")
    for it in items:
        del it["_nchild"]
    return items


def _children(items, c):
    return sorted((t for t in range(len(items)) if items[t]["parent"] == c and t != c),
                  key=lambda t: items[t]["childIdx"])


def raw(buf, items, t):
    """Raw CBOR bytes of item t (head + content + subtree)."""
    return buf[items[t]["off"]:items[t]["end"]]


def encode_key(key):
    """Canonical CBOR encoding of a map key given as python int or str."""
    if isinstance(key, int):
        major, val = (0, key) if key >= 0 else (1, -1 - key)
        if val < 24:
            return bytes([(major << 5) | val])
        if val < 256:
            return bytes([(major << 5) | 24, val])
        if val < 65536:
            return bytes([(major << 5) | 25]) + val.to_bytes(2, "big")
        return bytes([(major << 5) | 26]) + val.to_bytes(4, "big")
    kb = key.encode("utf-8")
    if len(kb) < 24:
        return bytes([0x60 | len(kb)]) + kb
    if len(kb) < 256:
        return bytes([0x78, len(kb)]) + kb
    raise ValueError("path key too long")


def find_subject(buf, items, path):
    """Walk `path` (list of map keys) from the root; returns
    (subject item index, [(key item, value item) per hop])."""
    subj = 0
    hops = []
    for key in path:
        if items[subj]["major"] != 5:
            raise ValueError("path hop through a non-map item")
        kb = encode_key(key)
        ch = _children(items, subj)
        for j in range(0, len(ch), 2):
            if raw(buf, items, ch[j]) == kb:
                hops.append((ch[j], ch[j + 1]))
                subj = ch[j + 1]
                break
        else:
            raise KeyError(f"path key {key!r} not found")
    if items[subj]["major"] != 5:
        raise ValueError("subject item is not a map")
    return subj, hops


def subject_entries(items, subj):
    """[(key item, value item)] of the subject map in document order."""
    ch = _children(items, subj)
    return [(ch[2 * j], ch[2 * j + 1]) for j in range(len(ch) // 2)]


def _enc_head(major, n):
    if n < 24:
        return bytes([(major << 5) | n])
    if n < 256:
        return bytes([(major << 5) | 24, n])
    if n < 65536:
        return bytes([(major << 5) | 25]) + n.to_bytes(2, "big")
    if n < 2 ** 32:
        return bytes([(major << 5) | 26]) + n.to_bytes(4, "big")
    raise ValueError("argument too large")


def encode(obj):
    """Canonical CBOR encoding of nested int/str/bytes/list/dict values
    (definite lengths, minimal heads, dict insertion order preserved)."""
    if isinstance(obj, bool):
        raise TypeError("booleans not supported")
    if isinstance(obj, int):
        return _enc_head(0, obj) if obj >= 0 else _enc_head(1, -1 - obj)
    if isinstance(obj, str):
        b = obj.encode("utf-8")
        return _enc_head(3, len(b)) + b
    if isinstance(obj, (bytes, bytearray)):
        return _enc_head(2, len(obj)) + bytes(obj)
    if isinstance(obj, (list, tuple)):
        return _enc_head(4, len(obj)) + b"".join(encode(x) for x in obj)
    if isinstance(obj, dict):
        out = _enc_head(5, len(obj))
        for k, v in obj.items():
            out += encode(k) + encode(v)
        return out
    raise TypeError(f"unsupported type {type(obj)}")


def tree_witness(buf, path, max_items=None, max_path_key_len=8):
    """Build the CborTreeVerify witness inputs for `buf` with subject `path`.

    Returns (inputs, items, subj, entries): `inputs` is a dict of the circuit
    input signals (item table, path and entry indices), `entries` the
    [(key item, value item)] list of the subject map.
    """
    items = build_item_table(buf)
    subj, hops = find_subject(buf, items, path)
    entries = subject_entries(items, subj)
    n = len(items)
    if max_items is None:
        max_items = n
    if n > max_items:
        raise ValueError("maxItems too small for this payload")

    def col(name, sentinel_root=None):
        vals = [it[name] for it in items] + [0] * (max_items - n)
        if sentinel_root is not None:
            vals[0] = sentinel_root
        return vals

    pd = max(len(path), 1)
    path_key_len = [0] * pd
    path_key = [[0] * max_path_key_len for _ in range(pd)]
    path_key_item = [0] * pd
    path_val_item = [0] * pd
    for h, (ki, vi) in enumerate(hops):
        kraw = raw(buf, items, ki)
        if len(kraw) > max_path_key_len:
            raise ValueError("path key longer than maxPathKeyLen")
        path_key_len[h] = len(kraw)
        path_key[h][:len(kraw)] = list(kraw)
        path_key_item[h] = ki
        path_val_item[h] = vi

    inputs = {
        "nItems": n,
        "itemOff": col("off"),
        "itemMajor": col("major"),
        "itemArg": [str(a) for a in col("arg")],  # up to 2^32-1
        "itemHdrLen": col("hdrLen"),
        "itemParent": col("parent", sentinel_root=max_items),
        "itemChildIdx": col("childIdx"),
        "itemEnd": col("end"),
        "pathKeyLen": path_key_len,
        "pathKey": path_key,
        "pathKeyItem": path_key_item,
        "pathValItem": path_val_item,
        "entryKey": [k for k, _ in entries],
        "entryVal": [v for _, v in entries],
    }
    return inputs, items, subj, entries


def item_preimage(digest_id, random, key_raw, value_raw,
                  max_key_len, max_value_len):
    """Fixed-width IssuerSignedItem-like preimage hashed by MdocDigest — must
    stay byte-per-byte in sync with the circuit. elementIdentifier and
    elementValue carry raw CBOR item bytes, zero-padded."""
    if len(key_raw) > max_key_len or len(value_raw) > max_value_len:
        raise ValueError("entry exceeds maxKeyLen/maxValueLen")
    return (bytes([digest_id]) + bytes(random)
            + bytes([len(key_raw)])
            + key_raw + b"\x00" * (max_key_len - len(key_raw))
            + bytes([len(value_raw)])
            + value_raw + b"\x00" * (max_value_len - len(value_raw)))


def mso_message(buf, items, entries, randoms, namespace,
                max_key_len, max_value_len):
    """Reference (off-circuit) computation of the MSO-style salted digest
    list produced by MdocDigest: nsLen || namespace || nFields ||
    (digestID || SHA256(preimage))*. Commits to ALL entries; disclosure is a
    separate off-circuit act (see present.py)."""
    import hashlib
    msg = bytes([len(namespace)]) + bytes(namespace) + bytes([len(entries)])
    for i, (ki, vi) in enumerate(entries):
        pre = item_preimage(i, randoms[i], raw(buf, items, ki),
                            raw(buf, items, vi), max_key_len, max_value_len)
        msg += bytes([i]) + hashlib.sha256(pre).digest()
    return msg
