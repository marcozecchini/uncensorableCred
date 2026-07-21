"""Minimal CBOR encoder (RFC 8949 subset).

Covers exactly the grammar supported by CborMapVerify in
examples/cbor_redact_verify.circom (see examples/cbor_redact_verify.DESIGN.md):
definite-length maps with text-string keys (1..255 bytes) and text/byte-string
values (0..255 bytes). Deliberately NOT a general CBOR library.
"""


def enc_head(major: int, n: int) -> bytes:
    """CBOR head for major type `major` and length/value `n`."""
    if n < 24:
        return bytes([(major << 5) | n])
    if n < 256:
        return bytes([(major << 5) | 24, n])
    if n < 65536:
        return bytes([(major << 5) | 25, n >> 8, n & 0xFF])
    raise ValueError("length too large for the minimal CBOR subset")


def enc_tstr(s: str) -> bytes:
    b = s.encode("utf-8")
    return enc_head(3, len(b)) + b


def enc_bstr(b: bytes) -> bytes:
    return enc_head(2, len(b)) + bytes(b)


def encode_claims(claims):
    """Encode an ordered mapping {str: str | bytes} as the CWT claims payload.

    Returns (payload, fields) where fields is a list of dicts with the parse
    witnesses the circuit expects: keyLen, valLen, valMajor, key, value.
    """
    if not 0 < len(claims) < 256:
        raise ValueError("nFields must be in 1..255")
    payload = enc_head(5, len(claims))
    fields = []
    for key, value in claims.items():
        kb = key.encode("utf-8")
        if isinstance(value, str):
            vb, major = value.encode("utf-8"), 3
        elif isinstance(value, (bytes, bytearray)):
            vb, major = bytes(value), 2
        else:
            raise TypeError("claim values must be str (tstr) or bytes (bstr)")
        if not 1 <= len(kb) <= 255:
            raise ValueError("claim keys must be 1..255 bytes")
        if len(vb) > 255:
            raise ValueError("claim values must be at most 255 bytes")
        payload += enc_head(3, len(kb)) + kb + enc_head(major, len(vb)) + vb
        fields.append({
            "keyLen": len(kb),
            "valLen": len(vb),
            "valMajor": major,
            "key": kb,
            "value": vb,
        })
    return payload, fields
