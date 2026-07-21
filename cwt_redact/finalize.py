"""Notary side of the experiment: blind-sign the blinded PSS message with the
notary secret key, unblind the result with r^{-1} mod n, and verify that the
final RSA-PSS signature validates over the mdoc-style message.
"""
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

EM_LEN = 256
SALT_LEN = 32


def finalize(ctx, message, blinded,
             notary_key_path="notary_key.pem",
             sig_out="signature_cwt.bin",
             message_out="mdoc_message.bin"):
    """`ctx` from prepare.prepare(); `message`/`blinded` from validate.validate().

    Returns the unblinded RSA-PSS signature over the mdoc-style message.
    """
    with open(notary_key_path, "rb") as f:
        sk = serialization.load_pem_private_key(f.read(), password=None)
    priv = sk.private_numbers()
    n = priv.public_numbers.n

    # [NOTARY] signs the blinded message without learning its content
    blind_sig = pow(int.from_bytes(blinded, "big"), priv.d, n)

    # [HOLDER] unblinds: (EM * r^e)^d * r^{-1} = EM^d mod n
    sig = (blind_sig * pow(ctx["r"], -1, n)) % n
    sig_bytes = sig.to_bytes(EM_LEN, "big")

    # the unblinded signature must be a valid RSA-PSS signature on the message
    sk.public_key().verify(
        sig_bytes,
        message,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=SALT_LEN),
        hashes.SHA256(),
    )

    with open(sig_out, "wb") as f:
        f.write(sig_bytes)
    with open(message_out, "wb") as f:
        f.write(message)

    print("The unblinded notary signature verifies over the mdoc-style message")
    return sig_bytes
