"""Final cross-check of the notary round.

The notary round itself (blind_sign on the circuit's blinded output, unblind
with the blinding secret, RSA-PSS verification) is performed in Rust by
./target/release/cwt_notary using the ACTS fork of
jedisct1/rust-blind-rsa-signatures (see src/bin/cwt_notary.rs). Here the
resulting signature is re-verified independently with the `cryptography`
library.
"""
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

SALT_LEN = 32


def verify_final_signature(message, sig_path,
                           notary_key_path="notary_key.pem"):
    """Verify the unblinded notary signature over the mdoc-style message."""
    with open(notary_key_path, "rb") as f:
        sk = serialization.load_pem_private_key(f.read(), password=None)
    with open(sig_path, "rb") as f:
        sig = f.read()

    sk.public_key().verify(
        sig,
        message,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=SALT_LEN),
        hashes.SHA256(),
    )
    print("Unblinded notary signature independently re-verified with `cryptography`")
    return sig
