//! Notary-side blind RSA-PSS operations, built on the ACTS fork of
//! jedisct1/rust-blind-rsa-signatures (vendored in rust-blind-rsa-signatures/).
//! The fork's BlindingResult exposes the PSS salt generated inside blind(),
//! which the circuit needs as an explicit witness.
//!
//! Subcommands:
//!   cwt_notary blind    <notary_key.pem> <message_file> <ctx_out.json>
//!     [HOLDER] blinds the mdoc-style message with the crate; writes the
//!     blinding context (salt, r = secret^-1 limbs, blind_msg, secret).
//!     The circuit must reproduce blind_msg byte-per-byte.
//!   cwt_notary finalize <notary_key.pem> <message_file> <ctx.json> <blinded_file> <sig_out>
//!     [NOTARY] blind-signs the circuit's blinded output (checked against the
//!     crate's blind_msg); [HOLDER] unblinds with the secret and verifies the
//!     final RSA-PSS signature over the message.
use std::fs;

use blind_rsa_signatures::{
    reexports::rsa::PublicKeyParts, BlindSignature, Hash, Options, Secret, SecretKey,
};
use num_bigint_dig::{BigInt, BigUint, ModInverse};
use rand::thread_rng;
use serde_json::{json, Value};

/// Splits a BigUint into `k` limbs of `w` bits each, returning decimal strings
/// (same convention as the circuits and cwt_redact/prepare.py).
fn decompose_biguint(n: &BigUint, k: usize, w: usize) -> Vec<String> {
    let mask = (BigUint::from(1u64) << w) - 1u32;
    let mut limbs = Vec::with_capacity(k);
    let mut value = n.clone();
    for _ in 0..k {
        limbs.push((&value & &mask).to_str_radix(10));
        value >>= w;
    }
    limbs
}

fn bytes_of(v: &Value) -> Vec<u8> {
    v.as_array()
        .expect("expected a byte array")
        .iter()
        .map(|x| x.as_u64().unwrap() as u8)
        .collect()
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let usage = format!(
        "Usage: {} blind <key.pem> <message> <ctx_out.json>\n       {} finalize <key.pem> <message> <ctx.json> <blinded> <sig_out>",
        args[0], args[0]
    );
    if args.len() < 2 {
        eprintln!("{}", usage);
        std::process::exit(1);
    }

    let options = Options::new(Hash::Sha256, false, 32);
    let rng = &mut thread_rng();

    match args[1].as_str() {
        "blind" if args.len() == 5 => {
            let sk = SecretKey::from_pem(&fs::read_to_string(&args[2]).unwrap()).unwrap();
            let pk = sk.public_key().unwrap();
            let msg = fs::read(&args[3]).unwrap();

            let blinding = pk.blind(rng, &msg, false, &options).unwrap();

            // the circuit's `r` input is the inverse of the unblinding secret
            let r = BigInt::from_bytes_be(num_bigint_dig::Sign::Plus, &blinding.secret)
                .mod_inverse(pk.n())
                .expect("no modular inverse")
                .to_biguint()
                .expect("modular inverse was negative?");

            let ctx = json!({
                "salt": blinding.salt.0,
                "r": decompose_biguint(&r, 32, 64),
                "blind_msg": blinding.blind_msg.0,
                "secret": blinding.secret.0,
            });
            fs::write(&args[4], serde_json::to_string_pretty(&ctx).unwrap()).unwrap();
            println!("Message blinded with rust-blind-rsa-signatures (salt and r exported)");
        }
        "finalize" if args.len() == 7 => {
            let sk = SecretKey::from_pem(&fs::read_to_string(&args[2]).unwrap()).unwrap();
            let pk = sk.public_key().unwrap();
            let msg = fs::read(&args[3]).unwrap();
            let ctx: Value = serde_json::from_str(&fs::read_to_string(&args[4]).unwrap()).unwrap();
            let blinded = fs::read(&args[5]).unwrap();

            // the circuit's blinded output must equal the crate's blind_msg
            assert_eq!(
                blinded,
                bytes_of(&ctx["blind_msg"]),
                "circuit blinded output does not match the crate's blind_msg"
            );

            // [NOTARY] signs the blinded message without learning its content
            let blind_sig: BlindSignature = sk.blind_sign(rng, &blinded, &options).unwrap();

            // [HOLDER] unblinds; finalize() also verifies the resulting signature
            let secret = Secret(bytes_of(&ctx["secret"]));
            let sig = pk.finalize(&blind_sig, &secret, None, &msg, &options).unwrap();
            sig.verify(&pk, None, &msg, &options).unwrap();

            fs::write(&args[6], &sig.0).unwrap();
            println!("Notary blind signature finalized and verified (rust-blind-rsa-signatures)");
        }
        _ => {
            eprintln!("{}", usage);
            std::process::exit(1);
        }
    }
}
