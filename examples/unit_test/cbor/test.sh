#bin/bash

python3 cbor.py
circom cbor_redact.circom --r1cs --wasm
node cbor_redact_js/generate_witness.js cbor_redact_js/cbor_redact.wasm input.json witness.wtns
snarkjs wtns export json witness.wtns witness.json
python3 cbor.py check
