#bin/bash

python3 emsa.py
circom emsa.circom --r1cs --wasm
node emsa_js/generate_witness.js emsa_js/emsa.wasm input.json witness.wtns
snarkjs wtns export json witness.wtns witness.json