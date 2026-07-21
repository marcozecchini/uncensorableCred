#bin/bash

python3 mgf.py
circom mgf1.circom --r1cs --wasm 
node mgf1_js/generate_witness.js mgf1_js/mgf1.wasm input.json witness.wtns
snarkjs wtns export json witness.wtns witness.json