#bin/bash

python3 cose_real.py
circom cose_real.circom --O2 --r1cs --wasm
node cose_real_js/generate_witness.js cose_real_js/cose_real.wasm input.json witness.wtns
snarkjs wtns export json witness.wtns witness.json
python3 cose_real.py check
