# Groth16 setup for the CWT redaction circuit (mirrors setup_groth.sh).
# Set PTAU to your powers-of-tau file if it is not ~/28.ptau.
snarkjs groth16 setup examples/cwt_test.r1cs "${PTAU:-$HOME/28.ptau}" examples/cwt_test.zkey
