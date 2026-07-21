# Groth16 proving for the CWT redaction circuit (mirrors prove_groth.sh).
# Set RAPIDSNARK to your rapidsnark prover binary to use it; falls back to snarkjs.
if [ -n "$RAPIDSNARK" ] && [ -x "$RAPIDSNARK" ]; then
    "$RAPIDSNARK" examples/cwt_test.zkey examples/cwt_witness.wtns examples/cwt_proof.json examples/cwt_public.json
else
    snarkjs groth16 prove examples/cwt_test.zkey examples/cwt_witness.wtns examples/cwt_proof.json examples/cwt_public.json
fi
