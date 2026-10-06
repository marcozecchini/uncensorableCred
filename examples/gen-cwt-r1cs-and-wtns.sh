# Mirrors gen-test-r1cs-and-wtns.sh for the CWT redaction experiment.
# examples/cwt_test.circom is rendered from cwt_test.template.circom by
# cwt_redact/prepare.py before this script runs.
# emit both backends in a single compile so the wasm fallback below never
# needs to recompile (the C++ generator cannot link on arm64 Macs: circom's
# fr.asm is x86-64 only)
circom --O2 --r1cs --c --wasm ./examples/cwt_test.circom -o ./examples 2> log_compiling_cwt.txt

cd examples/cwt_test_cpp
make
cd ../..
if [ -x examples/cwt_test_cpp/cwt_test ]; then
    examples/cwt_test_cpp/cwt_test examples/cwt_input.json examples/cwt_witness.wtns
else
    # fallback to the wasm witness generator if the C++ build is unavailable
    node examples/cwt_test_js/generate_witness.js examples/cwt_test_js/cwt_test.wasm examples/cwt_input.json examples/cwt_witness.wtns
fi
snarkjs wtns export json examples/cwt_witness.wtns examples/cwt_witness.json
