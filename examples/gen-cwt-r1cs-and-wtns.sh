# Mirrors gen-test-r1cs-and-wtns.sh for the CWT redaction experiment.
# examples/cwt_test.circom is rendered from cwt_test.template.circom by
# cwt_redact/prepare.py before this script runs.
circom --O2 --r1cs --c ./examples/cwt_test.circom -o ./examples 2> log_compiling_cwt.txt

cd examples/cwt_test_cpp
make
cd ../..
if [ -x examples/cwt_test_cpp/cwt_test ]; then
    examples/cwt_test_cpp/cwt_test examples/cwt_input.json examples/cwt_witness.wtns
else
    # fallback to the wasm witness generator if the C++ build is unavailable
    circom --O2 --r1cs --wasm ./examples/cwt_test.circom -o ./examples 2>> log_compiling_cwt.txt
    node examples/cwt_test_js/generate_witness.js examples/cwt_test_js/cwt_test.wasm examples/cwt_input.json examples/cwt_witness.wtns
fi
snarkjs wtns export json examples/cwt_witness.wtns examples/cwt_witness.json
