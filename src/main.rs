//! Prover entry point for the CWT redaction experiment.
//!
//! Runs a VOLE-in-the-head or Groth16 proof over the circuit generated from
//! examples/cwt_test.template.circom (examples/cwt_test.r1cs +
//! examples/cwt_witness.wtns, produced by main.py via
//! examples/gen-cwt-r1cs-and-wtns.sh).
use std::fs;
use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Instant;

use memory_stats::memory_stats;
use vole_zk::{
    actors::actors::{CommitAndProof, Prover, Verifier},
    circom::{r1cs::R1CSFile, witness::wtns_from_reader},
};

const R1CS_PATH: &str = "examples/cwt_test.r1cs";
const WITNESS_PATH: &str = "examples/cwt_witness.wtns";

/// Prints the size of a R1CS file in megabytes
fn r1cs_len(path: &str) {
    if let Ok(metadata) = fs::metadata(Path::new(path)) {
        let size_mb = metadata.len() as f64 / 1024.0 / 1024.0;
        println!("R1CS circuit size: {:.2} MB", size_mb);
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} [vole|snark]", args[0]);
        std::process::exit(1);
    }

    r1cs_len(R1CS_PATH);

    match args[1].as_str() {
        "vole" => {
            let witness = {
                let file = File::open(WITNESS_PATH).unwrap();
                wtns_from_reader(BufReader::new(file)).unwrap()
            };
            let circuit = {
                let file = File::open(R1CS_PATH).unwrap();
                R1CSFile::from_reader(BufReader::new(file)).unwrap().to_crate_format()
            };

            let before_mem = memory_stats().unwrap().physical_mem;
            let start_time = Instant::now();
            let mut prover = Prover::from_witness_and_circuit_unpadded(witness, circuit.clone());
            let commitment = prover.mkvole().unwrap();
            let proof = prover.prove().unwrap();
            println!("VOLE proving time: {:.3?}", start_time.elapsed());
            let proof_bytes = bincode::serialize(&proof).unwrap().len();
            println!("VOLE proof size: {:.2} MB", proof_bytes as f64 / 1024.0 / 1024.0);
            let after_mem = memory_stats().unwrap().physical_mem;
            println!("Memory used for VOLE: {:.2} MB", (after_mem - before_mem) as f64 / 1024.0 / 1024.0);

            let start_verify = Instant::now();
            let verifier = Verifier::from_circuit(circuit);
            verifier.verify(&CommitAndProof { commitment, proof }).unwrap();
            println!("VOLE verification time: {:.3?}", start_verify.elapsed());
            println!("Proof Done!");
        }
        "snark" => {
            println!("SNARK mode selected. Generating the zkey file...");
            let start_setup = Instant::now();
            Command::new("bash").arg("./examples/setup_groth_cwt.sh")
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit())
                .status()
                .unwrap();
            println!("SNARK setup time: {:.3?}", start_setup.elapsed());
            let start_prove = Instant::now();
            Command::new("bash").arg("./examples/prove_groth_cwt.sh")
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit())
                .status()
                .unwrap();
            println!("SNARK proving time: {:.3?}", start_prove.elapsed());
        }
        _ => {
            eprintln!("Mode must be \"vole\" or \"snark\"");
            std::process::exit(1);
        }
    }
}
