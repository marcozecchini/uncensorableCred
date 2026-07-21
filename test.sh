#!/bin/bash
set -e

RUSTFLAGS="-Awarnings" cargo build --release
python main.py --proof vole
