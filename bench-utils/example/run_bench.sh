#!/bin/bash

# Array of different thread numbers
threads=(1 2 4 8)
# export TMPDIR=/home/ec2-user/external/tmp
# 

# Setup
# 
cargo run --release --example setup 

# Loop over the thread numbers
for num_threads in "${threads[@]}"
do
    # TODO: run scribe-prover-bench.rs (cargo run --release --example hp-prover)
    # TODO: if srs file doesn't exist, run our setup.rs (cargo run --release --example scribe-setup)
    #
    # Run the command with the current number of threads and log the output
    # TODO: change this to cargo run --release --example scribe-prover
    env RAYON_NUM_THREADS=$num_threads cargo run --release --example bench --features print-trace > "scribe-${num_threads}.txt"
done
