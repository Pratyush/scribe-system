#!/bin/bash

# Usage: ./run_bench.sh <min_num_vars> <max_num_vars>

# Array of different thread numbers
# threads=(1 2 4 8)
threads=(1)
# export TMPDIR=/home/ec2-user/external/tmp
# 

# Setup
# 
cargo run --release --example scribe-setup $1 $2 .
cargo run --release --example hp-setup $1 $2 .

# Loop over the thread numbers
for num_threads in "${threads[@]}"
do
    echo "Running with $num_threads threads"
    env RAYON_NUM_THREADS=$num_threads cargo run --release --example scribe-prover $1 $2 . > "scribe-${num_threads}.txt"
    env RAYON_NUM_THREADS=$num_threads cargo run --release --example hp-prover $1 $2 . > "hp-${num_threads}.txt"
done
