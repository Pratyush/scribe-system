#!/bin/bash

# Array of different thread numbers
threads=(1 2 4 8)

# Loop over the thread numbers
for num_threads in "${threads[@]}"
do
    # Run the command with the current number of threads and log the output
    env RAYON_NUM_THREADS=$num_threads cargo bench --bench hyperplonk-benches --features print-trace > "scribe-${num_threads}.txt"
done
