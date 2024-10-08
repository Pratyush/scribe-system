#!/bin/bash

# Usage: ./run_provers.sh [options]

# Default values
MIN_VARIABLES=5
MAX_VARIABLES=20
SETUP_FOLDER="./setup"
PROVERS=("scribe" "hp" "gemini" "plonky2" "halo2")
MEMORY_LIMITS=("500M" "1G" "2G" "4G")
THREADS=("1" "2" "4" "8")
OUTPUT_FILE="output.log"

# Function to display help
function show_help {
    echo "Usage: $0 [options]"
    echo
    echo "Options:"
    echo "  -h               Show this help message"
    echo "  -m MIN_VARIABLES Set minimum number of variables (default: $MIN_VARIABLES)"
    echo "  -M MAX_VARIABLES Set maximum number of variables (default: $MAX_VARIABLES)"
    echo "  -s SETUP_FOLDER  Set setup folder (default: $SETUP_FOLDER)"
    echo "  -p PROVERS       Set provers to run (comma-separated, default: ${PROVERS[*]})"
    echo "  -l MEMORY_LIMITS Set memory limits (comma-separated, default: ${MEMORY_LIMITS[*]})"
    echo "  -t THREADS       Set thread counts (comma-separated, default: ${THREADS[*]})"
    echo "  -o OUTPUT_FILE   Set output file (default: $OUTPUT_FILE)"
    echo
    echo "Example:"
    echo "  $0 -m 5 -M 20 -s ./setup -p \"scribe,hp,gemini,plonky2,halo2\" -l \"500M,1G,2G,4G\" -t \"1,2,4,8\" -o output.log"
}

# Parse options
while getopts "hm:M:s:p:l:t:o:" opt; do
    case ${opt} in
        h )
            show_help
            exit 0
            ;;
        m )
            MIN_VARIABLES=$OPTARG
            ;;
        M )
            MAX_VARIABLES=$OPTARG
            ;;
        s )
            SETUP_FOLDER=$OPTARG
            ;;
        p )
            IFS=',' read -r -a PROVERS <<< "$OPTARG"
            ;;
        l )
            IFS=',' read -r -a MEMORY_LIMITS <<< "$OPTARG"
            ;;
        t )
            IFS=',' read -r -a THREADS <<< "$OPTARG"
            ;;
        o )
            OUTPUT_FILE=$OPTARG
            ;;
        \? )
            show_help
            exit 1
            ;;
    esac
done

# Print the configuration
echo "Configuration:"
echo "MIN_VARIABLES: $MIN_VARIABLES"
echo "MAX_VARIABLES: $MAX_VARIABLES"
echo "SETUP_FOLDER: $SETUP_FOLDER"
echo "PROVERS: ${PROVERS[*]}"
echo "MEMORY_LIMITS: ${MEMORY_LIMITS[*]}"
echo "THREADS: ${THREADS[*]}"
echo "OUTPUT_FILE: $OUTPUT_FILE"

# Redirect all output to the output file
exec > >(tee -a "$OUTPUT_FILE") 2>&1

# Build the necessary binaries
echo "Compiling binaries..."

for PROVER in "${PROVERS[@]}"; do
    case $PROVER in
        scribe)
            echo "Compiling scribe-prover and scribe-setup..."
            cargo build --release --example scribe-prover
            cargo build --release --example scribe-setup
            ;;
        hp)
            echo "Compiling hp-prover and hp-setup..."
            cargo build --release --example hp-prover
            cargo build --release --example hp-setup
            ;;
        gemini)
            echo "Compiling gemini-prover..."
            cargo build --release --features gemini --example gemini-prover
            ;;
        plonky2)
            echo "Compiling plonky2-prover..."
            cargo build --release --features plonky2 --example plonky2-prover
            ;;
        halo2)
            echo "Compiling halo2-prover..."
            cargo build --release --features halo2 --example halo2-prover
            ;;
        *)
            echo "Unknown prover: $PROVER"
            ;;
    esac
done

# Step 2: Run setups if necessary
if [[ " ${PROVERS[@]} " =~ " scribe " ]]; then
    echo "Running setup for scribe..."
    ./run_with_cgroup.sh 2048G ../../target/release/examples/scribe-setup RAYON_NUM_THREADS=8 -- $MIN_VARIABLES $MAX_VARIABLES $SETUP_FOLDER
fi

if [[ " ${PROVERS[@]} " =~ " hp " ]]; then
    echo "Running setup for hp..."
    ./run_with_cgroup.sh 2048G ../../target/release/examples/hp-setup RAYON_NUM_THREADS=8 -- $MIN_VARIABLES $MAX_VARIABLES $SETUP_FOLDER
fi

# Step 3: Run the provers in nested loops
for MEMORY_LIMIT in "${MEMORY_LIMITS[@]}"; do
    for THREAD_COUNT in "${THREADS[@]}"; do
        for PROVER in "${PROVERS[@]}"; do
            echo "Running prover $PROVER with memory limit $MEMORY_LIMIT and $THREAD_COUNT threads..."

            # Construct the binary path and arguments
            case $PROVER in
                scribe)
                    BINARY_PATH="../../target/release/examples/scribe-prover"
                    ARGS="$MIN_VARIABLES $MAX_VARIABLES $SETUP_FOLDER"
                    ;;
                hp)
                    BINARY_PATH="../../target/release/examples/hp-prover"
                    ARGS="$MIN_VARIABLES $MAX_VARIABLES $SETUP_FOLDER"
                    ;;
                gemini)
                    BINARY_PATH="../../target/release/examples/gemini-prover"
                    ARGS="$MIN_VARIABLES $MAX_VARIABLES"
                    ;;
                plonky2)
                    BINARY_PATH="../../target/release/examples/plonky2-prover"
                    ARGS="$MIN_VARIABLES $MAX_VARIABLES"
                    ;;
                halo2)
                    BINARY_PATH="../../target/release/examples/halo2-prover"
                    ARGS="$MIN_VARIABLES $MAX_VARIABLES"
                    ;;
                *)
                    echo "Unknown prover: $PROVER"
                    continue
                    ;;
            esac

            # Print run information
            echo "----------------------------------------"
            echo "Starting run:"
            echo "Prover       : $PROVER"
            echo "Memory Limit : $MEMORY_LIMIT"
            echo "Threads      : $THREAD_COUNT"
            echo "----------------------------------------"

            # Run the prover
            ./run_with_cgroup.sh $MEMORY_LIMIT $BINARY_PATH RAYON_NUM_THREADS=$THREAD_COUNT -- $ARGS
        done
    done
done

