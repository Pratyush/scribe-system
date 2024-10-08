#!/bin/bash

# Usage: ./run_benchmarks.sh [options]

# Default values
MIN_VARIABLES=5
MAX_VARIABLES=20
SETUP_FOLDER="./setup"
PROVERS=("scribe" "hp" "gemini" "plonky2" "halo2")
MEMORY_LIMITS=("500M" "1G" "2G" "4G")
BANDWIDTH_LIMITS=("200M" "500M" "1G" "2G")
THREADS=("1" "2" "4" "8")
OUTPUT_FILE="output.log"
SKIP_SETUP=false
EXPERIMENT_TYPE="both"  # 'm' for memory, 'b' for bandwidth, 'both' for both

# Function to display help
function show_help {
    echo "Usage: $0 [options]"
    echo
    echo "Options:"
    echo "  -h, --help          Show this help message"
    echo "  -m MIN_VARIABLES    Set minimum number of variables (default: $MIN_VARIABLES)"
    echo "  -M MAX_VARIABLES    Set maximum number of variables (default: $MAX_VARIABLES)"
    echo "  -s SETUP_FOLDER     Set setup folder (default: $SETUP_FOLDER)"
    echo "  -p PROVERS          Set provers to run (comma-separated, default: ${PROVERS[*]})"
    echo "  -l MEMORY_LIMITS    Set memory limits (comma-separated, default: ${MEMORY_LIMITS[*]})"
    echo "  -b BANDWIDTH_LIMITS Set bandwidth limits (comma-separated, default: ${BANDWIDTH_LIMITS[*]})"
    echo "  -t THREADS          Set thread counts (comma-separated, default: ${THREADS[*]})"
    echo "  -o OUTPUT_FILE      Set output file (default: $OUTPUT_FILE)"
    echo "  --skip-setup        Skip the setup section"
    echo "  -e EXPERIMENT       Set experiment type: 'm' for memory, 'b' for bandwidth (default: both)"
    echo
    echo "Example:"
    echo "  $0 -m 5 -M 20 -s ./setup -p \"scribe,hp,gemini,plonky2,halo2\" \\"
    echo "     -l \"500M,1G,2G,4G\" -b \"200M,500M,1G,2G\" -t \"1,2,4,8\" -o output.log -e m"
}

# Parse options
POSITIONAL_ARGS=()
while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            show_help
            exit 0
            ;;
        -m)
            MIN_VARIABLES=$2
            shift 2
            ;;
        -M)
            MAX_VARIABLES=$2
            shift 2
            ;;
        -s)
            SETUP_FOLDER=$2
            shift 2
            ;;
        -p)
            IFS=',' read -r -a PROVERS <<< "$2"
            shift 2
            ;;
        -l)
            IFS=',' read -r -a MEMORY_LIMITS <<< "$2"
            shift 2
            ;;
        -b)
            IFS=',' read -r -a BANDWIDTH_LIMITS <<< "$2"
            shift 2
            ;;
        -t)
            IFS=',' read -r -a THREADS <<< "$2"
            shift 2
            ;;
        -o)
            OUTPUT_FILE=$2
            shift 2
            ;;
        --skip-setup)
            SKIP_SETUP=true
            shift
            ;;
        -e)
            EXPERIMENT_TYPE=$2
            shift 2
            ;;
        *)
            POSITIONAL_ARGS+=("$1")
            shift
            ;;
    esac
done

# Set positional arguments back
set -- "${POSITIONAL_ARGS[@]}"

# Print the configuration
echo "Configuration:"
echo "MIN_VARIABLES     : $MIN_VARIABLES"
echo "MAX_VARIABLES     : $MAX_VARIABLES"
echo "SETUP_FOLDER      : $SETUP_FOLDER"
echo "PROVERS           : ${PROVERS[*]}"
echo "MEMORY_LIMITS     : ${MEMORY_LIMITS[*]}"
echo "BANDWIDTH_LIMITS  : ${BANDWIDTH_LIMITS[*]}"
echo "THREADS           : ${THREADS[*]}"
echo "OUTPUT_FILE       : $OUTPUT_FILE"
echo "SKIP_SETUP        : $SKIP_SETUP"
echo "EXPERIMENT_TYPE   : $EXPERIMENT_TYPE"

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
if [ "$SKIP_SETUP" = false ]; then
    if [[ " ${PROVERS[@]} " =~ " scribe " ]]; then
        echo "Running setup for scribe..."
        env RAYON_NUM_THREADS=8 ../../target/release/examples/scribe-setup \
            $MIN_VARIABLES $MAX_VARIABLES $SETUP_FOLDER
    fi

    if [[ " ${PROVERS[@]} " =~ " hp " ]]; then
        echo "Running setup for hp..."
        env RAYON_NUM_THREADS=8 ../../target/release/examples/hp-setup \
            $MIN_VARIABLES $MAX_VARIABLES $SETUP_FOLDER
    fi
else
    echo "Skipping setup section as per user request."
fi

# Function to run a command with memory limits using systemd-run
run_with_memory_limits() {
    local MEMORY_LIMIT=$1
    local THREAD_COUNT=$2
    local PROVER=$3
    local BINARY_PATH=$4
    local ARGS=$5

    # Convert memory limit to bytes
    MEMORY_LIMIT_BYTES=$(numfmt --from=iec "$MEMORY_LIMIT")

    # Build systemd-run command
    if [[ "$PROVER" == "gemini" ]] || [[ "$PROVER" == "scribe" ]]; then
        # Use hard memory limit (MemoryMax)
        SYSTEMD_CMD=(
            sudo systemd-run --scope
            --unit="${PROVER}_mem_$(date +%s%N)"
            -p MemoryMax=$MEMORY_LIMIT_BYTES
            env RAYON_NUM_THREADS=$THREAD_COUNT $BINARY_PATH $ARGS
        )
    else
        # Use soft memory limit (MemoryHigh)
        SYSTEMD_CMD=(
            sudo systemd-run --scope
            --unit="${PROVER}_mem_$(date +%s%N)"
            -p MemoryHigh=$MEMORY_LIMIT_BYTES
            env RAYON_NUM_THREADS=$THREAD_COUNT $BINARY_PATH $ARGS
        )
    fi

    # Run the command and capture errors
    echo "Executing command: ${SYSTEMD_CMD[*]}"
    "${SYSTEMD_CMD[@]}" || {
        echo "ERROR: Command failed for prover $PROVER with memory limit $MEMORY_LIMIT and threads $THREAD_COUNT"
    }
}

# Function to run a command with bandwidth limits using systemd-run
run_with_bandwidth_limits() {
    local BANDWIDTH_LIMIT=$1
    local THREAD_COUNT=$2
    local PROVER=$3
    local BINARY_PATH=$4
    local ARGS=$5

    # Convert bandwidth limit to bytes
    BANDWIDTH_LIMIT_BYTES=$(numfmt --from=iec "$BANDWIDTH_LIMIT")

    # Get the device for I/O limitations (adjust as necessary)
    DEVICE="/dev/nvme0n1"

    # Build systemd-run command
    SYSTEMD_CMD=(
        sudo systemd-run --scope
        --unit="${PROVER}_bw_$(date +%s%N)"
        -p IOReadBandwidthMax="$DEVICE $BANDWIDTH_LIMIT_BYTES"
        -p IOWriteBandwidthMax="$DEVICE $BANDWIDTH_LIMIT_BYTES"
        env RAYON_NUM_THREADS=$THREAD_COUNT $BINARY_PATH $ARGS
    )

    # Run the command and capture errors
    echo "Executing command: ${SYSTEMD_CMD[*]}"
    "${SYSTEMD_CMD[@]}" || {
        echo "ERROR: Command failed for prover $PROVER with bandwidth limit $BANDWIDTH_LIMIT and threads $THREAD_COUNT"
    }
}

# Step 3: Run memory-thread-prover loop
if [[ "$EXPERIMENT_TYPE" == "m" || "$EXPERIMENT_TYPE" == "both" ]]; then
    echo "Running memory benchmarks..."
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
                echo "Starting memory benchmark run:"
                echo "Prover       : $PROVER"
                echo "Memory Limit : $MEMORY_LIMIT"
                echo "Threads      : $THREAD_COUNT"
                echo "----------------------------------------"

                # Run the prover with memory limits
                run_with_memory_limits "$MEMORY_LIMIT" "$THREAD_COUNT" "$PROVER" "$BINARY_PATH" "$ARGS"
            done
        done
    done
fi

# Step 4: Run bandwidth-thread-prover loop
if [[ "$EXPERIMENT_TYPE" == "b" || "$EXPERIMENT_TYPE" == "both" ]]; then
    echo "Running bandwidth benchmarks..."
    for BANDWIDTH_LIMIT in "${BANDWIDTH_LIMITS[@]}"; do
        for THREAD_COUNT in "${THREADS[@]}"; do
            for PROVER in "${PROVERS[@]}"; do
                echo "Running prover $PROVER with bandwidth limit $BANDWIDTH_LIMIT and $THREAD_COUNT threads..."

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
                echo "Starting bandwidth benchmark run:"
                echo "Prover            : $PROVER"
                echo "Bandwidth Limit   : $BANDWIDTH_LIMIT"
                echo "Threads           : $THREAD_COUNT"
                echo "----------------------------------------"

                # Run the prover with bandwidth limits
                run_with_bandwidth_limits "$BANDWIDTH_LIMIT" "$THREAD_COUNT" "$PROVER" "$BINARY_PATH" "$ARGS"
            done
        done
    done
fi

