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
SKIP_SETUP=false
EXPERIMENT_TYPE="both"  # 'm' for memory, 'b' for bandwidth, 'both' for both
OUTPUT_FILE=""
DATA_FILE_BASE=""
VISUALIZE_CACHE=false  # New variable for cache visualization

# Function to display help
function show_help {
    echo "Usage: $0 [options]"
    echo
    echo "Options:"
    echo "  -h, --help             Show this help message"
    echo "  -m MIN_VARIABLES       Set minimum number of variables (default: $MIN_VARIABLES)"
    echo "  -M MAX_VARIABLES       Set maximum number of variables (default: $MAX_VARIABLES)"
    echo "  -s SETUP_FOLDER        Set setup folder (default: $SETUP_FOLDER)"
    echo "  -p PROVERS             Set provers to run (comma-separated, default: ${PROVERS[*]})"
    echo "  -l MEMORY_LIMITS       Set memory limits (comma-separated, default: ${MEMORY_LIMITS[*]})"
    echo "  -b BANDWIDTH_LIMITS    Set bandwidth limits (comma-separated, default: ${BANDWIDTH_LIMITS[*]})"
    echo "  -t THREADS             Set thread counts (comma-separated, default: ${THREADS[*]})"
    echo "  -o OUTPUT_FILE         Set output file (default: [mmddhhmmss].log)"
    echo "  --data-file NAME       Set base name for data file output (default: [mmddhhmmss].data)"
    echo "  --visualize-cache      Enable visualization of filesystem cache for 'scribe' prover"
    echo "  --skip-setup           Skip the setup section"
    echo "  -e EXPERIMENT          Set experiment type: 'm' for memory, 'b' for bandwidth (default: both)"
    echo
    echo "Example:"
    echo "  $0 -m 5 -M 20 -s ./setup -p \"scribe,hp,gemini,plonky2,halo2\" \\"
    echo "     -l \"500M,1G,2G,4G\" -b \"200M,500M,1G,2G\" -t \"1,2,4,8\" -o mylog \\"
    echo "     --data-file mydata --visualize-cache"
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
            OUTPUT_FILE_BASE=$2
            shift 2
            ;;
        --data-file)
            DATA_FILE_BASE=$2
            shift 2
            ;;
        --visualize-cache)
            VISUALIZE_CACHE=true
            shift
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

# Generate timestamp
START_TIME=$(date +"%m%d%H%M%S")

# Prepare output file
if [ -n "$OUTPUT_FILE_BASE" ]; then
    OUTPUT_FILE="${OUTPUT_FILE_BASE}.log"
else
    OUTPUT_FILE="${START_TIME}.log"
fi

# Prepare data file
if [ -n "$DATA_FILE_BASE" ]; then
    DATA_FILE="${DATA_FILE_BASE}.data"
else
    DATA_FILE="${START_TIME}.data"
fi

# Write header to data file
echo "starting_timestamp,prover,threads,memory_limit,bandwidth_limit,num_variables,run_time" > "$DATA_FILE"

# Initialize cache data file variable
CACHE_DATA_FILE=""

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
echo "DATA_FILE         : $DATA_FILE"
echo "SKIP_SETUP        : $SKIP_SETUP"
echo "EXPERIMENT_TYPE   : $EXPERIMENT_TYPE"
echo "VISUALIZE_CACHE   : $VISUALIZE_CACHE"

# Redirect all output to the output file
exec > >(tee -a "$OUTPUT_FILE") 2>&1

# Load cargo environment
source "$HOME/.cargo/env"

# Build the necessary binaries
echo "Compiling binaries..."

for PROVER in "${PROVERS[@]}"; do
    case $PROVER in
        scribe)
            echo "Compiling scribe-prover and scribe-setup..."
            cargo build --release --example scribe-prover
            cargo build --release --example scribe-setup --features print-trace
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
        env RAYON_NUM_THREADS=16 ../../target/release/examples/scribe-setup \
            $MIN_VARIABLES $MAX_VARIABLES $SETUP_FOLDER
    fi

    if [[ " ${PROVERS[@]} " =~ " hp " ]]; then
        echo "Running setup for hp..."
        env RAYON_NUM_THREADS=16 ../../target/release/examples/hp-setup \
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

    # Use hard memory limit (MemoryMax)
    MEMORY_PROPERTY="MemoryMax=${MEMORY_LIMIT_BYTES}"

    # Generate unique unit name
    UNIT_NAME="${PROVER}_mem_$(date +%s%N)"

    # Build systemd-run command
    SYSTEMD_CMD=(
        sudo systemd-run --scope
        --unit="${UNIT_NAME}"
        -p "$MEMORY_PROPERTY"
        -p "MemorySwapMax=0"
        env RAYON_NUM_THREADS=$THREAD_COUNT $BINARY_PATH $ARGS
    )

    # Start the command
    echo "Executing command: ${SYSTEMD_CMD[*]}"
    START_TIMESTAMP=$(date +"%Y-%m-%d %H:%M:%S")

    # If visualization is enabled and prover is scribe, set up cache monitoring
    if [ "$VISUALIZE_CACHE" = true ] && [ "$PROVER" == "scribe" ]; then
        # Define a single cache data file
        CACHE_DATA_FILE="${START_TIME}.cachedata"

        # Write header to cache data file only if it doesn't exist
        if [ ! -f "$CACHE_DATA_FILE" ]; then
            echo "prover,threads,memory_limit,num_variables,timestamp,memory.stat.anon,memory.stat.file" > "$CACHE_DATA_FILE"
        fi

        # Determine cgroup path
        CGROUP_PATH="/sys/fs/cgroup/system.slice/${UNIT_NAME}.scope/memory.stat"

        # Function to monitor memory.stat
        monitor_cache() {
            local PROVER_MON=$1
            local THREAD_MON=$2
            local MEMORY_LIMIT_MON=$3
            local CGROUP_PATH_MON=$4
            local CACHE_FILE_MON=$5
            local RUNNING_PID=$6

            while kill -0 "$RUNNING_PID" 2>/dev/null; do
                if [ -f "$CGROUP_PATH_MON" ]; then
                    ANON=$(grep "^anon " "$CGROUP_PATH_MON" | awk '{print $2}')
                    FILE=$(grep "^file " "$CGROUP_PATH_MON" | awk '{print $2}')
                    TIMESTAMP=$(date +"%Y-%m-%d %H:%M:%S")
                    # Initially, num_variables is unknown. We'll update it later.
                    echo "${PROVER_MON},${THREAD_MON},${MEMORY_LIMIT_MON},,${TIMESTAMP},${ANON},${FILE}" >> "$CACHE_FILE_MON"
                else
                    echo "Error: Cgroup path $CGROUP_PATH_MON does not exist."
                fi
                sleep 1
            done
        }

        # Start monitoring in the background, passing the systemd-run PID
        monitor_cache "$PROVER" "$THREAD_COUNT" "$MEMORY_LIMIT" "$CGROUP_PATH" "$CACHE_DATA_FILE" $$ &
        MONITOR_PID=$!
    fi

    # Run the command and capture output
    OUTPUT=$("${SYSTEMD_CMD[@]}" 2>&1)
    EXIT_STATUS=$?

    echo "$OUTPUT"

    if [ $EXIT_STATUS -ne 0 ]; then
        echo "ERROR: Command failed for prover $PROVER with memory limit $MEMORY_LIMIT and threads $THREAD_COUNT"
    fi

    # Process output to extract data
    process_output "$OUTPUT" "$START_TIMESTAMP" "$PROVER" "$THREAD_COUNT" "$MEMORY_LIMIT" "" "$EXIT_STATUS"

    # If monitoring was started, stop it and update the cache data file with num_variables
    if [ "$VISUALIZE_CACHE" = true ] && [ "$PROVER" == "scribe" ]; then
        if [ -n "$MONITOR_PID" ]; then
            # Stop the monitoring
            sudo kill "$MONITOR_PID" 2>/dev/null
            wait "$MONITOR_PID" 2>/dev/null

            # Extract num_variables from the output
            NUM_VARIABLES=$(echo "$OUTPUT" | grep -oP '(?<=Proving for )\d+(?= took:)')

            if [ -z "$NUM_VARIABLES" ]; then
                NUM_VARIABLES=""
            fi

            # Update the cache data file with num_variables
            # Using awk to insert num_variables into the 4th column
            awk -v num_vars="$NUM_VARIABLES" 'BEGIN{FS=OFS=","} NR==1 {print $0} NR>1 {$4=num_vars; print $0}' "$CACHE_DATA_FILE" > "${CACHE_DATA_FILE}.tmp" && mv "${CACHE_DATA_FILE}.tmp" "$CACHE_DATA_FILE"

            echo "Cache data saved to $CACHE_DATA_FILE"
        fi
    fi
}

# Function to run a command with bandwidth and memory limits using systemd-run
run_with_bandwidth_limits() {
    local BANDWIDTH_LIMIT=$1
    local MEMORY_LIMIT=$2
    local THREAD_COUNT=$3
    local PROVER=$4
    local BINARY_PATH=$5
    local ARGS=$6

    # Only allow 'scribe' as the prover for bandwidth tests
    if [[ "$PROVER" != "scribe" ]]; then
        echo "Skipping bandwidth test for prover $PROVER as only 'scribe' is allowed."
        return
    fi

    # Convert bandwidth limit to bytes
    BANDWIDTH_LIMIT_BYTES=$(numfmt --from=iec "$BANDWIDTH_LIMIT")

    # Convert memory limit to bytes
    MEMORY_LIMIT_BYTES=$(numfmt --from=iec "$MEMORY_LIMIT")

    # Use hard memory limit (MemoryMax)
    MEMORY_PROPERTY="MemoryMax=${MEMORY_LIMIT_BYTES}"

    # Get the device for I/O limitations (adjust as necessary)
    DEVICE="/dev/nvme2n1"

    # Generate unique unit name
    UNIT_NAME="${PROVER}_bw_$(date +%s%N)"

    # Build systemd-run command with bandwidth and memory limits
    SYSTEMD_CMD=(
        sudo systemd-run --scope
        --unit="${UNIT_NAME}"
        -p "IOReadBandwidthMax=${DEVICE} ${BANDWIDTH_LIMIT_BYTES}"
        -p "IOWriteBandwidthMax=${DEVICE} ${BANDWIDTH_LIMIT_BYTES}"
        -p "$MEMORY_PROPERTY"
        env RAYON_NUM_THREADS=$THREAD_COUNT $BINARY_PATH $ARGS
    )

    # Start the command
    echo "Executing command: ${SYSTEMD_CMD[*]}"
    START_TIMESTAMP=$(date +"%Y-%m-%d %H:%M:%S")

    # Run the command and capture output
    OUTPUT=$("${SYSTEMD_CMD[@]}" 2>&1)
    EXIT_STATUS=$?

    echo "$OUTPUT"

    if [ $EXIT_STATUS -ne 0 ]; then
        echo "ERROR: Command failed for prover $PROVER with bandwidth limit $BANDWIDTH_LIMIT, memory limit $MEMORY_LIMIT and threads $THREAD_COUNT"
    fi

    # Process output to extract data
    process_output "$OUTPUT" "$START_TIMESTAMP" "$PROVER" "$THREAD_COUNT" "$MEMORY_LIMIT" "$BANDWIDTH_LIMIT" "$EXIT_STATUS"
}

# Function to process command output and extract data
process_output() {
    local OUTPUT="$1"
    local START_TIMESTAMP="$2"
    local PROVER="$3"
    local THREAD_COUNT="$4"
    local MEMORY_LIMIT="$5"
    local BANDWIDTH_LIMIT="$6"
    local EXIT_STATUS="$7"

    # Parse the output line by line
    while IFS= read -r line; do
        # Look for lines matching "Proving for {num_variables} took: {run_time} us"
        if [[ "$line" =~ Proving\ for\ ([0-9]+)\ took:\ ([0-9]+)\ us ]]; then
            NUM_VARIABLES="${BASH_REMATCH[1]}"
            RUN_TIME="${BASH_REMATCH[2]}"

            # Write data to the data file
            echo "${START_TIMESTAMP},${PROVER},${THREAD_COUNT},${MEMORY_LIMIT},${BANDWIDTH_LIMIT},${NUM_VARIABLES},${RUN_TIME}" >> "$DATA_FILE"
        fi
    done <<< "$OUTPUT"

    # If the command failed, fill in rows up to MAX_VARIABLES with empty run_time
    if [ $EXIT_STATUS -ne 0 ]; then
        # Find the last NUM_VARIABLES processed
        LAST_NUM=${NUM_VARIABLES:-$((MIN_VARIABLES - 1))}
        for ((i = LAST_NUM + 1; i <= MAX_VARIABLES; i++)); do
            echo "${START_TIMESTAMP},${PROVER},${THREAD_COUNT},${MEMORY_LIMIT},${BANDWIDTH_LIMIT},${i}," >> "$DATA_FILE"
        done
    fi
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

# Step 4: Run bandwidth-thread-prover loop with memory limits
if [[ "$EXPERIMENT_TYPE" == "b" || "$EXPERIMENT_TYPE" == "both" ]]; then
    echo "Running bandwidth benchmarks..."
    for BANDWIDTH_LIMIT in "${BANDWIDTH_LIMITS[@]}"; do
        for MEMORY_LIMIT in "${MEMORY_LIMITS[@]}"; do
            for THREAD_COUNT in "${THREADS[@]}"; do
                for PROVER in "${PROVERS[@]}"; do
                    # Only 'scribe' prover is allowed for bandwidth tests
                    if [[ "$PROVER" != "scribe" ]]; then
                        echo "Skipping bandwidth test for prover $PROVER as only 'scribe' is allowed."
                        continue
                    fi

                    echo "Running prover $PROVER with bandwidth limit $BANDWIDTH_LIMIT, memory limit $MEMORY_LIMIT and $THREAD_COUNT threads..."

                    # Construct the binary path and arguments
                    BINARY_PATH="../../target/release/examples/scribe-prover"
                    ARGS="$MIN_VARIABLES $MAX_VARIABLES $SETUP_FOLDER"

                    # Print run information
                    echo "----------------------------------------"
                    echo "Starting bandwidth benchmark run:"
                    echo "Prover            : $PROVER"
                    echo "Bandwidth Limit   : $BANDWIDTH_LIMIT"
                    echo "Memory Limit      : $MEMORY_LIMIT"
                    echo "Threads           : $THREAD_COUNT"
                    echo "----------------------------------------"

                    # Run the prover with bandwidth and memory limits
                    run_with_bandwidth_limits "$BANDWIDTH_LIMIT" "$MEMORY_LIMIT" "$THREAD_COUNT" "$PROVER" "$BINARY_PATH" "$ARGS"
                done
            done
        done
    done
fi
