#!/bin/bash

# This script runs a binary with a memory limit using cgroups.
# It supports passing environment variables and additional arguments to the binary.

# Usage: ./run_with_cgroup.sh [memory_limit] <path_to_binary> [env_var1=value1 ...] -- [binary_args...]

# Check if the user provided the necessary arguments
if [ $# -lt 1 ]; then
    echo "Usage: $0 [memory_limit] <path_to_binary> [env_var1=value1 ...] -- [binary_args...]"
    echo "Example: $0 100M /path/to/binary RAYON_NUM_THREADS=4 -- arg1 arg2"
    exit 1
fi

# Default memory limit
DEFAULT_MEMORY_LIMIT="100M"
MEMORY_LIMIT="$DEFAULT_MEMORY_LIMIT"

# Parse optional memory limit
if [[ "$1" =~ ^[0-9]+[KMG]?$ ]]; then
    MEMORY_LIMIT="$1"
    shift  # Remove the memory limit from the arguments
fi

# Variables
BINARY_PATH="$1"  # Path to the binary executable
shift             # Remove the binary path from the arguments

# Initialize arrays for environment variables and binary arguments
ENV_VARS=()
BINARY_ARGS=()

# Parse environment variables and binary arguments
PARSING_ENV=true
for arg in "$@"; do
    if [ "$arg" == "--" ]; then
        PARSING_ENV=false
        continue
    fi

    if $PARSING_ENV && [[ "$arg" == *=* ]]; then
        # Argument is an environment variable assignment
        ENV_VARS+=("$arg")
    else
        # Argument is a binary argument
        BINARY_ARGS+=("$arg")
    fi
done

CGROUP_NAME="limited_memory_group"

# Ensure the binary exists and is executable
if [ ! -x "$BINARY_PATH" ]; then
    echo "Error: $BINARY_PATH is not an executable file."
    exit 1
fi

# Create cgroup
sudo cgcreate -g memory:/$CGROUP_NAME

# Convert memory limit to bytes
MEMORY_LIMIT_BYTES=$(echo $MEMORY_LIMIT | awk '
    /[0-9]$/{ print $1 }         # No unit provided
    /[0-9][kK]$/{ printf "%.0f\n", $1 * 1024 }
    /[0-9][mM]$/{ printf "%.0f\n", $1 * 1024 * 1024 }
    /[0-9][gG]$/{ printf "%.0f\n", $1 * 1024 * 1024 * 1024 }
    /[0-9][tT]$/{ printf "%.0f\n", $1 * 1024 * 1024 * 1024 * 1024 }
')

# Set memory limit for the cgroup
echo $MEMORY_LIMIT_BYTES | sudo tee /sys/fs/cgroup/memory/$CGROUP_NAME/memory.limit_in_bytes > /dev/null

# Run the binary within the cgroup with environment variables
echo "Running $BINARY_PATH with memory limit $MEMORY_LIMIT..."

# Build the env command with environment variables
ENV_CMD=("env")
for var in "${ENV_VARS[@]}"; do
    ENV_CMD+=("$var")
done
ENV_CMD+=("$BINARY_PATH" "${BINARY_ARGS[@]}")

sudo cgexec -g memory:/$CGROUP_NAME "${ENV_CMD[@]}"

# Clean up by removing the cgroup (optional)
sudo cgdelete -g memory:/$CGROUP_NAME
