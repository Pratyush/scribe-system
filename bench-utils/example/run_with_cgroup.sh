#!/bin/bash

# This script runs a binary with a memory limit using cgroups.

# Usage: ./run_with_cgroup.sh <path_to_binary> [memory_limit]

# Check if the user provided the necessary arguments
if [ $# -lt 1 ]; then
    echo "Usage: $0 <path_to_binary> [memory_limit]"
    echo "Example: $0 /path/to/binary 100M"
    exit 1
fi

# Variables
BINARY_PATH="$1"                 # Path to the binary executable
MEMORY_LIMIT="${2:-100M}"        # Memory limit (default is 100M if not specified)
CGROUP_NAME="limited_memory_group"

# Ensure the binary exists and is executable
if [ ! -x "$BINARY_PATH" ]; then
    echo "Error: $BINARY_PATH is not an executable file."
    exit 1
fi

# Create cgroup
sudo cgcreate -g memory:/$CGROUP_NAME

# Convert memory limit to bytes for cgroups v1
MEMORY_LIMIT_BYTES=$(echo $MEMORY_LIMIT | awk '
    /[0-9]$/{ print $1 }         # No unit provided
    /[0-9][kK]$/{ printf "%.0f\n", $1 * 1024 }
    /[0-9][mM]$/{ printf "%.0f\n", $1 * 1024 * 1024 }
    /[0-9][gG]$/{ printf "%.0f\n", $1 * 1024 * 1024 * 1024 }
    /[0-9][tT]$/{ printf "%.0f\n", $1 * 1024 * 1024 * 1024 * 1024 }
')

# Set memory limit for the cgroup
echo $MEMORY_LIMIT_BYTES | sudo tee /sys/fs/cgroup/memory/$CGROUP_NAME/memory.limit_in_bytes > /dev/null

# Run the binary within the cgroup
echo "Running $BINARY_PATH with memory limit $MEMORY_LIMIT..."
sudo cgexec -g memory:/$CGROUP_NAME "$BINARY_PATH"

# Clean up by removing the cgroup (optional)
sudo cgdelete -g memory:/$CGROUP_NAME
