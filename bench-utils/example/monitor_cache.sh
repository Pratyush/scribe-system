#!/bin/bash

# Function to convert kB to MB and display current cache and buffer usage
display_cache_info() {
    echo "----------------------------------------"
    date
    echo "File System Cache Usage (in MB):"
    awk '/^(MemTotal|MemFree|Buffers|Cached):/ { printf "%s: %.2f MB\n", $1, $2/1024 }' /proc/meminfo
    echo "----------------------------------------"
}

# Interval in seconds between updates
INTERVAL=5

# Monitor loop
while true; do
    display_cache_info
    sleep $INTERVAL
done

