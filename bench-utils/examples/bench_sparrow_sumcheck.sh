#!/bin/bash

for j in {15..28}; do
        total=0
        count=0
        for i in {1..5}; do
            output=$(./main 8 $j 1 1 16)
            
            # Extract the time value using sed.
            # This sed command looks for a pattern like "time : <number>," and captures the number.
            time_val=$(echo "$output" | sed -nE 's/.*time\s*:\s*([0-9.]+),.*/\1/p')
            
            # Check if time_val was extracted successfully.
            if [ -z "$time_val" ]; then
                echo "Error: Could not extract time value from output:"
                echo "$output"
                exit 1
            fi
            
            # echo "Run $i: time = $time_val"
            
            # Sum up the times using bc for floating-point arithmetic.
            total=$(echo "$total + $time_val" | bc -l)
            ((count++))
        done

        # Compute the average
        average=$(echo "$total / $count * 1000000" | bc -l)
        # echo "Average time for $j num_vars: $average"
        echo "sparrow,$average,13,$j"
done