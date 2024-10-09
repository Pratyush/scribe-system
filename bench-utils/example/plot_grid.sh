#!/bin/bash

# Usage: ./plot_grid.sh data_file --grid-x variable [values] --grid-y variable [values] --legend variable [values]

# Function to display help
function show_help {
    echo "Usage: $0 data_file --grid-x variable [values] --grid-y variable [values] --legend variable [values]"
    echo
    echo "Variables can be one of: prover, threads, memory_limit, bandwidth_limit"
    echo "Values are optional; if omitted, all available values will be used."
    echo "Example:"
    echo "$0 data.csv --grid-x memory_limit --grid-y threads --legend prover"
    echo "$0 data.csv --grid-x memory_limit 1G 2G --grid-y threads 1 2 4 --legend prover gemini scribe"
}

# Check for minimum arguments
if [ $# -lt 7 ]; then
    show_help
    exit 1
fi

# Parse arguments
DATA_FILE="$1"
shift

GRID_X=""
GRID_X_VALUES=()
GRID_Y=""
GRID_Y_VALUES=()
LEGEND=""
LEGEND_VALUES=()

while [[ $# -gt 0 ]]; do
    key="$1"
    case $key in
        --grid-x)
            GRID_X="$2"
            shift 2
            # Collect optional values
            while [[ $# -gt 0 && ! "$1" =~ --grid-.*|--legend ]]; do
                GRID_X_VALUES+=("$1")
                shift
            done
            ;;
        --grid-y)
            GRID_Y="$2"
            shift 2
            # Collect optional values
            while [[ $# -gt 0 && ! "$1" =~ --grid-.*|--legend ]]; do
                GRID_Y_VALUES+=("$1")
                shift
            done
            ;;
        --legend)
            LEGEND="$2"
            shift 2
            # Collect optional values
            while [[ $# -gt 0 && ! "$1" =~ --grid-.*|--legend ]]; do
                LEGEND_VALUES+=("$1")
                shift
            done
            ;;
        *)
            echo "Unknown argument: $1"
            show_help
            exit 1
            ;;
    esac
done

# Stage 1: Print all available values of all variables (except starting_timestamp and run_time)
echo "Available values for all variables:"
HEADER_LINE=$(head -1 "$DATA_FILE")
IFS=',' read -r -a HEADERS <<< "$HEADER_LINE"

declare -A AVAILABLE_VALUES

for VAR in "${HEADERS[@]}"; do
    if [[ "$VAR" == "starting_timestamp" || "$VAR" == "run_time" ]]; then
        continue
    fi
    # Get the index of the variable in the header
    INDEX=-1
    for i in "${!HEADERS[@]}"; do
        if [[ "${HEADERS[$i]}" == "$VAR" ]]; then
            INDEX=$i
            break
        fi
    done
    # Extract unique values for the variable
    VALUES=$(tail -n +2 "$DATA_FILE" | awk -F',' -v col=$((INDEX+1)) '{print $col}' | sort | uniq | sed '/^\s*$/d')
    AVAILABLE_VALUES["$VAR"]="$VALUES"
    echo "Variable: $VAR"
    echo "$VALUES"
    echo
done

# Stage 2: Validate required variables and process values
VARIABLES=("$GRID_X" "$GRID_Y" "$LEGEND")

# Check that required variables are different
if [[ "$GRID_X" == "$GRID_Y" || "$GRID_X" == "$LEGEND" || "$GRID_Y" == "$LEGEND" ]]; then
    echo "Error: The grid x-axis, grid y-axis, and legend variables must all be different."
    exit 1
fi

# Check that memory_limit and bandwidth_limit are not both among required variables
if [[ ( "$GRID_X" == "memory_limit" || "$GRID_Y" == "memory_limit" || "$LEGEND" == "memory_limit" ) && \
      ( "$GRID_X" == "bandwidth_limit" || "$GRID_Y" == "bandwidth_limit" || "$LEGEND" == "bandwidth_limit" ) ]]; then
    echo "Error: 'memory_limit' and 'bandwidth_limit' cannot both be among the required variables."
    exit 1
fi

# Function to validate and process provided values
function process_values {
    local VAR="$1"
    local -n VAR_VALUES="$2"
    local AVAILABLE="${AVAILABLE_VALUES[$VAR]}"
    local PROCESSED_VALUES=()
    local AVAILABLE_ARRAY=()
    IFS=$'\n' read -d '' -r -a AVAILABLE_ARRAY <<< "$AVAILABLE"
    if [ ${#VAR_VALUES[@]} -eq 0 ]; then
        # Use all available values
        VAR_VALUES=("${AVAILABLE_ARRAY[@]}")
    else
        # Filter out invalid values
        for VAL in "${VAR_VALUES[@]}"; do
            if grep -Fxq "$VAL" <<< "$AVAILABLE"; then
                PROCESSED_VALUES+=("$VAL")
            else
                echo "Warning: Value '$VAL' is not available for variable '$VAR' and will be ignored."
            fi
        done
        VAR_VALUES=("${PROCESSED_VALUES[@]}")
    fi
}

process_values "$GRID_X" GRID_X_VALUES
process_values "$GRID_Y" GRID_Y_VALUES
process_values "$LEGEND" LEGEND_VALUES

# Print the values that will be used
echo "Values to be used:"
echo "$GRID_X: ${GRID_X_VALUES[*]}"
echo "$GRID_Y: ${GRID_Y_VALUES[*]}"
echo "$LEGEND: ${LEGEND_VALUES[*]}"

# Stage 3: Generate Gnuplot script
GNUPLOT_SCRIPT="plot_grid.gnuplot"

echo "set terminal pngcairo size 800,600" > "$GNUPLOT_SCRIPT"
echo "set output 'grid_plot.png'" >> "$GNUPLOT_SCRIPT"

# Fix underscores in labels by escaping them or setting gnuplot to not interpret them
echo "set key noenhanced" >> "$GNUPLOT_SCRIPT"
echo "set encoding utf8" >> "$GNUPLOT_SCRIPT"

NUM_ROWS=${#GRID_Y_VALUES[@]}
NUM_COLS=${#GRID_X_VALUES[@]}

echo "set multiplot layout $NUM_ROWS,$NUM_COLS title 'Grid of Line Charts'" >> "$GNUPLOT_SCRIPT"

# Prepare temporary data files
TEMP_DIR=$(mktemp -d)
trap 'rm -rf "$TEMP_DIR"' EXIT

PLOT_COUNT=0
for GRID_Y_VAL in "${GRID_Y_VALUES[@]}"; do
    for GRID_X_VAL in "${GRID_X_VALUES[@]}"; do
        PLOT_COUNT=$((PLOT_COUNT+1))
        CELL_DATA_FILE="$TEMP_DIR/data_${GRID_X_VAL}_${GRID_Y_VAL}.dat"
        awk -F',' -v x_var="$GRID_X" -v x_val="$GRID_X_VAL" \
            -v y_var="$GRID_Y" -v y_val="$GRID_Y_VAL" \
            'NR==1{
                for (i=1; i<=NF; i++) {
                    header[$i]=i
                }
                next
             }
             {
                if ($(header[x_var])==x_val && $(header[y_var])==y_val) {
                    print
                }
             }' "$DATA_FILE" > "$CELL_DATA_FILE"

        # Check if CELL_DATA_FILE is empty
        if [ ! -s "$CELL_DATA_FILE" ]; then
            echo "Warning: No data found for $GRID_X='$GRID_X_VAL', $GRID_Y='$GRID_Y_VAL'. Skipping this subplot."
            echo "#### Subplot $PLOT_COUNT" >> "$GNUPLOT_SCRIPT"
            # Escape underscores in labels
            GRID_X_LABEL=$(echo "$GRID_X_VAL" | sed 's/_/\\\\_/g')
            GRID_Y_LABEL=$(echo "$GRID_Y_VAL" | sed 's/_/\\\\_/g')
            echo "set title '$GRID_X=$GRID_X_LABEL, $GRID_Y=$GRID_Y_LABEL'" >> "$GNUPLOT_SCRIPT"
            echo "set xlabel 'num_variables'" >> "$GNUPLOT_SCRIPT"
            echo "set ylabel 'run_time (us)'" >> "$GNUPLOT_SCRIPT"
            echo "set grid" >> "$GNUPLOT_SCRIPT"
            echo "plot NaN notitle" >> "$GNUPLOT_SCRIPT"
            continue
        fi

        echo "#### Subplot $PLOT_COUNT" >> "$GNUPLOT_SCRIPT"
        # Escape underscores in labels
        GRID_X_LABEL=$(echo "$GRID_X_VAL" | sed 's/_/\\\\_/g')
        GRID_Y_LABEL=$(echo "$GRID_Y_VAL" | sed 's/_/\\\\_/g')
        echo "set title '$GRID_X=$GRID_X_LABEL, $GRID_Y=$GRID_Y_LABEL'" >> "$GNUPLOT_SCRIPT"
        echo "set xlabel 'num_variables'" >> "$GNUPLOT_SCRIPT"
        echo "set ylabel 'run_time (us)'" >> "$GNUPLOT_SCRIPT"
        echo "set grid" >> "$GNUPLOT_SCRIPT"
        echo -n "plot " >> "$GNUPLOT_SCRIPT"
        LEGEND_PLOTS=()
        DATA_FOUND=false
        for LEGEND_VAL in "${LEGEND_VALUES[@]}"; do
            # Filter data for legend value
            LEGEND_DATA_FILE="$TEMP_DIR/data_${GRID_X_VAL}_${GRID_Y_VAL}_${LEGEND_VAL}.dat"
            awk -F',' -v legend_var="$LEGEND" -v legend_val="$LEGEND_VAL" \
                'NR==1{
                    for (i=1; i<=NF; i++) {
                        header[$i]=i
                    }
                    next
                 }
                 {
                    if ($(header[legend_var])==legend_val && $(header["run_time"]) != "") {
                        print $(header["num_variables"]), $(header["run_time"])
                    }
                 }' "$CELL_DATA_FILE" | sort -nk1 > "$LEGEND_DATA_FILE"
            if [ -s "$LEGEND_DATA_FILE" ]; then
                # Escape underscores in legend labels
                LEGEND_LABEL=$(echo "$LEGEND_VAL" | sed 's/_/\\\\_/g')
                LEGEND_PLOTS+=(" '$LEGEND_DATA_FILE' using 1:2 with linespoints title '$LEGEND_LABEL'")
                DATA_FOUND=true
            else
                echo "Notice: No data for $LEGEND='$LEGEND_VAL' at $GRID_X='$GRID_X_VAL', $GRID_Y='$GRID_Y_VAL'."
            fi
        done
        if [ "$DATA_FOUND" = false ]; then
            echo "Warning: No data found for any legend values at $GRID_X='$GRID_X_VAL', $GRID_Y='$GRID_Y_VAL'."
            echo "plot NaN notitle" >> "$GNUPLOT_SCRIPT"
        else
            echo "${LEGEND_PLOTS[*]}" | sed 's/  /, /g' >> "$GNUPLOT_SCRIPT"
        fi
    done
done

echo "unset multiplot" >> "$GNUPLOT_SCRIPT"

# Run Gnuplot
if ! command -v gnuplot &> /dev/null; then
    echo "Error: Gnuplot is not installed or not found in your PATH."
    echo "Please install Gnuplot to run this script."
    exit 1
fi

gnuplot "$GNUPLOT_SCRIPT"

echo "Plot saved to grid_plot.png"

