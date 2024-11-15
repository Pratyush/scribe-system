#!/usr/bin/env python3

import argparse
import csv
import sys
from collections import defaultdict

import matplotlib.pyplot as plt
from matplotlib.ticker import ScalarFormatter, LogLocator


def parse_arguments():
    parser = argparse.ArgumentParser(description='Generate grid plots from data.')
    parser.add_argument('data_file', help='Input data CSV file')
    parser.add_argument('--grid-x', nargs='+', required=True, help='Variable for grid x-axis, followed by optional values')
    parser.add_argument('--grid-y', nargs='+', required=True, help='Variable for grid y-axis, followed by optional values')
    parser.add_argument('--legend', nargs='+', required=True, help='Variable for legend, followed by optional values')
    parser.add_argument('--output', '-o', default='grid_plot.png', help='Output file name for the plot image (default: grid_plot.png)')

    args = parser.parse_args()

    data_file = args.data_file

    grid_x = args.grid_x[0]
    grid_x_values = args.grid_x[1:] if len(args.grid_x) > 1 else []

    grid_y = args.grid_y[0]
    grid_y_values = args.grid_y[1:] if len(args.grid_y) > 1 else []

    legend = args.legend[0]
    legend_values = args.legend[1:] if len(args.legend) > 1 else []

    output_file = args.output

    return data_file, grid_x, grid_x_values, grid_y, grid_y_values, legend, legend_values, output_file


def read_data(data_file):
    # Read CSV data, handling empty fields
    with open(data_file, 'r') as csvfile:
        reader = csv.DictReader(csvfile)
        data = list(reader)
        headers = reader.fieldnames
    return data, headers


def get_available_values(data, variable):
    values = set()
    for row in data:
        value = row.get(variable, '').strip()
        if value:
            values.add(value)
    return sorted(values)


def process_values(variable, provided_values, available_values):
    if not provided_values:
        return available_values
    else:
        processed_values = []
        for val in provided_values:
            if val in available_values:
                processed_values.append(val)
            else:
                print(f"Warning: Value '{val}' is not available for variable '{variable}' and will be ignored.")
        return processed_values


def validate_variables(grid_x, grid_y, legend):
    if grid_x == grid_y or grid_x == legend or grid_y == legend:
        print("Error: The grid x-axis, grid y-axis, and legend variables must all be different.")
        sys.exit(1)
    if ('memory_limit' in [grid_x, grid_y, legend]) and ('bandwidth_limit' in [grid_x, grid_y, legend]):
        print("Error: 'memory_limit' and 'bandwidth_limit' cannot both be among the required variables.")
        sys.exit(1)


def prepare_data(data, grid_x, grid_x_values, grid_y, grid_y_values, legend, legend_values):
    # Organize data into a nested dictionary for easy access
    nested_data = defaultdict(lambda: defaultdict(lambda: defaultdict(list)))
    for row in data:
        x_val = row.get(grid_x, '').strip()
        y_val = row.get(grid_y, '').strip()
        legend_val = row.get(legend, '').strip()
        num_variables = row.get('num_variables', '').strip()
        run_time = row.get('run_time', '').strip()

        if not x_val or not y_val or not legend_val or not num_variables or not run_time:
            continue  # Skip incomplete data

        if x_val in grid_x_values and y_val in grid_y_values and legend_val in legend_values:
            nested_data[y_val][x_val][legend_val].append((int(num_variables), float(run_time)))

    return nested_data


def escape_underscores(label):
    return label.replace('_', r'\_')


def plot_grid(nested_data, grid_x_values, grid_y_values, legend_values, grid_x, grid_y, legend, output_file):
    import numpy as np

    num_rows = len(grid_y_values)
    num_cols = len(grid_x_values)

    fig, axes = plt.subplots(num_rows, num_cols, figsize=(4 * num_cols, 3 * num_rows), squeeze=False)
    fig.suptitle('Proving Time Benchmarking', y=0.95)

    # Collect handles and labels for legend
    legend_handles = []
    legend_labels = []

    for i, y_val in enumerate(grid_y_values):
        for j, x_val in enumerate(grid_x_values):
            ax = axes[i][j]
            data_found = False

            if y_val in nested_data and x_val in nested_data[y_val]:
                for legend_val in legend_values:
                    if legend_val in nested_data[y_val][x_val]:
                        data = nested_data[y_val][x_val][legend_val]
                        data.sort(key=lambda x: x[0])  # Sort by num_variables
                        num_vars, run_times = zip(*data)
                        legend_label = escape_underscores(legend_val)
                        (line,) = ax.plot(num_vars, run_times, marker='o', label=legend_label)
                        if legend_label not in legend_labels:
                            legend_handles.append(line)
                            legend_labels.append(legend_label)
                        data_found = True
                    else:
                        print(f"Notice: No data for {legend}='{legend_val}' at {grid_x}='{x_val}', {grid_y}='{y_val}'.")
            else:
                print(f"Warning: No data found for {grid_x}='{x_val}', {grid_y}='{y_val}'. Skipping this subplot.")

            ax.grid(True)

            # Set y-axis to logarithmic scale
            ax.set_yscale('log')

            # Use ScalarFormatter for y-axis tick labels in scientific notation
            formatter = ScalarFormatter()
            formatter.set_scientific(True)
            formatter.set_powerlimits((0, 0))
            ax.yaxis.set_major_formatter(formatter)
            ax.yaxis.set_minor_formatter(formatter)

            # Set y-axis minor locator for better tick spacing
            ax.yaxis.set_minor_locator(LogLocator(base=10.0, subs=np.arange(1, 10)))

            if not data_found:
                ax.plot([], [])
                ax.text(0.5, 0.5, 'No data', transform=ax.transAxes, ha='center', va='center')

            # Only set x-labels for bottom row
            if i == num_rows - 1:
                ax.set_xlabel('num_variables')

            # Only set y-labels for leftmost column
            if j == 0:
                ax.set_ylabel('run_time (us)')

    # Adjust spacing
    plt.subplots_adjust(hspace=0.1, wspace=0.1)

    # Add legend below the plots but above x-axis labels
    # Place legend at the bottom center of the grid
    fig.legend(legend_handles, legend_labels, loc='lower center', ncol=len(legend_labels),
               bbox_to_anchor=(0.5, 0.0), bbox_transform=fig.transFigure, borderaxespad=0.1)

    # Add grid x values as labels above the x-axis of the bottom plots
    for j, x_val in enumerate(grid_x_values):
        x_label = escape_underscores(f'{grid_x}={x_val}')
        axes[-1][j].set_xlabel('num_variables\n' + x_label)

    # Add grid y values as labels next to the y-axis of the leftmost plots
    for i, y_val in enumerate(grid_y_values):
        y_label = escape_underscores(f'{grid_y}={y_val}')
        axes[i][0].set_ylabel(y_label + '\nrun_time (us)')

    plt.tight_layout(rect=[0, 0.05, 1, 0.93])  # Adjust rect to make space for legend and title
    plt.savefig(output_file)
    print(f"Plot saved to {output_file}")


def main():
    data_file, grid_x, grid_x_values, grid_y, grid_y_values, legend, legend_values, output_file = parse_arguments()

    data, headers = read_data(data_file)

    # Validate variables
    validate_variables(grid_x, grid_y, legend)

    # Get available values for all variables
    print("Available values for all variables:")
    available_values = {}
    for var in headers:
        if var in ['starting_timestamp', 'run_time']:
            continue
        values = get_available_values(data, var)
        available_values[var] = values
        print(f"Variable: {var}")
        for val in values:
            print(val)
        print()

    # Process provided values
    grid_x_values = process_values(grid_x, grid_x_values, available_values.get(grid_x, []))
    grid_y_values = process_values(grid_y, grid_y_values, available_values.get(grid_y, []))
    legend_values = process_values(legend, legend_values, available_values.get(legend, []))

    print("Values to be used:")
    print(f"{grid_x}: {' '.join(grid_x_values)}")
    print(f"{grid_y}: {' '.join(grid_y_values)}")
    print(f"{legend}: {' '.join(legend_values)}")

    # Prepare data
    nested_data = prepare_data(data, grid_x, grid_x_values, grid_y, grid_y_values, legend, legend_values)

    # Plot grid
    plot_grid(nested_data, grid_x_values, grid_y_values, legend_values, grid_x, grid_y, legend, output_file)


if __name__ == "__main__":
    main()

