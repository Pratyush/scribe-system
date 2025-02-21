# Benchmarking Script

This script runs benchmarks for various cryptographic provers with configurable memory limits and thread counts. The results are logged to a data file.

## Prerequisites

- Python 3
- Cargo (Rust package manager)
- `systemd-run` (requires sudo privileges)
- Ensure the necessary binaries are built before running the benchmarks.

## Installation

1. Clone the repository (if applicable) and navigate to the script's directory:

   ```sh
   git clone <repository-url>
   cd <repository-directory>
   ```

2. Install Rust and Cargo if not already installed:

    ```sh
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
    source $HOME/.cargo/env
    ```

3. Ensure the required dependencies are installed:

   ```sh
   sudo apt update && sudo apt install systemd cargo python3
   ```

## Usage

Run the script using:

```sh
python3 benchmark.py [OPTIONS]
```

### Options

| Option                 | Description                                               | Default Value |
|------------------------|-----------------------------------------------------------|---------------|
| `-m`, `--min-variables` | Minimum number of variables                              | `5`           |
| `-M`, `--max-variables` | Maximum number of variables                              | `20`          |
| `-s`, `--setup-folder`  | Path to the setup folder                                | `./setup`      |
| `-p`, `--provers`       | Comma-separated list of provers                         | `scribe,hp,gemini,plonky2,halo2` |
| `-l`, `--memory-limits` | Comma-separated list of memory limits                   | `500M,1G,2G,4G` |
| `-t`, `--threads`       | Comma-separated list of thread counts                   | `1,2,4,8`       |
| `--data-file`          | Specify the output file for benchmark results           | Auto-generated timestamped file |
| `--skip-setup`         | Skip the setup phase                                    | `False`        |
| `--bw-limit [VALUE]`   | Set a bandwidth limit (e.g., `200M`). If used without a value, defaults to `200M`. | `None` (no limit) |

### Example Usage

#### Run benchmarks with default settings

```sh
python3 benchmark.py
```

#### Specify provers and memory limits

```sh
python3 benchmark.py -p "scribe,hp" -l "1G,2G" -t "2,4"
```

#### Skip setup phase

```sh
python3 benchmark.py --skip-setup
```

#### Specify a custom output data file

```sh
python3 benchmark.py --data-file results.csv
```

#### Enforce default bandwidth limit (200M)

```sh
python3 benchmark.py --bw-limit
```

#### Enforce a custom bandwidth limit (e.g., 150M)

```sh
python3 benchmark.py --bw-limit 150M
```

## Output Format

The benchmark results are stored in a CSV file with the following structure:

```csv
prover,num_variables,threads,memory_limit,bandwidth,max_tmpdir_usage,run_time
scribe,10,2,1G,200M,5000000000,5000
hp,12,4,2G,None,7000000000,7000
```

Here,

- the `bandwidth` column will show `None` if no bandwidth limit was enforced.
- the `max_tmpdir_usage` column indicates the maximum temporary directory usage during the benchmark, in terms of bytes.
- the `run_time` column indicates the total prover runtime, in microseconds.

## Notes

- Ensure `systemd-run` has the necessary privileges (`sudo` may be required).
- The script compiles the binaries before execution.
- Results are saved in a timestamped file unless specified otherwise.
- `--bw-limit` allows specifying a custom bandwidth limit; if omitted, no limit is enforced.
- Currently the script hardcodes a particular temporary directory that is used for benchmarking Scribe. If you want to use a different directory, you will need to modify the script.
