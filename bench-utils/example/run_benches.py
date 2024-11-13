import re
import argparse
import os
import subprocess
from datetime import datetime, timezone

def parse_arguments():
    parser = argparse.ArgumentParser(description="Run benchmarks with specified provers and configurations.")
    parser.add_argument("-m", "--min-variables", type=int, default=5, help="Set minimum number of variables.")
    parser.add_argument("-M", "--max-variables", type=int, default=20, help="Set maximum number of variables.")
    parser.add_argument("-s", "--setup-folder", default="./setup", help="Set the setup folder path.")
    parser.add_argument("-p", "--provers", default="scribe,hp,gemini,plonky2,halo2", help="Comma-separated list of provers to run.")
    parser.add_argument("-l", "--memory-limits", default="500M,1G,2G,4G", help="Comma-separated list of memory limits.")
    parser.add_argument("-t", "--threads", default="1,2,4,8", help="Comma-separated list of thread counts.")
    parser.add_argument("--data-file", help="Set base name for data file output.")
    parser.add_argument("--skip-setup", action="store_true", help="Skip the setup section.")
    parser.add_argument("--no-limit", action="store_true", help="Run without memory limits for all but `scribe` and `gemini`.")
    return parser.parse_args()

def run_command_direct(command, env=None):
    """Runs a shell command and logs the output."""
    print(f"Running command: {command}")
    result = subprocess.run(command, shell=True, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if result.returncode != 0:
        print(f"Command failed: {result.stderr}")
    print(result.stdout.strip())
    return result.stdout.strip()

def run_command(command, env=None):
    """Runs a shell command and yields the output line by line in real-time."""
    print(f"Running command: {command}")
    
    process = subprocess.Popen(
        command,
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        text=True
    )
    
    # Yield stdout line by line
    while True:
        output = process.stdout.readline()
        if output == "" and process.poll() is not None:
            break
        if output:
            yield output.strip()
    
    # Yield any stderr output at the end
    stderr = process.stderr.read().strip()
    if stderr:
        yield f"Error output: {stderr}"
    
    return_code = process.wait()
    if return_code != 0:
        yield f"Command failed with return code {return_code}"

def run_with_systemd(prover, thread_count, memory_limit, command, skip_memory_limit=False):
    """Runs a command using systemd-run with resource limits and yields output line by line."""
    unit_name = f"{prover}_mem_{memory_limit}_threads_{thread_count}"
    env = os.environ.copy()
    env["RAYON_NUM_THREADS"] = str(thread_count)
    if skip_memory_limit:
        systemd_command = "sudo systemd-run " + \
            "--collect " + \
            "--scope " + \
            f"-p \"MemoryMax=16G\" " + \
            "-p \"MemorySwapMax=0\" " + \
            f"--unit=\"{unit_name}\" " + \
            f"{command}"
    else:
        systemd_command = "sudo systemd-run " + \
            "--collect " + \
            "--scope " + \
            f"--unit=\"{unit_name}\" " + \
            f"-p \"MemoryMax={memory_limit}\" " + \
            "-p \"MemorySwapMax=0\" " + \
            f"{command}"

    for line in run_command(systemd_command, env=env):
        yield line

def compile_binaries(provers):
    for prover in provers:
        if prover == "gemini":
            run_command_direct("cargo build --release --features gemini --example gemini-prover")
        elif prover == "plonky2":
            run_command_direct("cargo build --release --features plonky2 --example plonky2-prover")
        elif prover == "halo2":
            run_command_direct("cargo build --release --features halo2 --example halo2-prover")
        else:
            run_command_direct(f"cargo build --release --example {prover}-prover")

    for prover in ["scribe", "hp"]:
        run_command_direct(f"cargo build --release --example {prover}-setup")

def setup_provers(provers, min_vars, max_vars, setup_folder):
    env = os.environ.copy()
    env["TMPDIR"] = "/home/ec2-user/external/tmp"
    for prover in provers:
        if prover == "scribe":
            print("Running setup for scribe...")
            run_command_direct(f"../../target/release/examples/scribe-setup {min_vars} {max_vars} {setup_folder}", env=env)
        elif prover == "hp":
            print("Running setup for hp...")
            run_command_direct(f"../../target/release/examples/hp-setup {min_vars} {max_vars} {setup_folder}", env=env)
        else:
            print(f"Setup for prover {prover} is not implemented.")

def run_benchmark(prover, thread_count, memory_limit, min_vars, max_vars, skip_memory_limit, setup_folder, data):
    """Runs a single benchmark using systemd-run and logs results in real-time."""
    binary_path = f"../../target/release/examples/{prover}-prover"
    command = "env " + \
        "TMPDIR=/home/ec2-user/external/tmp " + \
        f"RAYON_NUM_THREADS={thread_count} " + \
        f"{binary_path} {min_vars} {max_vars} {setup_folder}"
    print("")
    print("----------------------------------------")
    print("Starting memory benchmark run:")
    print(f"Prover       : {prover}")
    print(f"Memory Limit : {memory_limit}")
    print(f"Threads      : {thread_count}")
    print("----------------------------------------")
    
    run_time = None
    skip_memory_limit = skip_memory_limit or prover in ["scribe", "gemini"]

    pattern = re.compile(r"Proving for (\d+) took: (\d+) us")
    for line in run_with_systemd(prover, thread_count, memory_limit, command, skip_memory_limit):
        print(line)  # Print real-time output for visibility
        line = line.strip()
        match = pattern.search(line)
        print("Pattern match: ", match)
        if match:
            num_variables = match.group(1)
            run_time = match.group(2)
            data.write(f"{prover},{num_variables},{thread_count},{memory_limit},{run_time}\n")
            data.flush()

def run_benchmarks(provers, memory_limits, threads, min_vars, max_vars, skip_memory_limit, setup_folder, data_file):
    """Runs benchmarks and logs results to data in real-time."""
    with open(data_file, "w") as data:
        data.write("prover,num_variables,threads,memory_limit,run_time\n")
        
        for prover in provers:
            for thread in threads:
                for mem_limit in memory_limits:
                    run_benchmark(prover, thread, mem_limit, min_vars, max_vars, skip_memory_limit, setup_folder, data)

def main():
    args = parse_arguments()

    provers = args.provers.split(",")
    memory_limits = args.memory_limits.split(",")
    threads = [int(t) for t in args.threads.split(",")]

    start_time = datetime.now().strftime("%m%d%H%M%S")
    data_file = args.data_file or f"{start_time}.data"

    print(f"Starting with configuration:\n{args}")

    # Compile binaries if necessary
    compile_binaries(provers)
    
    min_variables = args.min_variables
    max_variables = args.max_variables
    setup_folder = args.setup_folder
    skip_setup = args.skip_setup
    skip_memory_limit = args.no_limit

    # Setup
    if not skip_setup:
        setup_provers(
            provers, 
            min_variables, 
            max_variables, 
            setup_folder, 
        )

    # Run benchmarks
    run_benchmarks(
        provers, 
        memory_limits, 
        threads, 
        min_variables, 
        max_variables, 
        skip_memory_limit,
        setup_folder, 
        data_file
    )

if __name__ == "__main__":
    main()
