import subprocess
import argparse
import time
import psutil

def run_rust_binary(nv_range, work_set_size, replace_prob):
    binary_path = "../../target/release/examples/witness-synthesis"
    for num_vars in nv_range:
        try:
            # Start time
            start_time = time.perf_counter()
            
            # Start the process
            process = subprocess.Popen(
                [binary_path, str(num_vars), str(work_set_size), str(replace_prob)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            # Monitor memory usage using psutil
            proc = psutil.Process(process.pid)
            peak_memory = 0

            while process.poll() is None:  # Check if the process is still running
                try:
                    current_memory = proc.memory_info().rss
                    peak_memory = max(peak_memory, current_memory)
                except psutil.NoSuchProcess:
                    break  # Process has already exited

            # Capture the output after process completion
            stdout, stderr = process.communicate()

            # End time
            end_time = time.perf_counter()
            duration = end_time - start_time

            # Print results
            print(f"Output for args ({num_vars}, {work_set_size}, {replace_prob}):\n{stdout}")
            print(f"Execution time: {duration:.4f} seconds")
            print(f"Peak memory usage: {peak_memory / 1024 / 1024:.2f} MB\n")

            if process.returncode != 0:
                print(f"Error: {stderr}")

        except psutil.NoSuchProcess:
            print(f"Process {process.pid} exited before monitoring could complete.")
        except Exception as e:
            print(f"An error occurred: {e}")




if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="Run Rust binary with a range of arguments.")
    parser.add_argument("-m", "--min", type=int, help="Minimum number of variables.")
    parser.add_argument("-M", "--max", type=int, help="Maximum number of variables.")
    parser.add_argument("-w", "--work-set-size", type=int, default=2**17, help="Size of the working set (default: 2^17).")
    parser.add_argument("-r", "--replace-prob", type=float, default=0.01, help="Probability with which we update the working set (default: 0.01).")
    
    args = parser.parse_args()

    # Generate the range for the first argument
    first_arg_range = range(args.min, args.max)

    # Call the Rust binary with the provided arguments
    run_rust_binary(first_arg_range, args.work_set_size, args.replace_prob)