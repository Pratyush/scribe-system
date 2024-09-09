pub fn main() {
    let [min_num_vars, max_num_vars] = std::env::args()
        .skip(1)
        .map(|arg| arg.parse().unwrap())
        .take(2)
        .collect::<Vec<usize>>()[..]
    else {
        panic!("Please provide min_num_vars and max_num_vars as arguments")
    };
    bench_utils::prover(min_num_vars, max_num_vars).unwrap();
}
