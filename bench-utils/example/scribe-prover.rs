/* use jemallocator::Jemalloc;

#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;
 */
pub fn main() {
    let args = std::env::args().skip(1).collect::<Vec<String>>();
    let min_num_vars: usize = args[0].parse().unwrap();
    let max_num_vars: usize = args[1].parse().unwrap();
    let file_dir_path = std::path::Path::new(args[2].as_str());
    bench_utils::scribe::prover(min_num_vars, max_num_vars, None, file_dir_path, false).unwrap();
}
