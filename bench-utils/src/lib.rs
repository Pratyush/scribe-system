use std::{ffi::CStr, path::Path};

use libc::{c_char, size_t};

macro_rules! timed {
    ($name:expr, $block:expr) => {{
        let start = Instant::now();
        let result = { $block };
        let elapsed = start.elapsed().as_micros();
        println!("{} took: {:?} us", $name, elapsed);
        result
    }};
}

pub mod hp;
pub mod scribe;
pub use hp::*;
pub use scribe::*;

#[no_mangle]
pub extern "C" fn bench_scribe_prover(
    min_num_vars: size_t,
    max_num_vars: size_t,
    file_dir_path: *const c_char,
) -> size_t {
    let file_dir_path = unsafe { CStr::from_ptr(file_dir_path) }.to_str().unwrap();
    match scribe_prover(min_num_vars, max_num_vars, Path::new(file_dir_path)) {
        Ok(_) => 0,
        Err(_) => 1,
    }
}

#[no_mangle]
pub extern "C" fn bench_hp_prover(
    min_num_vars: size_t,
    max_num_vars: size_t,
    file_dir_path: *const c_char,
) -> size_t {
    let file_dir_path = unsafe { CStr::from_ptr(file_dir_path) }.to_str().unwrap();
    match hp_prover(min_num_vars, max_num_vars, Path::new(file_dir_path)) {
        Ok(_) => 0,
        Err(_) => 1,
    }
}
