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

#[cfg(feature = "gemini")]
pub mod gemini;
#[cfg(feature = "halo2")]
pub mod halo2;
pub mod hp;
#[cfg(feature = "plonky2")]
pub mod plonky2;
pub mod scribe;

#[no_mangle]
pub extern "C" fn bench_scribe_prover(
    min_num_vars: size_t,
    max_num_vars: size_t,
    supported_size: size_t,
    file_dir_path: *const c_char,
) -> size_t {
    rlimit::increase_nofile_limit(1 << 13).unwrap();
    let file_dir_path = unsafe { CStr::from_ptr(file_dir_path) }.to_str().unwrap();
    match scribe::prover(
        min_num_vars,
        max_num_vars,
        supported_size,
        Path::new(file_dir_path),
    ) {
        Ok(_) => 0,
        Err(_) => 1,
    }
}

#[no_mangle]
pub extern "C" fn bench_hp_prover(
    min_num_vars: size_t,
    max_num_vars: size_t,
    supported_size: size_t,
    file_dir_path: *const c_char,
) -> size_t {
    let file_dir_path = unsafe { CStr::from_ptr(file_dir_path) }.to_str().unwrap();
    match hp::prover(
        min_num_vars,
        max_num_vars,
        supported_size,
        Path::new(file_dir_path),
    ) {
        Ok(_) => 0,
        Err(_) => 1,
    }
}

#[no_mangle]
pub extern "C" fn bench_gemini_prover(
    min_num_vars: size_t,
    max_num_vars: size_t,
) -> size_t {
    gemini::prover(
        min_num_vars,
        max_num_vars,
    );
    1
}