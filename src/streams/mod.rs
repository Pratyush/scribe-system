pub const BUFFER_SIZE: usize = 1 << 2;
pub const LOG_BUFFER_SIZE: u32 = BUFFER_SIZE.ilog2();

pub mod dense_mle;
pub use dense_mle::*;

pub mod file_vec;
pub mod iterator;
pub mod serialize;
