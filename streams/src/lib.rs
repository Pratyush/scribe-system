pub const BUFFER_SIZE: usize = 1 << 16;
pub const LOG_BUFFER_SIZE: u32 = BUFFER_SIZE.ilog2();

pub mod file_vec;
pub mod iterator;
pub mod serialize;
