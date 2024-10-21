#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub(crate) use linux::avec;
#[cfg(target_os = "linux")]
pub use linux::{AVec, InnerFile};

#[cfg(not(target_os = "linux"))]
mod default;
#[cfg(not(target_os = "linux"))]
pub use default::{avec, AVec, InnerFile};

pub trait ReadN: std::io::Read {
    /// Reads `n` bytes from the file into `dest`.
    /// This assumes that `dest` is of length `n`.
    /// Clears `dest` before reading.
    ///
    /// If `self` contains `m` bytes, for `m < n`, this function will fill `dest` with `m` bytes and return `Ok(())`.
    fn read_n(&mut self, dest: &mut AVec, n: usize) -> std::io::Result<()> {
        assert_eq!(dest.len(), 0);
        dest.clear();
        dest.reserve(n);
        // Safety: `dest` is empty and has capacity `n`.
        unsafe {
            dest.set_len(n);
        }
        dest.fill(0);
        let n = self.read(&mut dest[..n])?;
        dest.truncate(n);
        Ok(())
    }
}

impl<R: std::io::Read> ReadN for R {}
