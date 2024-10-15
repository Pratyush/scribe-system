use std::{
    ffi::OsStr,
    fs::{File, OpenOptions},
    io::{self, IoSlice, IoSliceMut, Read, Write},
    path::PathBuf,
};

use tempfile::NamedTempFile;

pub type AVec = Vec<u8>;

#[derive(Debug)]
pub struct InnerFile {
    pub file: File,
    pub path: PathBuf,
}

impl InnerFile {
    #[inline(always)]
    pub fn new(file: File, path: PathBuf) -> Self {
        Self { file, path }
    }

    #[inline(always)]
    pub fn new_temp(prefix: impl AsRef<OsStr>) -> Self {
        let mut options = OpenOptions::new();
        options
            .read(true)
            .write(true)
            .create(true);
        let (file, path) = Builder::new()
            .prefix(&prefix)
            .suffix(".scribe")
            .keep(true)
            .make(|p| options.open(p))
            .expect("failed to open file")
            .keep()
            .expect("failed to keep file");
        Self { file, path }
    }

    #[inline(always)]
    pub fn reopen(&self) -> io::Result<Self> {
        let file = File::open(&self.path)?;
        Ok(Self::new(file, self.path.clone()))
    }

    #[inline(always)]
    pub fn reopen_read(&self) -> io::Result<Self> {
        let file = OpenOptions::new().read(true).open(&self.path)?;
        Ok(Self::new(file, self.path.clone()))
    }

    #[inline(always)]
    pub fn remove(self) -> io::Result<()> {
        std::fs::remove_file(&self.path)
    }

    #[inline(always)]
    pub fn try_clone(&self) -> io::Result<Self> {
        let file = self.file.try_clone()?;
        Ok(Self::new(file, self.path.clone()))
    }

    /// Reads `n` bytes from the file into `dest`.
    /// This assumes that `dest` is of length `n`.
    pub fn read_n(&mut self, dest: &mut AVec, n: usize) -> io::Result<()> {
        assert_eq!(dest.len(), 0);
        dest.clear();
        dest.reserve(n);
        // Safety: `dest` is empty and has capacity `n`.
        unsafe {
            dest.set_len(n);
        }
        dest.fill(0);
        self.file.read_exact(&mut dest[..n])
    }
}

impl Read for InnerFile {
    #[inline(always)]
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        (&*self).read(buf)
    }

    #[inline(always)]
    fn read_vectored(&mut self, bufs: &mut [IoSliceMut<'_>]) -> io::Result<usize> {
        (&*self).read_vectored(bufs)
    }

    #[inline(always)]
    fn read_to_end(&mut self, buf: &mut Vec<u8>) -> io::Result<usize> {
        (&*self).read_to_end(buf)
    }

    #[inline(always)]
    fn read_to_string(&mut self, buf: &mut String) -> io::Result<usize> {
        (&*self).read_to_string(buf)
    }
}

impl Read for &InnerFile {
    /// Read some bytes from the file.
    ///
    /// See [`Read::read`] docs for more info.
    ///
    /// # Platform-specific behavior
    ///
    /// This function currently corresponds to the `read` function on Unix and
    /// the `NtReadFile` function on Windows. Note that this [may change in
    /// the future][changes].
    ///
    /// [changes]: io#platform-specific-behavior
    #[inline(always)]
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        (&(*self).file).read(buf)
    }

    /// Like `read`, except that it reads into a slice of buffers.
    ///
    /// See [`Read::read_vectored`] docs for more info.
    ///
    /// # Platform-specific behavior
    ///
    /// This function currently corresponds to the `readv` function on Unix and
    /// falls back to the `read` implementation on Windows. Note that this
    /// [may change in the future][changes].
    ///
    /// [changes]: io#platform-specific-behavior
    #[inline(always)]
    fn read_vectored(&mut self, bufs: &mut [IoSliceMut<'_>]) -> io::Result<usize> {
        (&(*self).file).read_vectored(bufs)
    }

    // Reserves space in the buffer based on the file size when available.
    #[inline(always)]
    fn read_to_end(&mut self, buf: &mut Vec<u8>) -> io::Result<usize> {
        (&(*self).file).read_to_end(buf)
    }

    // Reserves space in the buffer based on the file size when available.
    #[inline(always)]
    fn read_to_string(&mut self, buf: &mut String) -> io::Result<usize> {
        (&(*self).file).read_to_string(buf)
    }
}

impl Write for InnerFile {
    #[inline(always)]
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        (&*self).write(buf)
    }

    #[inline(always)]
    fn write_vectored(&mut self, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
        (&*self).write_vectored(bufs)
    }

    #[inline(always)]
    fn flush(&mut self) -> io::Result<()> {
        (&*self).flush()
    }
}

impl Write for &InnerFile {
    /// Write some bytes from the file.
    ///
    /// See [`Write::write`] docs for more info.
    ///
    /// # Platform-specific behavior
    ///
    /// This function currently corresponds to the `write` function on Unix and
    /// the `NtWriteFile` function on Windows. Note that this [may change in
    /// the future][changes].
    ///
    /// [changes]: io#platform-specific-behavior
    #[inline(always)]
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        (&self.file).write(buf)
    }

    /// Like `write`, except that it writes into a slice of buffers.
    ///
    /// See [`Write::write_vectored`] docs for more info.
    ///
    /// # Platform-specific behavior
    ///
    /// This function currently corresponds to the `writev` function on Unix
    /// and falls back to the `write` implementation on Windows. Note that this
    /// [may change in the future][changes].
    ///
    /// [changes]: io#platform-specific-behavior
    #[inline(always)]
    fn write_vectored(&mut self, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
        (&self.file).write_vectored(bufs)
    }

    /// Flushes the file, ensuring that all intermediately buffered contents
    /// reach their destination.
    ///
    /// See [`Write::flush`] docs for more info.
    ///
    /// # Platform-specific behavior
    ///
    /// Since a `File` structure doesn't contain any buffers, this function is
    /// currently a no-op on Unix and Windows. Note that this [may change in
    /// the future][changes].
    ///
    /// [changes]: io#platform-specific-behavior
    #[inline(always)]
    fn flush(&mut self) -> io::Result<()> {
        (&self.file).flush()
    }
}

impl io::Seek for &InnerFile {
    #[inline(always)]
    fn seek(&mut self, pos: io::SeekFrom) -> io::Result<u64> {
        (&(*self).file).seek(pos)
    }
}

impl io::Seek for InnerFile {
    #[inline(always)]
    fn seek(&mut self, pos: io::SeekFrom) -> io::Result<u64> {
        (&*self).seek(pos)
    }
}
