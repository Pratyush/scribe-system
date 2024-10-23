use std::{
    ffi::OsStr,
    fs::{File, OpenOptions},
    io::{self, IoSlice, Read, Write},
    os::unix::fs::OpenOptionsExt,
    path::PathBuf,
    sync::{Arc, Mutex},
};
use tempfile::Builder;

use crate::BUFFER_SIZE;

pub type AVec = aligned_vec::AVec<u8, aligned_vec::ConstAlign<4096>>;

macro_rules! avec {
    () => {
        $crate::file_vec::AVec::new(4096)
    };
    ($elem: expr; $count: expr) => {
        $crate::file_vec::AVec::__from_elem(0, $elem, $count)
    };
}

pub(crate) use avec;

#[derive(Debug)]
pub struct InnerFile {
    file: File,
    buffer: Arc<Mutex<AVec>>,
    pub path: PathBuf,
}

impl InnerFile {
    #[inline(always)]
    pub fn create_read_write(path: PathBuf) -> Self {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .custom_flags(libc::O_DIRECT)
            .open(&path)
            .expect("failed to open file");
        let buffer: AVec = AVec::with_capacity(4096, BUFFER_SIZE);
        Self {
            file,
            buffer: Arc::new(Mutex::new(buffer)),
            path,
        }
    }

    #[inline(always)]
    pub fn open_read_only(path: PathBuf) -> Self {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECT)
            .open(&path)
            .expect("failed to open file");
        let buffer: AVec = AVec::with_capacity(4096, BUFFER_SIZE);
        Self {
            file,
            buffer: Arc::new(Mutex::new(buffer)),
            path,
        }
    }

    #[inline(always)]
    pub fn new_temp(prefix: impl AsRef<OsStr>) -> Self {
        let mut options = OpenOptions::new();
        options
            .read(true)
            .write(true)
            .create(true)
            .custom_flags(libc::O_DIRECT);
        let (file, path) = Builder::new()
            .prefix(&prefix)
            .suffix(".scribe")
            .keep(true)
            .make(|p| options.open(p))
            .expect("failed to open file")
            .keep()
            .expect("failed to keep file");
        let buffer: AVec = AVec::with_capacity(4096, BUFFER_SIZE);
        Self {
            file,
            buffer: Arc::new(Mutex::new(buffer)),
            path,
        }
    }

    #[inline(always)]
    pub fn reopen(&self) -> io::Result<Self> {
        Ok(Self::create_read_write(self.path.clone()))
    }

    #[inline(always)]
    pub fn reopen_read(&self) -> io::Result<Self> {
        Ok(Self::open_read_only(self.path.clone()))
    }

    #[inline(always)]
    pub fn remove(self) -> io::Result<()> {
        std::fs::remove_file(&self.path)
    }

    #[inline(always)]
    pub fn try_clone(&self) -> io::Result<Self> {
        let file = self.file.try_clone()?;
        Ok(Self {
            file,
            buffer: self.buffer.clone(),
            path: self.path.clone(),
        })
    }
}

impl Read for InnerFile {
    #[inline(always)]
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        (&*self).read(buf)
    }

    fn read_exact(&mut self, buf: &mut [u8]) -> io::Result<()> {
        (&*self).read_exact(buf)
    }

    fn read_to_end(&mut self, buf: &mut Vec<u8>) -> io::Result<usize> {
        (&*self).read_to_end(buf)
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
        let mut self_buffer = self.buffer.lock().unwrap();
        self_buffer.clear();
        self_buffer.extend_from_slice(&buf);
        assert_eq!(self_buffer.len(), buf.len());
        assert_eq!(self_buffer.len() % 4096, 0);
        let e = (&self.file).read(&mut self_buffer)?;
        buf.copy_from_slice(&self_buffer);
        Ok(e)
    }

    fn read_exact(&mut self, buf: &mut [u8]) -> io::Result<()> {
        let mut self_buffer = self.buffer.lock().unwrap();
        self_buffer.clear();
        self_buffer.extend_from_slice(&buf);
        assert_eq!(self_buffer.len(), buf.len());
        assert_eq!(self_buffer.len() % 4096, 0);
        (&self.file).read_exact(&mut self_buffer)?;
        buf.copy_from_slice(&self_buffer);
        Ok(())
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
    fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        (&*self).write_all(buf)
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
        assert_eq!(buf.len() % 4096, 0);
        let mut self_buffer = self.buffer.lock().unwrap();
        self_buffer.clear();
        self_buffer.extend_from_slice(&buf);
        (&self.file).write(&self_buffer)
    }

    #[inline(always)]
    fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        assert_eq!(buf.len() % 4096, 0);
        let mut self_buffer = self.buffer.lock().unwrap();
        self_buffer.clear();
        self_buffer.extend_from_slice(&buf);
        (&self.file).write_all(&self_buffer)
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
    fn seek(&mut self, _: io::SeekFrom) -> io::Result<u64> {
        unimplemented!()
    }

    #[inline(always)]
    fn rewind(&mut self) -> io::Result<()> {
        (&self.file).seek(io::SeekFrom::Start(0)).map(|_| ())
    }
}

impl io::Seek for InnerFile {
    #[inline(always)]
    fn seek(&mut self, _: io::SeekFrom) -> io::Result<u64> {
        unimplemented!()
    }

    #[inline(always)]
    fn rewind(&mut self) -> io::Result<()> {
        (&self.file).seek(io::SeekFrom::Start(0)).map(|_| ())
    }
}
