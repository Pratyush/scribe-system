#[cfg(target_os = "linux")]
use std::os::unix::fs::OpenOptionsExt;
use std::{
    ffi::OsStr,
    fs::{File, OpenOptions},
    io::{self, IoSlice, Read, Write},
    path::PathBuf,
    sync::{Arc, Mutex},
};
use tempfile::Builder;

pub trait ReadN: std::io::Read {
    /// Reads `n` bytes from the file into `dest`.
    /// This assumes that `dest` is of length `n`.
    /// Clears `dest` before reading.
    ///
    /// If `self` contains `m` bytes, for `m < n`, this function will fill `dest` with `m` bytes and return `Ok(())`.
    fn read_n(&mut self, dest: &mut AVec, n: usize) -> std::io::Result<()> {
        debug_assert_eq!(dest.len(), 0);
        unsafe {
            dest.set_len(0);
        }
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

impl<'a> ReadN for &'a mut InnerFile {
    /// Reads `n` bytes from the file into `dest`.
    /// This assumes that `dest` is of length `n`.
    /// Clears `dest` before reading.
    ///
    /// If `self` contains `m` bytes, for `m < n`, this function will fill `dest` with `m` bytes and return `Ok(())`.
    fn read_n(&mut self, dest: &mut AVec, n: usize) -> std::io::Result<()> {
        debug_assert_eq!(dest.len(), 0);
        unsafe {
            dest.set_len(0);
        }
        dest.reserve(n);
        // Safety: `dest` is empty and has capacity `n`.
        unsafe {
            dest.set_len(n);
        }
        dest.fill(0);
        debug_assert_eq!(dest.len() % PAGE_SIZE, 0);
        let n = (&self.file).read(&mut dest[..])?;
        dest.truncate(n);
        Ok(())
    }
}

impl<'a> ReadN for &'a [u8] {}

#[cfg(any(target_os = "macos", target_os = "ios"))]
pub const PAGE_SIZE: usize = 16384;

#[cfg(not(any(target_os = "macos", target_os = "ios")))]
pub const PAGE_SIZE: usize = 4096;

pub type AVec = aligned_vec::AVec<u8, aligned_vec::ConstAlign<PAGE_SIZE>>;

macro_rules! avec {
    () => {
        $crate::file_vec::AVec::new($crate::file_vec::PAGE_SIZE)
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
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true);
        #[cfg(target_os = "linux")]
        options.custom_flags(libc::O_DIRECT);
        let file = options.open(&path).expect("failed to open file");

        file_set_nocache(&file);

        let buffer: AVec = AVec::new(PAGE_SIZE);
        Self {
            file,
            buffer: Arc::new(Mutex::new(buffer)),
            path,
        }
    }

    #[inline(always)]
    pub fn open_read_only(path: PathBuf) -> Self {
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(target_os = "linux")]
        options.custom_flags(libc::O_DIRECT);

        let file = options.open(&path).expect("failed to open file");

        file_set_nocache(&file);

        let buffer: AVec = AVec::new(PAGE_SIZE);
        Self {
            file,
            buffer: Arc::new(Mutex::new(buffer)),
            path,
        }
    }

    #[doc(hidden)]
    #[inline(always)]
    pub(super) fn empty() -> Self {
        let mut options = OpenOptions::new();
        options.read(true).create(true);
        let (file, path) = Builder::new()
            .suffix(".scribe")
            .tempfile()
            .expect("failed to open file")
            .keep()
            .expect("failed to keep file");
        let buffer: AVec = AVec::new(PAGE_SIZE);
        Self {
            file,
            buffer: Arc::new(Mutex::new(buffer)),
            path,
        }
    }

    #[inline(always)]
    pub fn new_temp(prefix: impl AsRef<OsStr>) -> Self {
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true);
        #[cfg(target_os = "linux")]
        options.custom_flags(libc::O_DIRECT);
        let (file, path) = Builder::new()
            .prefix(&prefix)
            .suffix(".scribe")
            .keep(true)
            .make(|p| options.open(p))
            .expect("failed to open file")
            .keep()
            .expect("failed to keep file");

        file_set_nocache(&file);

        let buffer: AVec = AVec::new(PAGE_SIZE);
        Self {
            file,
            buffer: Arc::new(Mutex::new(buffer)),
            path,
        }
    }

    #[inline(always)]
    pub fn reopen_read_by_ref(&self) -> io::Result<Self> {
        Ok(Self::open_read_only(self.path.clone()))
    }

    /// Re-opens the file in read-only mode.
    /// Replaces the current file with a dummy one that *should* not be used.
    #[inline(always)]
    pub fn reopen_read(mut self) -> io::Result<Self> {
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(target_os = "linux")]
        options.custom_flags(libc::O_DIRECT);

        self.file = options.open(&self.path)?;

        file_set_nocache(&self.file);

        Ok(self)
    }

    #[inline(always)]
    pub fn remove(self) -> io::Result<()> {
        std::fs::remove_file(&self.path)
    }

    pub fn allocate_space(&mut self, len: usize) -> io::Result<()> {
        let len = len as u64;
        use std::os::unix::io::AsRawFd;
        let fd = self.file.as_raw_fd();
        #[cfg(target_os = "linux")]
        {
            use libc::{fallocate, FALLOC_FL_KEEP_SIZE};
            let result = unsafe { fallocate(fd, FALLOC_FL_KEEP_SIZE, 0, len as i64) };
            if result == 0 {
                Ok(())
            } else {
                Err(io::Error::last_os_error())
            }
        }
        #[cfg(any(target_os = "macos", target_os = "ios"))]
        {
            use libc::{c_void, fcntl, off_t, F_ALLOCATEALL, F_ALLOCATECONTIG, F_PREALLOCATE};
            // Prepare the allocation request
            let mut alloc_struct = libc::fstore_t {
                fst_flags: F_ALLOCATECONTIG,
                fst_posmode: libc::F_PEOFPOSMODE,
                fst_offset: 0,
                fst_length: len as off_t,
                fst_bytesalloc: 0,
            };

            // Attempt to allocate contiguous space
            let result = unsafe {
                fcntl(
                    fd,
                    F_PREALLOCATE,
                    &alloc_struct as *const _ as *const c_void,
                )
            };

            if result == -1 {
                alloc_struct.fst_flags = F_ALLOCATEALL;
                let result = unsafe {
                    fcntl(
                        fd,
                        F_PREALLOCATE,
                        &alloc_struct as *const _ as *const c_void,
                    )
                };

                if result == -1 {
                    return Err(io::Error::last_os_error());
                }
            }

            // Set the file size to the desired length
            // self.file.set_len(len as u64)?;
            Ok(())
        }
    }

    #[inline(always)]
    pub fn metadata(&self) -> io::Result<std::fs::Metadata> {
        self.file.metadata()
    }

    #[inline(always)]
    pub fn len(&self) -> usize {
        self.metadata().expect("failed to get metadata").len() as usize
    }

    #[inline(always)]
    pub fn try_clone(&self) -> io::Result<Self> {
        let file = self.file.try_clone()?;

        file_set_nocache(&file);

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
        debug_assert_eq!(self_buffer.len(), buf.len());
        debug_assert_eq!(self_buffer.len() % PAGE_SIZE, 0);
        let e = (&self.file).read(&mut self_buffer)?;
        buf.copy_from_slice(&self_buffer);
        Ok(e)
    }

    fn read_exact(&mut self, buf: &mut [u8]) -> io::Result<()> {
        let mut self_buffer = self.buffer.lock().unwrap();
        self_buffer.clear();
        self_buffer.extend_from_slice(&buf);
        debug_assert_eq!(self_buffer.len(), buf.len());
        debug_assert_eq!(self_buffer.len() % PAGE_SIZE, 0);
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
        debug_assert_eq!(buf.len() % PAGE_SIZE, 0);
        if std::mem::align_of_val(buf) % PAGE_SIZE == 0 {
            // If the buffer is already aligned, we can write directly.
            (&self.file).write(buf)
        } else {
            let mut self_buffer = self.buffer.lock().unwrap();
            self_buffer.clear();
            self_buffer.extend_from_slice(&buf);
            (&self.file).write(&self_buffer)
        }
    }

    #[inline(always)]
    fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        debug_assert_eq!(buf.len() % PAGE_SIZE, 0);
        if std::mem::align_of_val(buf) % PAGE_SIZE == 0 {
            // If the buffer is already aligned, we can write directly.
            (&self.file).write_all(buf)
        } else {
            let mut self_buffer = self.buffer.lock().unwrap();
            self_buffer.clear();
            self_buffer.extend_from_slice(&buf);
            (&self.file).write_all(&self_buffer)
        }
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

fn file_set_nocache(_file: &File) {
    #[cfg(target_os = "macos")]
    {
        use libc::{fcntl, F_NOCACHE};
        use std::os::unix::io::AsRawFd;
        let fd = _file.as_raw_fd();
        let result = unsafe { fcntl(fd, F_NOCACHE, 1) };
        assert_ne!(result, -1);
    }
}
