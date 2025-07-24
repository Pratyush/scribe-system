#[cfg(target_os = "linux")]
use std::os::unix::fs::OpenOptionsExt;
use std::{
    ffi::OsStr,
    fs::{File, OpenOptions},
    io::{self, Read, Seek, Write},
    path::PathBuf,
};
use tempfile::Builder;

pub trait ReadN {
    /// Reads `n` bytes from the file into `dest`.
    /// This assumes that `dest` is of length `n`.
    /// Clears `dest` before reading.
    ///
    /// If `self` contains `m` bytes, for `m < n`, this function will fill `dest` with `m` bytes and return `Ok(())`.
    fn read_n(&mut self, dest: &mut AVec, n: usize) -> std::io::Result<()>;
}

pub trait WriteAligned {
    /// Write all elements from `src` into `self.
    fn write_all(&mut self, src: &AVec) -> std::io::Result<()>;

    fn flush(&mut self) -> std::io::Result<()>;
}

impl ReadN for &mut InnerFile {
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
        // dest.fill(0);
        debug_assert_eq!(dest.len() % PAGE_SIZE, 0);
        let n = (&self.file).read(&mut dest[..])?;
        dest.truncate(n);
        Ok(())
    }
}

impl ReadN for &InnerFile {
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

impl ReadN for &[u8] {
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
        // TODO: figure out how to do this without undefined behaviour.
        // dest.fill(0);
        let n = self.read(&mut dest[..n])?;
        dest.truncate(n);
        Ok(())
    }
}

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
        Self { file, path }
    }

    #[inline(always)]
    pub fn open_read_only(path: PathBuf) -> Self {
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(target_os = "linux")]
        options.custom_flags(libc::O_DIRECT);

        let file = options.open(&path).expect("failed to open file");

        file_set_nocache(&file);
        Self { file, path }
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
            .disable_cleanup(true)
            .make(|p| options.open(p))
            .expect("failed to open file")
            .keep()
            .expect("failed to keep file");

        file_set_nocache(&file);

        Self { file, path }
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
            use libc::{FALLOC_FL_KEEP_SIZE, fallocate};
            let result = unsafe { fallocate(fd, FALLOC_FL_KEEP_SIZE, 0, len as i64) };
            if result == 0 {
                Ok(())
            } else {
                Err(io::Error::last_os_error())
            }
        }
        #[cfg(any(target_os = "macos", target_os = "ios"))]
        {
            use libc::{F_ALLOCATEALL, F_ALLOCATECONTIG, F_PREALLOCATE, c_void, fcntl, off_t};
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

    pub fn position(&self) -> usize {
        (&self.file).stream_position().unwrap() as usize
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    #[inline(always)]
    pub fn try_clone(&self) -> io::Result<Self> {
        let file = self.file.try_clone()?;

        file_set_nocache(&file);

        Ok(Self {
            file,
            path: self.path.clone(),
        })
    }
}

impl WriteAligned for InnerFile {
    #[inline(always)]
    fn write_all(&mut self, buf: &AVec) -> io::Result<()> {
        debug_assert_eq!(buf.len() % PAGE_SIZE, 0);
        (&self.file).write_all(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.file.flush()
    }
}

impl WriteAligned for &InnerFile {
    #[inline(always)]
    fn write_all(&mut self, buf: &AVec) -> io::Result<()> {
        debug_assert_eq!(buf.len() % PAGE_SIZE, 0);
        (&self.file).write_all(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        (&self.file).flush()
    }
}

impl WriteAligned for &mut [u8] {
    #[inline(always)]
    fn write_all(&mut self, buf: &AVec) -> io::Result<()> {
        Write::write_all(&mut *self, buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl io::Seek for &InnerFile {
    #[inline(always)]
    fn seek(&mut self, s: io::SeekFrom) -> io::Result<u64> {
        match s {
            io::SeekFrom::Start(pos) => {
                assert_eq!(
                    pos % PAGE_SIZE as u64,
                    0,
                    "Seek position must be a multiple of PAGE_SIZE"
                );
            },
            _ => unimplemented!(),
        }
        (&self.file).seek(s)
    }

    #[inline(always)]
    fn rewind(&mut self) -> io::Result<()> {
        (&self.file).seek(io::SeekFrom::Start(0)).map(|_| ())
    }
}

impl io::Seek for InnerFile {
    #[inline(always)]
    fn seek(&mut self, s: io::SeekFrom) -> io::Result<u64> {
        match s {
            io::SeekFrom::Start(pos) => {
                assert_eq!(
                    pos % PAGE_SIZE as u64,
                    0,
                    "Seek position must be a multiple of PAGE_SIZE"
                );
            },
            _ => unimplemented!(),
        }
        self.file.seek(s)
    }

    #[inline(always)]
    fn rewind(&mut self) -> io::Result<()> {
        (&self.file).seek(io::SeekFrom::Start(0)).map(|_| ())
    }
}

fn file_set_nocache(_file: &File) {
    #[cfg(target_os = "macos")]
    {
        use libc::{F_NOCACHE, fcntl};
        use std::os::unix::io::AsRawFd;
        let fd = _file.as_raw_fd();
        let result = unsafe { fcntl(fd, F_NOCACHE, 1) };
        assert_ne!(result, -1);
    }
}
