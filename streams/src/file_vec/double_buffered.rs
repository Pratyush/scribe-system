use crossbeam::channel::Receiver;
use std::{collections::VecDeque, io::{self, Seek, SeekFrom}};

use crate::{
    BUFFER_SIZE,
    serialize::{DeserializeRaw, SerializeRaw},
};

use super::{AVec, avec, backend::InnerFile};

pub struct DoubleBufferedReader<T> {
    file: InnerFile,
    end_of_file: bool,
    current: Buffers<T>,
    // The following fields are used to manage the background reading
    // and to avoid blocking the main thread while reading from the file.

    // `ready` contains the buffers that have been read and are ready to be processed.
    ready:   VecDeque<Buffers<T>>,
    // `pending` contains the buffers that are being read in the background.
    pending: VecDeque<Receiver<Buffers<T>>>,
    // The next offset in the file to read from.
    // This is used to launch multiple reads.
    next_offset_bytes: u64,
    // Pool of buffers that will be reused for reading.
    pool: Vec<Buffers<T>>,
}

const PREFETCH_DEPTH: usize = 1;

struct Buffers<T> {
    pub(super) t_s: Vec<T>,      // capacity = BUFFER_SIZE
    bytes: AVec,        // capacity = BUFFER_SIZE * T::SIZE
}


impl<T: SerializeRaw + DeserializeRaw> Buffers<T> {
    #[inline]
    fn new() -> Self {
        let mut bytes = avec![];
        bytes.reserve(T::SIZE * BUFFER_SIZE);

        let t_s = Vec::<T>::with_capacity(BUFFER_SIZE);
        Self { t_s, bytes }
    }
    
    #[inline]
    fn empty() -> Self {
        Self {
            t_s: Vec::new(),
            bytes: avec![],
        }
    }
    
    #[inline]
    fn clear(&mut self) {
        self.t_s.clear();
        self.bytes.clear();
    }
}

impl<T: SerializeRaw + DeserializeRaw + 'static> DoubleBufferedReader<T> {
    #[inline]
    pub(super) fn new(file: InnerFile) -> Self {
        let buffer = Buffers::<T>::new();

        Self {
            file,
            end_of_file: false,

            current: buffer,
            pending: Default::default(),
            ready: Default::default(),
            pool: Default::default(),
            next_offset_bytes: 0,
        }
    }
}

impl<T: SerializeRaw + DeserializeRaw + Send + Sync + 'static> DoubleBufferedReader<T> {

    const BYTES_PER_BLOCK: u64 = (BUFFER_SIZE * T::SIZE) as u64;

    #[inline]
    pub(super) fn is_first_read(&self) -> bool {
        self.next_offset_bytes == 0
    }

    /// If we have no data buffered yet and haven’t hit EOF, do a *synchronous* read.
    #[inline]
    pub(super) fn do_first_read(&mut self) -> Result<(), io::Error> {
        if self.is_first_read() && !self.end_of_file {
            T::deserialize_raw_batch(&mut self.current.t_s, &mut self.current.bytes, BUFFER_SIZE, &mut self.file)?;
            if self.current.t_s.is_empty() {
                self.end_of_file = true;
            }
            self.next_offset_bytes = Self::BYTES_PER_BLOCK;
        }
        Ok(())
    }
    
    
    
    pub fn start_prefetches(&mut self) {
        if self.end_of_file { return; }

        while (self.ready.len() + self.pending.len()) < PREFETCH_DEPTH && 
            self.next_offset_bytes < self.file.len() as u64
        {
            let mut file = self.file.reopen_read_by_ref()
                .expect("failed to reopen file for reading");
            
            let offset = self.next_offset_bytes;
            self.next_offset_bytes += Self::BYTES_PER_BLOCK;

            let mut buffer = self.pool.pop().unwrap_or_else(Buffers::new);
            buffer.clear();

            let (tx, rx) = crossbeam::channel::bounded(1);
            self.pending.push_back(rx);
            rayon::spawn(move || {
            // We can move the file head to the next offset.
                if file.seek(SeekFrom::Start(offset)).is_ok() {
                    let _ = T::deserialize_raw_batch(
                        &mut buffer.t_s,
                        &mut buffer.bytes,
                        BUFFER_SIZE,
                        &mut file,
                    );
                }
                // send buffers back whether read succeeded or hit EOF
                let _ = tx.send(buffer);
            });
        }
    }

    /// move finished jobs from `pending` ➜ `ready`
    pub fn harvest(&mut self) {
        let mut harvested_at_least_one = false;
        while let Some(rx) = self.pending.front() && !harvested_at_least_one {
            match rx.try_recv() {
                Ok(bufs) => {
                    self.ready.push_back(bufs);
                    self.pending.pop_front();
                    harvested_at_least_one = true;
                }
                Err(crossbeam::channel::TryRecvError::Empty) => {
                    continue;
                },
                Err(_) => {
                    self.pending.pop_front();
                    self.end_of_file = true;
                }
            }
        }
    }

    // returns and empties self.front
    #[inline]
    pub(super) fn read_output(&mut self, buffer: &mut Vec<T>) -> Option<()> {
        // Move from `ready` to `current`:
        if let Some(mut next) = self.ready.pop_front() {
            // Put `next` into `current`, swapping out the old one.
            std::mem::swap(&mut self.current, &mut next);
            // Put this buffer back into the pool.
            self.pool.push(next);
        }

        if self.current.t_s.is_empty() {
            return None
        } else {
            std::mem::swap(&mut self.current.t_s, buffer);
        }
        Some(())
    }

    #[inline]
    pub(super) fn len(&self) -> Option<usize> {
        Some((self.file.len() - self.next_offset_bytes as usize) / T::SIZE)
    }
}
