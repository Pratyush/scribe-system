use crossbeam::channel::Receiver;
use std::io;

use crate::{
    BUFFER_SIZE,
    serialize::{DeserializeRaw, SerializeRaw},
};

use super::{AVec, avec, backend::InnerFile};

pub struct DoubleBufferedReader<T> {
    file: Option<InnerFile>,
    end_of_file: bool,
    buffer: Buffers<T>,
    // The following fields are used to manage the background reading
    // and to avoid blocking the main thread while reading from the file.

    // // `ready` contains the buffers that have been read and are ready to be processed.
    // ready:   VecDeque<Buffers<T>>,
    // // `pending` contains the buffers that are being read in the background.
    // pending: VecDeque<Receiver<Buffers<T>>>,

    // // The next offset in the file to read from.
    // // This is used to launch multiple reads.
    // next_offset_bytes: u64,

    pending: Option<Receiver<(Buffers<T>, InnerFile)>>,
    first_read: bool,
}

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
            end_of_file: false,
            file: Some(file),
            buffer,
            pending: None,
            // next_offset_bytes: 0,
            first_read: true,
        }
    }
}

impl<T: SerializeRaw + DeserializeRaw + Send + Sync + 'static> DoubleBufferedReader<T> {
    #[inline]
    pub(super) fn is_first_read(&self) -> bool {
        self.first_read
    }

    /// If we have no data buffered yet and haven’t hit EOF, do a *synchronous* read.
    #[inline]
    pub(super) fn do_first_read(&mut self) -> Result<(), io::Error> {
        if self.first_read && !self.end_of_file {
            if let Some(f) = self.file.as_mut() {
                T::deserialize_raw_batch(&mut self.buffer.t_s, &mut self.buffer.bytes, BUFFER_SIZE, f)?;
                if self.buffer.t_s.is_empty() {
                    self.end_of_file = true;
                }
            }
            self.first_read = false;
        }
        Ok(())
    }

    /// Gets the batch that was supposed to have been prefetched in the previous iteration.
    #[inline]
    pub(super) fn get_prefetched_batch(&mut self) {
        if let Some(rx) = self.pending.take() {
            if let Ok((buffer, file)) = rx.recv() {
                self.buffer = buffer;
                self.file = Some(file);
                if self.buffer.t_s.is_empty() {
                    self.end_of_file = true;
                }
            } else {
                self.end_of_file = true; // background thread failed
            }
        }
    }

    /// Starts a background thread to read the next batch of data.
    #[inline]
    pub(super) fn start_prefetch(&mut self) {
        if self.end_of_file {
            return;
        }

        let mut file = self.file.take().expect("file already taken");
        let mut buffer = Buffers::<T>::empty();
        std::mem::swap(&mut self.buffer, &mut buffer);

        let (tx, rx) = crossbeam::channel::bounded(1);
        rayon::spawn(move || {
            buffer.clear();
            let _ = T::deserialize_raw_batch(&mut buffer.t_s, &mut buffer.bytes, BUFFER_SIZE, &mut file);
            let _ = tx.send((buffer, file));
        });
        self.pending = Some(rx);
    }

    // returns and empties self.front
    #[inline]
    pub(super) fn swap_t_buffer(&mut self, buffer: &mut Vec<T>) {
        std::mem::swap(&mut self.buffer.t_s, buffer);
    }

    #[inline]
    pub(super) fn len(&self) -> Option<usize> {
        self.file
            .as_ref()
            .map(|f| (f.len() - f.position()) / T::SIZE)
    }
}
