use std::io;
use crossbeam::channel::Receiver;

use crate::{
  BUFFER_SIZE,  serialize::{DeserializeRaw, SerializeRaw},
};

use super::{AVec, avec, backend::InnerFile};



pub struct DoubleBufferedReader<T> {
    file: Option<InnerFile>,
    end_of_file: bool,
    pub(super) t_s: Vec<T>,
    bytes: AVec,
    pending: Option<Receiver<(Vec<T>, InnerFile, AVec)>>,
    first_read: bool,
}

impl<T: SerializeRaw + DeserializeRaw + 'static> DoubleBufferedReader<T> {
    pub(super) fn new(file: InnerFile) -> Self { 
        let mut bytes = avec![];
        bytes.reserve(T::SIZE * BUFFER_SIZE);

        let t_s = Vec::with_capacity(BUFFER_SIZE);

        Self {
            end_of_file: false,
            file: Some(file),
            t_s,
            bytes,
            pending: None,
            first_read: true,
        }

    }
}

impl<T: SerializeRaw + DeserializeRaw + Send + Sync + 'static> DoubleBufferedReader<T> {
    
    pub(super) fn is_first_read(&self) -> bool {
        self.first_read
    }
    
    /// If we have no data buffered yet and haven’t hit EOF, do a *synchronous* read.
    pub(super) fn do_first_read(&mut self) -> Result<(), io::Error>{
        if self.first_read && !self.end_of_file {
            if let Some(f) = self.file.as_mut() {
                T::deserialize_raw_batch(
                    &mut self.t_s,
                    &mut self.bytes,
                    BUFFER_SIZE,
                    f,
                )?;
                if self.t_s.is_empty() {
                    self.end_of_file = true;
                }
            }
            self.first_read = false;
        }
        Ok(())
    }

    /// Gets the batch that was supposed to have been prefetched in the previous iteration.
    pub(super) fn get_prefetched_batch(&mut self) {
        if let Some(rx) = self.pending.take() {
            if let Ok((t_s, file, bytes)) = rx.recv() {
                self.t_s = t_s;
                self.file = Some(file);
                self.bytes = bytes;
                if self.t_s.is_empty() {
                    self.end_of_file = true;
                }
            } else {
                self.end_of_file = true; // background thread failed
            }
        }
    }
    
    /// Starts a background thread to read the next batch of data.
    pub(super) fn start_prefetch(&mut self) {
        if self.end_of_file {
            return;
        }

        let mut file = self.file.take().expect("file already taken");
        let mut t_s = std::mem::take(&mut self.t_s);
        let mut bytes = avec![];
        std::mem::swap(&mut self.bytes, &mut avec![]);

        let (tx, rx) = crossbeam::channel::bounded(1);
        rayon::spawn(move || {
            let _ = T::deserialize_raw_batch(&mut t_s, &mut bytes, BUFFER_SIZE, &mut file);
            let _ = tx.send((t_s, file, bytes));
        });
        self.pending = Some(rx);
    }

    // returns and empties self.front
    pub(super) fn swap_t_buffer(&mut self, buffer: &mut Vec<T>) {
        std::mem::swap(&mut self.t_s, buffer);
    }

    pub(super) fn len(&self) -> Option<usize> { 
        self.file
            .as_ref()
            .map(|f| (f.len() - f.position()) / T::SIZE)
    }
}