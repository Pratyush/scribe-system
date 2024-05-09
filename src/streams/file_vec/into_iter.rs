use crate::streams::serialize::{DeserializeRaw, SerializeRaw};
use rayon::{iter::MinLen, prelude::*, vec::IntoIter as VecIntoIter};
use std::{fs::File, io::BufReader, path::PathBuf};

use crate::streams::{iterator::BatchedIterator, BUFFER_SIZE};

pub enum IntoIter<T: SerializeRaw + DeserializeRaw + 'static> {
    File {
        file: BufReader<File>,
        path: PathBuf,
        work_buffer: Vec<u8>,
    },
    Buffer {
        buffer: Vec<T>,
    },
}

impl<T: SerializeRaw + DeserializeRaw> IntoIter<T> {
    pub fn new_file(file: File, path: PathBuf) -> Self {
        let size = core::mem::size_of::<T>();
        let file = BufReader::with_capacity(size * BUFFER_SIZE, file);
        Self::File {
            file,
            path,
            work_buffer: Vec::with_capacity(size * BUFFER_SIZE),
        }
    }

    pub fn new_buffer(buffer: Vec<T>) -> Self {
        Self::Buffer { buffer }
    }
}

impl<T: 'static + SerializeRaw + DeserializeRaw + Send + Sync + Copy> BatchedIterator
    for IntoIter<T>
{
    type Item = T;
    type Batch = MinLen<VecIntoIter<T>>;

    fn next_batch(&mut self) -> Option<Self::Batch> {
        match self {
            IntoIter::File {
                file, work_buffer, ..
            } => {
                let mut result = Vec::with_capacity(BUFFER_SIZE);
                T::deserialize_raw_batch(&mut result, work_buffer, BUFFER_SIZE, file).ok()?;

                if result.is_empty() {
                    None
                } else {
                    Some(result.into_par_iter().with_min_len(1 << 7))
                }
            }
            IntoIter::Buffer { buffer } => {
                if buffer.is_empty() {
                    return None;
                } else {
                    Some(
                        std::mem::replace(buffer, Vec::new())
                            .into_par_iter()
                            .with_min_len(1 << 7),
                    )
                }
            }
        }
    }
}

impl<T: SerializeRaw + DeserializeRaw> Drop for IntoIter<T> {
    fn drop(&mut self) {
        match self {
            Self::File { path, .. } => match std::fs::remove_file(&path) {
                Ok(_) => (),
                Err(e) => eprintln!("Failed to remove file at path {path:?}: {e:?}"),
            },
            Self::Buffer { .. } => (),
        }
    }
}
