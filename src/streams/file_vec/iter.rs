use crate::streams::serialize::{DeserializeRaw, SerializeRaw};
use rayon::{iter::MinLen, prelude::*, vec::IntoIter};
use std::{fs::File, io::BufReader, marker::PhantomData};

use crate::streams::{iterator::BatchedIterator, BUFFER_SIZE};

pub enum Iter<'a, T: SerializeRaw + DeserializeRaw + 'static> {
    File {
        file: BufReader<File>,
        lifetime: PhantomData<&'a T>,
        work_buffer: Vec<u8>,
    },
    Buffer {
        buffer: Vec<T>,
    },
}

impl<'a, T: SerializeRaw + DeserializeRaw> Iter<'a, T> {
    pub fn new_file(file: File) -> Self {
        let file = BufReader::with_capacity(BUFFER_SIZE, file);
        Self::File {
            file,
            lifetime: PhantomData,
            work_buffer: Vec::with_capacity(BUFFER_SIZE),
        }
    }

    pub fn new_buffer(buffer: Vec<T>) -> Self {
        Self::Buffer { buffer }
    }
}

impl<'a, T: 'static + SerializeRaw + DeserializeRaw + Send + Sync + Copy>
    BatchedIterator for Iter<'a, T>
{
    type Item = T;
    type Batch = MinLen<IntoIter<T>>;

    fn next_batch(&mut self) -> Option<Self::Batch> {
        match self {
            Iter::File {
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
            Iter::Buffer { buffer } => {
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
