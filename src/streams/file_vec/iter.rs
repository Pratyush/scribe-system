use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use rayon::{iter::MinLen, prelude::*, vec::IntoIter};
use std::{fs::File, io::BufReader, marker::PhantomData};

use crate::streams::{iterator::BatchedIterator, BUFFER_SIZE};

use super::utils::par_deserialize;

pub enum Iter<'a, T: CanonicalSerialize + CanonicalDeserialize + 'static> {
    File {
        file: BufReader<File>,
        lifetime: PhantomData<&'a T>,
        work_buffer: Vec<u8>,
    },
    Buffer {
        buffer: Vec<T>,
    },
}

impl<'a, T: CanonicalSerialize + CanonicalDeserialize> Iter<'a, T> {
    pub fn new_file(file: File) -> Self {
        let file = BufReader::new(file);
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

impl<'a, T: 'static + CanonicalSerialize + CanonicalDeserialize + Send + Sync + Copy>
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
                par_deserialize(file, work_buffer, &mut result)?;

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
