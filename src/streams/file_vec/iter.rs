use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use rayon::iter::IntoParallelIterator;
use std::{fs::File, io::BufReader, marker::PhantomData};

use crate::streams::{iterator::BatchedIterator, BUFFER_SIZE};

pub enum Iter<'a, T: CanonicalSerialize + CanonicalDeserialize + 'static> {
    File {
        file: BufReader<File>,
        lifetime: PhantomData<&'a T>,
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
    type Batch = rayon::vec::IntoIter<T>;

    fn next_batch(&mut self) -> Option<Self::Batch> {
        match self {
            Iter::File { file, .. } => {
                let mut buffer = Vec::with_capacity(BUFFER_SIZE);
                for _ in 0..BUFFER_SIZE {
                    match T::deserialize_uncompressed_unchecked(&mut *file) {
                        Ok(val) => buffer.push(val),
                        Err(_) => break,
                    }
                }
                if buffer.is_empty() {
                    None
                } else {
                    Some(buffer.into_par_iter())
                }
            }
            Iter::Buffer { buffer } => {
                let buffer = std::mem::replace(buffer, Vec::new());
                Some(buffer.into_par_iter())
            },
        }
        
    }
}
