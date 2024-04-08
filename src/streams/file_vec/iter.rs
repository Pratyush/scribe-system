use std::{fs::File, io::BufReader, marker::PhantomData};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use rayon::iter::IntoParallelIterator;

use crate::streams::{iterator::BatchedIterator, BUFFER_SIZE};

pub struct Iter<'a, T: CanonicalSerialize + CanonicalDeserialize + 'static> {
    file: BufReader<File>,
    buffer: Vec<T>,
    lifetime: PhantomData<&'a T>,
}

impl<'a, T: CanonicalSerialize + CanonicalDeserialize> Iter<'a, T> {
    pub fn new(file: File) -> Self {
        let file = BufReader::new(file);
        let buffer = Vec::with_capacity(BUFFER_SIZE);
        Self { file, buffer, lifetime: PhantomData }
    }
}

impl<'a, T: 'static + CanonicalSerialize + CanonicalDeserialize + Send + Sync + Copy> BatchedIterator for Iter<'a, T> 
where 
    Self: 'a
{
    type Item = T;
    type Batch = rayon::vec::IntoIter<T>;
    
    fn next_batch(&mut self) -> Option<Self::Batch> {
        self.buffer.clear();
        for _ in 0..BUFFER_SIZE {
            match T::deserialize_uncompressed_unchecked(&mut self.file) {
                Ok(val) => self.buffer.push(val),
                Err(_) => break,
            }
        }
        let buffer = self.buffer.clone();
        if self.buffer.is_empty() {
            None
        } else {
            Some(buffer.into_par_iter())
        }
    }
}