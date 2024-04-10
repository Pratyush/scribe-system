use rayon::prelude::*;
use crate::streams::BUFFER_SIZE;

use super::BatchedIterator;

pub struct ArrayChunks<I: BatchedIterator, const N: usize> {
    iter: I,
}

impl<I: BatchedIterator, const N: usize> ArrayChunks<I, N> {
    pub fn new(iter: I) -> Self {
        assert!(N > 0, "N must be greater than 0");
        assert!(BUFFER_SIZE % N == 0, "BUFFER_SIZE must be divisible by N");
        Self { iter }
    }
}

impl<I, const N: usize> BatchedIterator for ArrayChunks<I, N> 
where
    I: BatchedIterator,
    I::Item: Copy,
    [I::Item; N]: Send + Sync,
{
    type Item = [I::Item; N];
    type Batch = rayon::vec::IntoIter<[I::Item; N]>;
    
    fn next_batch(&mut self) -> Option<Self::Batch> {
        let batch: Vec<_> = self.iter.next_batch()?.collect();
        let batch = batch.par_chunks_exact(N).map(|chunk| {
            <[I::Item; N]>::try_from(chunk).unwrap()
        }).collect::<Vec<_>>();
        Some(batch.into_par_iter())
    }
}

#[cfg(test)]
mod tests {
    use crate::streams::iterator::BatchAdapter;
    use rayon::iter::IndexedParallelIterator;
    use super::BatchedIterator;

    #[test]
    fn test_array_chunks_result_is_indexed_parallel_iter() {
        let mut iter = BatchAdapter::from(0..100u32).array_chunks::<2>();
        is_indexed_parallel_iter(iter.next_batch().unwrap());
    }
    
    fn is_indexed_parallel_iter<T: IndexedParallelIterator>(_t: T) {}
}
