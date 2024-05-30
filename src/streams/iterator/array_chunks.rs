use std::fmt::Debug;

use crate::streams::BUFFER_SIZE;
use rayon::prelude::*;

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
    I::Item: Debug,
    [I::Item; N]: Send + Sync,
{
    type Item = [I::Item; N];
    type Batch = rayon::vec::IntoIter<[I::Item; N]>;

    #[inline]
    fn next_batch(&mut self) -> Option<Self::Batch> {
        let batch = self.iter.next_batch()?.collect::<Vec<_>>();
        assert_eq!(batch.len() % N, 0, "Buffer size must be divisible by N");
        assert_eq!(std::mem::align_of::<[I::Item; N]>(), std::mem::align_of::<I::Item>());
        assert_eq!(std::mem::size_of::<[I::Item; N]>(), N * std::mem::size_of::<I::Item>());
        let mut batch = unsafe { std::mem::transmute::<Vec<I::Item>, Vec<[I::Item; N]>>(batch) };
        unsafe {
            batch.set_len(batch.len() / N);
        }
        Some(batch.into_par_iter())
    }
}

#[cfg(test)]
mod tests {
    use super::BatchedIterator;
    use crate::streams::iterator::BatchAdapter;
    use rayon::iter::IndexedParallelIterator;

    #[test]
    fn test_array_chunks_result_is_indexed_parallel_iter() {
        let mut iter = BatchAdapter::from(0..100u32).array_chunks::<2>();
        is_indexed_parallel_iter(iter.next_batch().unwrap());
    }

    fn is_indexed_parallel_iter<T: IndexedParallelIterator>(_t: T) {}
}
