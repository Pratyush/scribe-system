use std::fmt::Debug;

use crate::BUFFER_SIZE;
use rayon::prelude::*;

use super::BatchedIterator;

pub struct ArrayChunks<I: BatchedIterator, const N: usize> {
    iter: I,
    buffer: Vec<I::Item>,
}

impl<I: BatchedIterator, const N: usize> ArrayChunks<I, N> {
    pub fn new(iter: I) -> Self {
        assert!(N > 0, "N must be greater than 0");
        assert!(BUFFER_SIZE % N == 0, "BUFFER_SIZE must be divisible by N");
        assert_eq!(
            std::mem::align_of::<[I::Item; N]>(),
            std::mem::align_of::<I::Item>()
        );
        assert_eq!(
            std::mem::size_of::<[I::Item; N]>(),
            N * std::mem::size_of::<I::Item>()
        );
        let buffer = Vec::with_capacity(BUFFER_SIZE);
        Self { iter, buffer }
    }
}

impl<I, const N: usize> BatchedIterator for ArrayChunks<I, N>
where
    I: BatchedIterator,
    I::Batch: IndexedParallelIterator<Item = I::Item>,
    I::Item: Debug + Copy,
    [I::Item; N]: Send + Sync,
{
    type Item = [I::Item; N];
    type Batch = rayon::vec::IntoIter<[I::Item; N]>;

    #[inline]
    fn next_batch(&mut self) -> Option<Self::Batch> {
        self.iter.next_batch().map(|i| {
            self.buffer.clear();
            self.buffer.par_extend(i);
            assert_eq!(
                self.buffer.len() % N,
                0,
                "Buffer size must be divisible by N"
            );
            let (head, mid, tail) = unsafe { self.buffer.align_to::<[I::Item; N]>() };
            assert!(head.is_empty(), "Buffer must be aligned to [I::Item; N]");
            assert!(tail.is_empty(), "Buffer must be aligned to [I::Item; N]");
            mid.par_iter().copied().with_min_len(1 << 10).collect::<Vec<_>>().into_par_iter()
        })
    }

    fn len(&self) -> Option<usize> {
        self.iter.len().map(|len| len / N)
    }
}

#[cfg(test)]
mod tests {
    use super::BatchedIterator;
    use crate::iterator::BatchAdapter;
    use rayon::iter::IndexedParallelIterator;

    #[test]
    fn test_array_chunks_result_is_indexed_parallel_iter() {
        let mut iter = BatchAdapter::from(0..100u32).array_chunks::<2>();
        is_indexed_parallel_iter(iter.next_batch().unwrap());
    }

    fn is_indexed_parallel_iter<T: IndexedParallelIterator>(_t: T) {}
}
