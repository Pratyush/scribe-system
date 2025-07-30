use std::fmt::Debug;

use crate::{BUFFER_SIZE, iterator::BatchedIteratorAssocTypes};
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

impl<I, const N: usize> BatchedIteratorAssocTypes for ArrayChunks<I, N>
where
    I: BatchedIterator,
    for<'a> I::Batch<'a>: IndexedParallelIterator<Item = I::Item>,
    I::Item: Debug + Copy,
    [I::Item; N]: Send + Sync,
{
    type Item = [I::Item; N];
    type Batch<'a> = rayon::vec::IntoIter<[I::Item; N]>;
}

impl<I, const N: usize> BatchedIterator for ArrayChunks<I, N>
where
    I: BatchedIterator,
    for<'a> I::Batch<'a>: IndexedParallelIterator<Item = I::Item>,
    I::Item: Debug + Copy,
    [I::Item; N]: Send + Sync,
{
    #[inline]
    fn next_batch<'a>(&'a mut self) -> Option<Self::Batch<'a>> {
        self.iter.next_batch().map(|i| {
            self.buffer.clear();
            i.collect_into_vec(&mut self.buffer);
            println!("Buffer length: {}", self.buffer.len());
            assert_eq!(
                self.buffer.len() % N,
                0,
                "Buffer size ({}) must be divisible by N = {N}",
                self.buffer.len()
            );
            let (head, mid, tail) = unsafe { self.buffer.align_to::<[I::Item; N]>() };
            assert!(head.is_empty(), "Buffer must be aligned to [I::Item; N]");
            assert!(tail.is_empty(), "Buffer must be aligned to [I::Item; N]");
            mid.par_iter()
                .copied()
                .with_min_len(1 << 10)
                .collect::<Vec<_>>()
                .into_par_iter()
        })
    }

    fn len(&self) -> Option<usize> {
        dbg!(self.iter.len()).map(|len| len / N)
    }
}

#[cfg(test)]
mod tests {
    use super::BatchedIterator;
    use crate::{file_vec::FileVec, iterator::BatchAdapter};
    use rayon::iter::IndexedParallelIterator;

    #[test]
    fn test_array_chunks_result_is_indexed_parallel_iter() {
        let mut iter = BatchAdapter::from(0..100u32).array_chunks::<2>();
        is_indexed_parallel_iter(iter.next_batch().unwrap());
    }

    fn is_indexed_parallel_iter<T: IndexedParallelIterator>(_t: T) {}

    #[test]
    fn test_with_zip() {
        for log_size in 1..=20 {
            let size = 1 << log_size;
            let input: Vec<u32> = (0..size).collect();
            let half_input: Vec<u32> = (0..size / 2).collect();
            let fv = FileVec::from_iter(input.clone());
            let half_fv = FileVec::from_iter(half_input.clone());

            let expected = input
                .chunks(2)
                .zip(half_input)
                .map(|(a, b)| (a[0], a[1], b))
                .collect::<Vec<_>>();
            let actual = fv
                .iter()
                .array_chunks::<2>()
                .zip(half_fv.iter())
                .map(|(a, b)| (a[0], a[1], b))
                .to_vec();
            assert_eq!(actual.len(), expected.len(), "Length mismatch");
            for (i, (actual, expected)) in actual.into_iter().zip(expected).enumerate() {
                assert_eq!(actual, expected, "Mismatch at index {i}");
            }
        }
    }
}
