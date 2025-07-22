use std::marker::PhantomData;

use crate::iterator::BatchedIteratorAssocTypes;

use super::BatchedIterator;
use rayon::prelude::*;

pub struct BatchedMap<I, U, BatchU, F>
where
    I: BatchedIterator,
    U: Send + Sync,
    BatchU: ParallelIterator<Item = U>,
    for<'a> F: FnMut(I::Batch<'a>) -> BatchU + Send + Sync,
{
    pub iter: I,
    pub f: F,
    _u: PhantomData<U>,
    _batch_u: PhantomData<BatchU>,
}

impl<I, U, BatchU, F> BatchedMap<I, U, BatchU, F>
where
    I: BatchedIterator,
    U: Send + Sync,
    BatchU: ParallelIterator<Item = U>,
    for<'a> F: FnMut(I::Batch<'a>) -> BatchU + Send + Sync,
{
    pub fn new(iter: I, f: F) -> Self {
        Self {
            iter,
            f,
            _u: PhantomData,
            _batch_u: PhantomData,
        }
    }
}

impl<I, U, BatchU, F> BatchedIteratorAssocTypes for BatchedMap<I, U, BatchU, F>
where
    I: BatchedIterator,
    U: Send + Sync,
    BatchU: ParallelIterator<Item = U>,
    for<'a> F: FnMut(I::Batch<'a>) -> BatchU + Send + Sync,
{
    type Item = U;
    type Batch<'a> = BatchU;
}

impl<I, U, BatchU, F> BatchedIterator for BatchedMap<I, U, BatchU, F>
where
    I: BatchedIterator,
    U: Send + Sync,
    BatchU: ParallelIterator<Item = U>,
    for<'a> F: FnMut(I::Batch<'a>) -> BatchU + Send + Sync,
{
    #[inline]
    fn next_batch<'a>(&'a mut self) -> Option<Self::Batch<'a>> {
        self.iter.next_batch().map(|i| (self.f)(i))
    }

    fn len(&self) -> Option<usize> {
        self.iter.len()
    }
}

#[cfg(test)]
mod tests {
    use ark_bls12_381::Fr;
    use ark_std::{UniformRand, test_rng};

    use crate::{file_vec::FileVec, iterator::BatchedIterator};

    #[test]
    fn test_batched_map_matches_standard_map() {
        let mut rng = test_rng();

        for log_size in 1..=20 {
            let size = 1 << log_size;
            let input: Vec<Fr> = (0..size).map(|_| Fr::rand(&mut rng)).collect();
            let fv = FileVec::from_iter(input.clone());

            let expected: Vec<_> = input.iter().map(|x| *x + Fr::from(3u64)).collect();

            let result = fv
                .iter()
                .batched_map(|batch| {
                    use rayon::prelude::*;
                    batch.map(|x| x + Fr::from(3u64))
                })
                .to_vec();

            assert_eq!(result, expected, "Mismatch for size {size}");
        }
    }
}
