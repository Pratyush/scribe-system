use std::marker::PhantomData;

use super::BatchedIterator;
use rayon::prelude::*;

pub struct BatchedMap<I, U, BatchU, F> 
where
    I: BatchedIterator, 
    U: Send + Sync, 
    BatchU: ParallelIterator<Item = U>, 
    F: FnMut(I::Batch) -> BatchU + Send + Sync
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
    F: FnMut(I::Batch) -> BatchU + Send + Sync,
{
    pub fn new(
        iter: I,
        f: F,
    ) -> Self {
        Self {
            iter,
            f,
            _u: PhantomData,
            _batch_u: PhantomData,
        }
    }
}

impl<I, U, BatchU, F> BatchedIterator for BatchedMap<I, U, BatchU, F>
where
    I: BatchedIterator,
    U: Send + Sync,
    BatchU: ParallelIterator<Item = U>, 
    F: FnMut(I::Batch) -> BatchU + Send + Sync,
{
    type Item = U;
    type Batch = BatchU;

    #[inline]
    fn next_batch(&mut self) -> Option<Self::Batch> {
        self.iter.next_batch().map(|i| (self.f)(i))
    }

    fn len(&self) -> Option<usize> {
        self.iter.len()
    }
}
