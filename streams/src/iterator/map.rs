use crate::iterator::BatchedIteratorAssocTypes;

use super::BatchedIterator;
use rayon::prelude::*;

pub struct Map<I: BatchedIterator, U: Send + Sync, F: Fn(I::Item) -> U + Send + Sync + Clone> {
    pub iter: I,
    pub f: F,
}

impl<I, U, F> BatchedIteratorAssocTypes for Map<I, U, F>
where
    I: BatchedIterator,
    U: Send + Sync,
    F: Fn(I::Item) -> U + Send + Sync + Clone,
{
    type Item = U;
    type Batch<'a> = rayon::iter::Map<I::Batch<'a>, F>;
}

impl<I, U, F> BatchedIterator for Map<I, U, F>
where
    I: BatchedIterator,
    U: Send + Sync,
    F: Fn(I::Item) -> U + Send + Sync + Clone,
{
    #[inline]
    fn next_batch<'a>(&'a mut self) -> Option<Self::Batch<'a>> {
        self.iter.next_batch().map(|i| i.map(self.f.clone()))
    }

    fn len(&self) -> Option<usize> {
        self.iter.len()
    }
}
