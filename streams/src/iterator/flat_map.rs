use rayon::prelude::*;

use crate::iterator::BatchedIteratorAssocTypes;

use super::BatchedIterator;

pub struct FlatMap<I, U, F>
where
    I: BatchedIterator,
    U: IntoParallelIterator + Send + Sync,
    F: Fn(I::Item) -> U,
{
    pub iter: I,
    pub f: F,
}

impl<I, U, F> BatchedIteratorAssocTypes for FlatMap<I, U, F>
where
    I: BatchedIterator,
    U: IntoParallelIterator + Send + Sync,
    for<'a> F: Fn(I::Item) -> U + Send + Sync + Clone + 'a,
    U::Item: Send + Sync,
{
    type Item = U::Item;
    type Batch<'a> = rayon::iter::FlatMap<I::Batch<'a>, F>;
}

impl<I, U, F> BatchedIterator for FlatMap<I, U, F>
where
    I: BatchedIterator,
    U: IntoParallelIterator + Send + Sync,
    for<'a> F: Fn(I::Item) -> U + Send + Sync + Clone + 'a,
    U::Item: Send + Sync,
{
    #[inline]
    fn next_batch<'a>(&'a mut self) -> Option<Self::Batch<'a>> {
        let iter = self.iter.next_batch()?;
        Some(iter.flat_map(self.f.clone()))
    }
}
