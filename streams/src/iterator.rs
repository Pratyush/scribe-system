use super::BUFFER_SIZE;
use crate::{
    iterator::batched_map::BatchedMap,
    serialize::{DeserializeRaw, SerializeRaw},
};
use rayon::prelude::*;
use std::iter::Sum;

use super::file_vec::FileVec;

pub mod array_chunks;
pub mod batched_map;
pub mod chain_many;
pub mod flat_map;
pub mod from_fn;
pub mod map;
pub mod repeat;
pub mod take;
pub mod zip;
pub mod zip_many;
pub mod zip_with_buf;

pub use array_chunks::ArrayChunks;
pub use chain_many::ChainMany;
pub use flat_map::FlatMap;
pub use from_fn::FromFn;
pub use map::Map;
pub use repeat::Repeat;
pub use take::Take;
pub use zip::Zip;
pub use zip_many::ZipMany;
pub use zip_with_buf::ZipWithBuf;

pub trait BatchedIteratorAssocTypes: Sized {
    type Item: Send + Sync;
    type Batch<'a>: ParallelIterator<Item = Self::Item>;
}
pub trait BatchedIterator: BatchedIteratorAssocTypes {
    fn next_batch<'a>(&'a mut self) -> Option<Self::Batch<'a>>;

    fn len(&self) -> Option<usize> {
        None
    }

    #[inline(always)]
    fn map<U: Send + Sync, F>(self, f: F) -> Map<Self, U, F>
    where
        F: Fn(Self::Item) -> U + Send + Sync + Clone,
    {
        Map { iter: self, f }
    }

    #[inline(always)]
    fn batched_map<U, BatchU, F>(self, f: F) -> BatchedMap<Self, U, BatchU, F>
    where
        U: Send + Sync,
        for<'a> F: FnMut(Self::Batch<'a>) -> BatchU + Send + Sync,
        BatchU: ParallelIterator<Item = U>,
    {
        BatchedMap::new(self, f)
    }

    #[inline(always)]
    fn for_each(mut self, f: impl Fn(Self::Item) + Send + Sync + Clone) {
        while let Some(batch) = self.next_batch() {
            batch.for_each(f.clone());
        }
    }

    #[inline(always)]
    fn zip<I2: BatchedIterator>(self, other: I2) -> Zip<Self, I2> {
        Zip::new(self, other)
    }

    fn zip_with_bufs<'a, I2: BatchedIterator>(
        self,
        other: I2,
        buf1: &'a mut Vec<Self::Item>,
        buf2: &'a mut Vec<I2::Item>,
    ) -> ZipWithBuf<'a, Self, I2> {
        ZipWithBuf::new(self, other, buf1, buf2)
    }

    #[inline(always)]
    fn flat_map<U, F>(self, f: F) -> FlatMap<Self, U, F>
    where
        U: IntoParallelIterator + Send + Sync,
        F: Fn(Self::Item) -> U + Send + Sync,
    {
        FlatMap { iter: self, f }
    }

    #[inline(always)]
    fn array_chunks<const N: usize>(self) -> ArrayChunks<Self, N>
    where
        for<'a> Self::Batch<'a>: IndexedParallelIterator,
    {
        ArrayChunks::new(self)
    }

    #[inline(always)]
    fn take(self, n: usize) -> Take<Self> {
        Take { iter: self, n }
    }

    #[inline(always)]
    fn fold<T, ID, F, F2>(mut self, identity: ID, fold_op: F, reduce_op: F2) -> T
    where
        F: Fn(T, Self::Item) -> T + Sync + Send,
        F2: Fn(T, T) -> T + Sync + Send,
        ID: Fn() -> T + Sync + Send,
        T: Send + Clone + Sync,
    {
        let mut acc = identity();
        let mut res = Vec::with_capacity(BUFFER_SIZE);
        while let Some(batch) = self.next_batch() {
            res.clear();
            res.par_extend(batch.fold_with(identity(), &fold_op));
            res.push(acc);
            acc = res.par_drain(..res.len()).reduce(&identity, &reduce_op);
        }
        acc
    }

    #[inline(always)]
    fn to_file_vec(self) -> FileVec<Self::Item>
    where
        Self::Item: SerializeRaw + DeserializeRaw + std::fmt::Debug,
    {
        FileVec::from_batched_iter(self)
    }

    #[inline(always)]
    fn unzip<A, B>(self) -> (FileVec<A>, FileVec<B>)
    where
        Self: BatchedIterator<Item = (A, B)>,
        A: SerializeRaw + DeserializeRaw + Send + Sync,
        B: SerializeRaw + DeserializeRaw + Send + Sync,
    {
        FileVec::<(A, B)>::unzip_helper(self)
    }

    /// Helper function to convert the iterator into a vector.
    #[inline(always)]
    fn to_vec(mut self) -> Vec<Self::Item>
    where
        for<'a> Self::Batch<'a>: IndexedParallelIterator,
    {
        let mut vec = Vec::new();
        while let Some(batch) = self.next_batch() {
            vec.par_extend(batch);
        }
        vec
    }

    #[inline(always)]
    fn sum<S>(mut self) -> S
    where
        S: Sum<Self::Item> + Sum<S> + Send + Sync,
    {
        let mut intermediate_sums = Vec::new();
        while let Some(batch) = self.next_batch() {
            let sum: S = batch.sum();
            intermediate_sums.push(sum);
        }
        intermediate_sums.into_par_iter().sum()
    }
}

#[inline(always)]
pub fn zip_many<I>(iters: impl IntoIterator<Item = I>) -> ZipMany<I>
where
    I: BatchedIterator,
    I::Item: Clone,
{
    ZipMany::new(iters.into_iter().collect())
}

#[inline(always)]
pub fn chain_many<I: BatchedIterator>(iters: impl IntoIterator<Item = I>) -> ChainMany<I> {
    ChainMany::new(iters.into_iter().collect())
}

#[inline(always)]
pub fn repeat<T: Send + Sync + Copy>(iter: T, count: usize) -> Repeat<T> {
    Repeat { iter, count }
}

#[inline(always)]
pub fn from_fn<T: Send + Sync, F>(func: F, max: usize) -> FromFn<F>
where
    F: Fn(usize) -> Option<T> + Send + Sync + Copy,
{
    FromFn::new(func, max)
}

pub struct BatchAdapter<I: Iterator> {
    iter: I,
}

impl<I: Iterator> From<I> for BatchAdapter<I> {
    #[inline(always)]
    fn from(iter: I) -> Self {
        Self { iter }
    }
}

#[inline(always)]
pub fn from_iter<I: IntoIterator>(iter: I) -> BatchAdapter<I::IntoIter> {
    BatchAdapter::from(iter.into_iter())
}

impl<I: Iterator<Item: Send + Sync>> BatchedIteratorAssocTypes for BatchAdapter<I> {
    type Item = I::Item;
    type Batch<'a> = rayon::vec::IntoIter<I::Item>;
}

impl<I: Iterator<Item: Send + Sync>> BatchedIterator for BatchAdapter<I> {
    #[inline(always)]
    fn next_batch<'a>(&'a mut self) -> Option<Self::Batch<'a>> {
        let batch: Vec<_> = self.iter.by_ref().take(BUFFER_SIZE).collect();
        if batch.is_empty() {
            None
        } else {
            Some(batch.into_par_iter())
        }
    }
}

pub trait IntoBatchedIterator {
    type Item: Send + Sync;
    type Iter: BatchedIterator<Item = Self::Item>;
    fn into_batched_iter(self) -> Self::Iter;
}

impl<I: BatchedIterator> IntoBatchedIterator for I {
    type Item = I::Item;
    type Iter = I;
    fn into_batched_iter(self) -> Self::Iter {
        self
    }
}
