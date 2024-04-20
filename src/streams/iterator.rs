use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use rayon::prelude::*;
use std::iter::Sum;

use super::file_vec::FileVec;

const BUFFER_SIZE: usize = 1 << 16;

pub mod array_chunks;
pub mod chain_many;
pub mod flat_map;
pub mod map;
pub mod zip;
pub mod zip_many;

pub use array_chunks::ArrayChunks;
pub use chain_many::ChainMany;
pub use flat_map::FlatMap;
pub use map::Map;
pub use zip::Zip;
pub use zip_many::ZipMany;

pub trait BatchedIterator: Sized {
    type Item: Send + Sync;
    type Batch: ParallelIterator<Item = Self::Item>;
    fn next_batch(&mut self) -> Option<Self::Batch>;

    fn map<U: Send + Sync, F>(self, f: F) -> Map<Self, U, F>
    where
        F: Fn(Self::Item) -> U + Send + Sync + Clone,
    {
        Map { iter: self, f }
    }

    fn for_each(mut self, f: impl Fn(Self::Item) + Send + Sync + Clone) {
        while let Some(batch) = self.next_batch() {
            batch.for_each(f.clone());
        }
    }

    fn batched_for_each(mut self, f: impl Fn(Self::Batch) + Send + Sync + Clone) {
        while let Some(batch) = self.next_batch() {
            f(batch)
        }
    }

    fn zip<I2: BatchedIterator>(self, other: I2) -> Zip<Self, I2> {
        Zip {
            iter1: self,
            iter2: other,
        }
    }

    fn flat_map<U, F>(self, f: F) -> FlatMap<Self, U, F>
    where
        U: IntoParallelIterator + Send + Sync,
        F: Fn(Self::Item) -> U + Send + Sync,
    {
        FlatMap { iter: self, f }
    }

    fn array_chunks<const N: usize>(self) -> ArrayChunks<Self, N>
    where
        Self::Batch: IndexedParallelIterator,
        Self::Item: Copy,
    {
        ArrayChunks::new(self)
    }

    fn fold<T, ID, F, F2>(mut self, identity: ID, fold_op: F, reduce_op: F2) -> T
    where
        F: Fn(T, Self::Item) -> T + Sync + Send,
        F2: Fn(T, T) -> T + Sync + Send,
        ID: Fn() -> T + Sync + Send,
        T: Send + Clone,
    {
        let mut acc = identity();
        while let Some(batch) = self.next_batch() {
            acc = batch
                .fold_with(acc, |a, b| fold_op(a, b))
                .reduce(|| identity(), |a, b| reduce_op(a, b));
        }
        acc
    }

    fn batched_fold<T, B, ID, F, F2>(mut self, batch_op: B, identity: ID, fold_op: F, reduce_op: F2) -> T
    where
        B: Fn(Self::Batch) -> T + Sync + Send,
        F: Fn(T, T) -> T + Sync + Send,
        F2: Fn(T, T) -> T + Sync + Send,
        ID: Fn() -> T + Sync + Send,
        T: Send + Clone,
    {
        let mut processed_batches: Vec<T> = Vec::new();
        while let Some(batch) = self.next_batch() {
            processed_batches.push(batch_op(batch));
        }
        let mut acc = identity();
        acc = processed_batches.into_par_iter().fold_with(acc, |a, b| fold_op(a, b))
        .reduce(|| identity(), |a, b| reduce_op(a, b));
        acc
    }

    fn to_file_vec(self) -> FileVec<Self::Item>
    where
        Self::Item: CanonicalSerialize + CanonicalDeserialize,
    {
        FileVec::from_batched_iter(self)
    }

    fn to_file_vec_tuple<T>(
        self,
    ) -> (FileVec<T>, FileVec<T>)
    where
        Self: IntoBatchedIterator<Item = (T, T)>,
        T: CanonicalSerialize + CanonicalDeserialize + Send + Sync,
    {
        FileVec::from_batched_iter_tuple(self)
    }

    /// Helper function to convert the iterator into a vector.
    fn to_vec(mut self) -> Vec<Self::Item>
    where
        Self::Batch: IndexedParallelIterator,
    {
        let mut vec = Vec::new();
        while let Some(batch) = self.next_batch() {
            vec.par_extend(batch);
        }
        vec
    }

    fn sum<S>(mut self) -> S
    where
        S: Sum<Self::Item> + Sum<S> + Send + Sync,
    {
        let mut intermediate_sums = Vec::new();
        while let Some(batch) = self.next_batch() {
            let sum: S = batch.sum();
            intermediate_sums.push(sum);
        }
        intermediate_sums.into_iter().sum()
    }
}

pub fn zip_many<I>(iters: impl IntoIterator<Item = I>) -> ZipMany<I>
where
    I: BatchedIterator,
    I::Item: Clone,
{
    ZipMany::new(iters.into_iter().collect())
}

pub fn chain_many<I: BatchedIterator>(iters: impl IntoIterator<Item = I>) -> ChainMany<I> {
    ChainMany::new(iters.into_iter().collect())
}

pub struct BatchAdapter<I: Iterator> {
    iter: I,
}

impl<I: Iterator> From<I> for BatchAdapter<I> {
    fn from(iter: I) -> Self {
        Self { iter }
    }
}

pub fn from_iter<I: IntoIterator>(iter: I) -> BatchAdapter<I::IntoIter> {
    BatchAdapter::from(iter.into_iter())
}

impl<I: Iterator> BatchedIterator for BatchAdapter<I>
where
    I::Item: Send + Sync,
{
    type Item = I::Item;
    type Batch = rayon::vec::IntoIter<I::Item>;

    fn next_batch(&mut self) -> Option<Self::Batch> {
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
