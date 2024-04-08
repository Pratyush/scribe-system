use std::iter::Sum;

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use rayon::iter::IntoParallelIterator;

#[cfg(feature = "parallel")]
use rayon::prelude::*;

use super::file_vec::FileVec;

const BUFFER_SIZE: usize = 1 << 16;

pub trait BatchedIterator: Sized {
    type Item: Send + Sync;
    type Batch: ParallelIterator<Item = Self::Item>;
    fn next_batch(&mut self) -> Option<Self::Batch>;
    
    fn map<U: Send + Sync>(self, f: impl Fn(Self::Item) -> U + Send + Sync + Clone) -> impl BatchedIterator<Item = U> {
        Map { iter: self, f }
    }
    
    fn for_each(mut self, f: impl Fn(Self::Item) + Send + Sync + Clone) {
        while let Some(batch) = self.next_batch() {
            batch.for_each(f.clone());
        }
    }
    
    fn zip<I2: BatchedIterator>(self, other: I2) -> Zip<Self, I2> {
        Zip { iter1: self, iter2: other }
    }
    
    // fn sum(self) -> Self::Item
    // where
    //     Self::Item: Default + std::ops::Add<Output = Self::Item>
    // {
    //     let mut sum = Self::Item::default();
    //     self.for_each(|item| sum = sum + item);
    //     sum
    // }
    
    fn flat_map<U, F>(self, f: F) -> FlatMap<Self, U, F> 
    where
        U: IntoParallelIterator + Send + Sync,
        F: Fn(Self::Item) -> U + Send + Sync,
    {
        FlatMap { iter: self, f }
    }
    
    fn array_chunks<const N: usize>(self) -> impl BatchedIterator<Item = [Self::Item; N]> 
        where 
        Self::Batch: IndexedParallelIterator,
        Self::Item: Copy
    {
        ArrayChunks::new(self)
    }
    
    fn to_file_vec(self) -> FileVec<Self::Item> 
        where Self::Item: CanonicalSerialize + CanonicalDeserialize
    {
        FileVec::from_batched_iter(self)
    }
    
    /// Helper function to convert the iterator into a vector.
    fn to_vec(mut self) -> Vec<Self::Item> 
        where Self::Batch: IndexedParallelIterator
    {
        let mut vec = Vec::new();
        while let Some(batch) = self.next_batch() {
            vec.par_extend(batch);
        }
        vec
    }
    
    fn sum<S>(mut self) -> S
    where
        S: Sum<Self::Item> + Sum<S> + Send + Sync
    {
        let mut intermediate_sums = Vec::new();
        while let Some(batch) = self.next_batch() {
            let sum: S = batch.sum();
            intermediate_sums.push(sum);
        }
        intermediate_sums.into_iter().sum()
    }
}

pub struct Map<I: BatchedIterator, U: Send + Sync, F: Fn(I::Item) -> U + Send + Sync + Clone> {
    iter: I,
    f: F,
}

impl<I, U, F> BatchedIterator for Map<I, U, F> 
where
    I: BatchedIterator, U: Send + Sync, F: Fn(I::Item) -> U + Send + Sync + Clone
{
    type Item = U;
    type Batch = rayon::iter::Map<I::Batch, F>;
    
    fn next_batch(&mut self) -> Option<Self::Batch> {
            self.iter.next_batch().map(|i| i.map(self.f.clone()))
    }
}

pub struct Zip<I1: BatchedIterator, I2: BatchedIterator> {
    iter1: I1,
    iter2: I2,
}

impl<I1, I2> BatchedIterator for Zip<I1, I2> 
where
    I1: BatchedIterator, I2: BatchedIterator,
    I1::Batch: IndexedParallelIterator,
    I2::Batch: IndexedParallelIterator,
{
    type Item = (I1::Item, I2::Item);
    type Batch = rayon::iter::Zip<I1::Batch, I2::Batch>;
    
    fn next_batch(&mut self) -> Option<Self::Batch> {
        let iter1 = self.iter1.next_batch()?;
        let iter2 = self.iter2.next_batch()?;
        Some(iter1.zip(iter2))
    }
}

pub struct FlatMap<I, U, F> 
where
I: BatchedIterator, 
U: IntoParallelIterator + Send + Sync, 
F: Fn(I::Item) -> U,
{
    iter: I,
    f: F,
}

impl<I, U, F> BatchedIterator for FlatMap<I, U, F> 
where
    I: BatchedIterator, 
    U: IntoParallelIterator + Send + Sync, 
    F: Fn(I::Item) -> U + Send + Sync + Clone,
    U::Item: Send + Sync
{
    type Item = U::Item;
    type Batch = rayon::iter::FlatMap<I::Batch, F>;
    
    fn next_batch(&mut self) -> Option<Self::Batch> {
        let iter = self.iter.next_batch()?;
        Some(iter.flat_map(self.f.clone()))
    }
}

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
    I::Batch: IndexedParallelIterator,
    I::Item: Copy,
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

pub struct BatchAdapter<I: Iterator> {
    iter: I,
}

impl<I: Iterator> From<I> for BatchAdapter<I> {
    fn from(iter: I) -> Self {
        Self { iter }
    }
}

impl<I: Iterator> BatchedIterator for BatchAdapter<I> 
where I::Item: Send + Sync
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