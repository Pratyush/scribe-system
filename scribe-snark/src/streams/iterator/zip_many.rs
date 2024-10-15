use rayon::prelude::*;
use smallvec::{smallvec, SmallVec};

use super::{BatchedIterator, BUFFER_SIZE};

pub type SVec<T> = SmallVec<[T; 6]>;

pub struct ZipMany<I> {
    iters: Vec<I>,
}

impl<I> ZipMany<I> {
    pub fn new(iters: Vec<I>) -> Self {
        Self { iters }
    }
}

impl<I> BatchedIterator for ZipMany<I>
where
    I: BatchedIterator,
    I::Item: Clone + std::fmt::Debug,
    I::Batch: IndexedParallelIterator,
{
    type Item = SVec<I::Item>;
    type Batch = rayon::vec::IntoIter<SVec<I::Item>>;

    fn next_batch(&mut self) -> Option<Self::Batch> {
        let mut batched = match self.iters.len() {
            0 => unreachable!("ZipMany must have at least one iterator"),
            1 => self.iters[0].next_batch()?.map(|b| smallvec![b]).collect(),
            2 => (self.iters[0].next_batch()?, self.iters[1].next_batch()?)
                .into_par_iter()
                .map(|(a, b)| smallvec![a, b])
                .collect(),
            3 => (
                self.iters[0].next_batch()?,
                self.iters[1].next_batch()?,
                self.iters[2].next_batch()?,
            )
                .into_par_iter()
                .map(|(a, b, c)| smallvec![a, b, c])
                .collect(),
            4 => (
                self.iters[0].next_batch()?,
                self.iters[1].next_batch()?,
                self.iters[2].next_batch()?,
                self.iters[3].next_batch()?,
            )
                .into_par_iter()
                .map(|(a, b, c, d)| smallvec![a, b, c, d])
                .collect(),
            5 => (
                self.iters[0].next_batch()?,
                self.iters[1].next_batch()?,
                self.iters[2].next_batch()?,
                self.iters[3].next_batch()?,
                self.iters[4].next_batch()?,
            )
                .into_par_iter()
                .map(|(a, b, c, d, e)| smallvec![a, b, c, d, e])
                .collect(),
            6 => (
                self.iters[0].next_batch()?,
                self.iters[1].next_batch()?,
                self.iters[2].next_batch()?,
                self.iters[3].next_batch()?,
                self.iters[4].next_batch()?,
                self.iters[5].next_batch()?,
            )
                .into_par_iter()
                .map(|(a, b, c, d, e, f)| smallvec![a, b, c, d, e, f])
                .collect(),
            _ => {
                let mut batched = vec![SVec::with_capacity(self.iters.len()); BUFFER_SIZE];
                for iter in &mut self.iters {
                    batched
                        .par_iter_mut()
                        .zip(iter.next_batch()?)
                        .for_each(|(zipped, b)| zipped.push(b));
                }
                batched
            },
        };
        let start_of_empty = batched.partition_point(|x| !x.is_empty());
        batched.truncate(start_of_empty);
        Some(batched.into_par_iter())
    }
}

#[cfg(test)]
mod tests {
    use crate::streams::{
        file_vec::FileVec,
        iterator::{from_iter, zip_many, BatchAdapter, BatchedIterator},
        BUFFER_SIZE,
    };

    #[test]
    fn test_zip_many_trait() {
        let iter1 = BatchAdapter::from(0..100).array_chunks::<2>();
        let iter2 = BatchAdapter::from(100..200).array_chunks::<2>();

        let _zipped = zip_many(vec![iter1, iter2]);
    }

    #[test]
    fn test_zip_many_trait_for_each() {
        let iter1 = from_iter(0..(2 * BUFFER_SIZE) as u32);
        let iter2 = from_iter(100..(2 * BUFFER_SIZE + 100) as u32);

        let zipped = zip_many([iter1, iter2]);
        let mut vec = FileVec::from_iter(0..(2 * BUFFER_SIZE) as u32);
        vec.zipped_for_each(zipped, |a, b| {
            assert_eq!(*a, b[0]);
            assert_eq!(*a + 100u32, b[1]);
        });
    }
}
