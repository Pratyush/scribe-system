use rayon::prelude::*;
use smallvec::{SmallVec, smallvec};

use crate::iterator::BatchedIteratorAssocTypes;

use super::{BUFFER_SIZE, BatchedIterator};

pub type SVec<T> = SmallVec<[T; 6]>;

pub struct ZipMany<I: BatchedIterator> {
    iters: Vec<I>,
}

impl<I: BatchedIterator> ZipMany<I> {
    pub fn new(iters: Vec<I>) -> Self {
        let iters_min = iters.iter().map(|i| i.len()).min();
        let iters_max = iters.iter().map(|i| i.len()).max();
        assert_eq!(
            iters_min, iters_max,
            "All iterators must have the same length"
        );
        Self { iters }
    }
}

impl<I> BatchedIteratorAssocTypes for ZipMany<I>
where
    I: BatchedIterator,
    I::Item: Clone + std::fmt::Debug,
    for<'a> I::Batch<'a>: IndexedParallelIterator,
{
    type Item = SVec<I::Item>;
    type Batch<'a> = rayon::vec::IntoIter<SVec<I::Item>>;
}

impl<I> BatchedIterator for ZipMany<I>
where
    I: BatchedIterator,
    I::Item: Clone + std::fmt::Debug,
    for<'a> I::Batch<'a>: IndexedParallelIterator,
{
    fn next_batch<'a>(&'a mut self) -> Option<Self::Batch<'a>> {
        let mut batched = match self.iters.len() {
            0 => unreachable!("ZipMany must have at least one iterator"),
            1 => self.iters[0].next_batch()?.map(|b| smallvec![b]).collect(),
            2 => {
                let (left, right) = self.iters.split_at_mut(1);
                (left[0].next_batch()?, right[0].next_batch()?)
                    .into_par_iter()
                    .map(|(a, b)| smallvec![a, b])
                    .collect()
            },
            3 => {
                let [a, b, c] = self.iters.as_mut_slice() else {
                    panic!("expected slice of length 3");
                };
                (a.next_batch()?, b.next_batch()?, c.next_batch()?)
                    .into_par_iter()
                    .map(|(a, b, c)| smallvec![a, b, c])
                    .collect()
            },

            4 => {
                let [a, b, c, d] = self.iters.as_mut_slice() else {
                    panic!("expected slice of length 4");
                };
                (
                    a.next_batch()?,
                    b.next_batch()?,
                    c.next_batch()?,
                    d.next_batch()?,
                )
                    .into_par_iter()
                    .map(|(a, b, c, d)| smallvec![a, b, c, d])
                    .collect()
            },
            5 => {
                let [a, b, c, d, e] = self.iters.as_mut_slice() else {
                    panic!("expected slice of length 5");
                };
                (
                    a.next_batch()?,
                    b.next_batch()?,
                    c.next_batch()?,
                    d.next_batch()?,
                    e.next_batch()?,
                )
                    .into_par_iter()
                    .map(|(a, b, c, d, e)| smallvec![a, b, c, d, e])
                    .collect()
            },
            6 => {
                let [a, b, c, d, e, f] = self.iters.as_mut_slice() else {
                    panic!("expected slice of length 6");
                };
                (
                    a.next_batch()?,
                    b.next_batch()?,
                    c.next_batch()?,
                    d.next_batch()?,
                    e.next_batch()?,
                    f.next_batch()?,
                )
                    .into_par_iter()
                    .map(|(a, b, c, d, e, f)| smallvec![a, b, c, d, e, f])
                    .collect()
            },
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

    fn len(&self) -> Option<usize> {
        self.iters.iter().map(|iter| iter.len()).min().unwrap()
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        BUFFER_SIZE,
        file_vec::FileVec,
        iterator::{BatchAdapter, BatchedIterator, from_iter, zip_many},
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
