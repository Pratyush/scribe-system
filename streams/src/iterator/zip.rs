use rayon::{
    iter::{
        IndexedParallelIterator, IntoParallelIterator, ParallelExtend, ParallelIterator,
        Zip as RayonZip,
    },
    vec::IntoIter,
};

use crate::iterator::BatchedIteratorAssocTypes;

use super::BatchedIterator;

pub struct Zip<I1: BatchedIterator, I2: BatchedIterator> {
    iter1: I1,
    iter2: I2,
}

impl<I1: BatchedIterator, I2: BatchedIterator> Zip<I1, I2> {
    pub fn new(iter1: I1, iter2: I2) -> Self {
        Self { iter1, iter2 }
    }
}

impl<I1, I2> BatchedIteratorAssocTypes for Zip<I1, I2>
where
    I1: BatchedIterator,
    I2: BatchedIterator,
    for<'a> I1::Batch<'a>: IndexedParallelIterator,
    for<'a> I2::Batch<'a>: IndexedParallelIterator,
{
    type Item = (I1::Item, I2::Item);
    type Batch<'a> = RayonZip<IntoIter<I1::Item>, IntoIter<I2::Item>>;
}

impl<I1, I2> BatchedIterator for Zip<I1, I2>
where
    I1: BatchedIterator,
    I2: BatchedIterator,
    for<'a> I1::Batch<'a>: IndexedParallelIterator,
    for<'a> I2::Batch<'a>: IndexedParallelIterator,
{
    fn next_batch<'a>(&'a mut self) -> Option<Self::Batch<'a>> {
        let mut batch1: Vec<_> = self.iter1.next_batch()?.collect();
        let mut batch2: Vec<_> = self.iter2.next_batch()?.collect();

        while batch1.len() != batch2.len() {
            if batch1.len() < batch2.len() {
                batch1.par_extend(self.iter1.next_batch()?);
            } else {
                batch2.par_extend(self.iter2.next_batch()?);
            }
        }

        Some(batch1.into_par_iter().zip(batch2))
    }

    fn len(&self) -> Option<usize> {
        self.iter1
            .len()
            .and_then(|len1| self.iter2.len().map(|len2| len1.min(len2)))
    }
}
