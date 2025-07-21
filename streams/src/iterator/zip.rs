use rayon::iter::IndexedParallelIterator;

use crate::iterator::BatchedIteratorAssocTypes;

use super::BatchedIterator;

pub struct Zip<I1: BatchedIterator, I2: BatchedIterator> {
    pub iter1: I1,
    pub iter2: I2,
}

impl<I1, I2> BatchedIteratorAssocTypes for Zip<I1, I2>
where
    I1: BatchedIterator,
    I2: BatchedIterator,
    for<'a> I1::Batch<'a>: IndexedParallelIterator,
    for<'a> I2::Batch<'a>: IndexedParallelIterator,
{
    type Item = (I1::Item, I2::Item);
    type Batch<'a> = rayon::iter::Zip<I1::Batch<'a>, I2::Batch<'a>>;
}

impl<I1, I2> BatchedIterator for Zip<I1, I2>
where
    I1: BatchedIterator,
    I2: BatchedIterator,
    for<'a> I1::Batch<'a>: IndexedParallelIterator,
    for<'a> I2::Batch<'a>: IndexedParallelIterator,
{
    #[inline]
    fn next_batch<'a>(&'a mut self) -> Option<Self::Batch<'a>> {
        let iter1 = self.iter1.next_batch()?;
        let iter2 = self.iter2.next_batch()?;
        Some(iter1.zip(iter2))
    }

    fn len(&self) -> Option<usize> {
        self.iter1
            .len()
            .and_then(|len1| self.iter2.len().map(|len2| len1.min(len2)))
    }
}
