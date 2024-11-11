use rayon::iter::IndexedParallelIterator;

use super::BatchedIterator;

pub struct Zip<I1: BatchedIterator, I2: BatchedIterator> {
    pub iter1: I1,
    pub iter2: I2,
}

impl<I1, I2> BatchedIterator for Zip<I1, I2>
where
    I1: BatchedIterator,
    I2: BatchedIterator,
    I1::Batch: IndexedParallelIterator,
    I2::Batch: IndexedParallelIterator,
{
    type Item = (I1::Item, I2::Item);
    type Batch = rayon::iter::Zip<I1::Batch, I2::Batch>;

    #[inline]
    fn next_batch(&mut self) -> Option<Self::Batch> {
        let iter1 = self.iter1.next_batch()?;
        let iter2 = self.iter2.next_batch()?;
        Some(iter1.zip(iter2))
    }
    
    fn len(&self) -> Option<usize> {
        self.iter1.len().and_then(|len1| self.iter2.len().map(|len2| len1.min(len2)))
    }
}
