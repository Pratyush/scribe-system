use rayon::{
    iter::{
        Copied, IndexedParallelIterator, IntoParallelRefIterator, ParallelExtend, ParallelIterator,
        Zip,
    },
    slice::Iter,
};

use super::BatchedIterator;
use crate::iterator::BatchedIteratorAssocTypes;

pub struct ZipWithBuf<'a, I1, I2>
where
    I1: BatchedIterator,
    I2: BatchedIterator,
{
    iter1: I1,
    iter2: I2,
    buf1: &'a mut Vec<I1::Item>,
    buf2: &'a mut Vec<I2::Item>,
}

impl<'a, I1, I2> ZipWithBuf<'a, I1, I2>
where
    I1: BatchedIterator,
    I2: BatchedIterator,
{
    pub fn new(
        iter1: I1,
        iter2: I2,
        buf1: &'a mut Vec<I1::Item>,
        buf2: &'a mut Vec<I2::Item>,
    ) -> Self {
        Self {
            iter1,
            iter2,
            buf1,
            buf2,
        }
    }
}

impl<'a, I1, I2> BatchedIteratorAssocTypes for ZipWithBuf<'a, I1, I2>
where
    I1: BatchedIterator,
    I2: BatchedIterator,
    I1::Item: Send + Sync + Copy + 'static,
    I2::Item: Send + Sync + Copy + 'static,
{
    type Item = (I1::Item, I2::Item);
    type Batch<'b> = Zip<Copied<Iter<'b, I1::Item>>, Copied<Iter<'b, I2::Item>>>;
}

impl<'a, I1, I2> BatchedIterator for ZipWithBuf<'a, I1, I2>
where
    I1: BatchedIterator,
    I2: BatchedIterator,
    I1::Item: Send + Sync + Copy + 'static,
    I2::Item: Send + Sync + Copy + 'static,
{
    fn next_batch<'b>(&'b mut self) -> Option<Self::Batch<'b>> {
        self.buf1.clear();
        self.buf2.clear();

        self.buf1.par_extend(self.iter1.next_batch()?);
        self.buf2.par_extend(self.iter2.next_batch()?);

        while self.buf1.len() != self.buf2.len() {
            if self.buf1.len() < self.buf2.len() {
                self.buf1.par_extend(self.iter1.next_batch()?);
            } else {
                self.buf2.par_extend(self.iter2.next_batch()?);
            }
        }

        Some(
            (&*self.buf1)
                .par_iter()
                .copied()
                .zip((&*self.buf2).par_iter().copied()),
        )
    }

    fn len(&self) -> Option<usize> {
        self.iter1
            .len()
            .zip(self.iter2.len())
            .map(|(a, b)| a.min(b))
    }
}
