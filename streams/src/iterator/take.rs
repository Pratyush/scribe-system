use rayon::iter::IndexedParallelIterator;

use super::BatchedIterator;

pub struct Take<I: BatchedIterator> {
    pub iter: I,
    pub n: usize,
}

impl<I> BatchedIterator for Take<I>
where
    I: BatchedIterator,
    I::Batch: IndexedParallelIterator,
{
    type Item = I::Item;
    type Batch = rayon::iter::Take<I::Batch>;

    #[inline]
    fn next_batch(&mut self) -> Option<Self::Batch> {
        let batch = self.iter.next_batch()?;
        let len = batch.len();
        if self.n > batch.len() {
            self.n -= len;
            Some(batch.take(len))
        } else if self.n > 0 {
            let n = self.n;
            self.n = self.n.saturating_sub(len);
            Some(batch.take(n))
        } else {
            None
        }
    }

    fn len(&self) -> Option<usize> {
        Some(self.n)
    }
}

impl<I: BatchedIterator> Take<I> {
    pub fn new(iter: I, n: usize) -> Self {
        Take { iter, n }
    }
}

#[cfg(test)]
mod test {
    use crate::{file_vec::FileVec, BUFFER_SIZE};

    use super::*;

    #[test]
    fn test_take() {
        let iter = FileVec::from_iter(0..BUFFER_SIZE * 2);
        assert_eq!(iter.iter().take(5).to_vec(), (0..5).collect::<Vec<_>>());
        assert_eq!(
            iter.into_iter().take(BUFFER_SIZE).to_vec(),
            (0..BUFFER_SIZE).collect::<Vec<_>>()
        );
    }
}
