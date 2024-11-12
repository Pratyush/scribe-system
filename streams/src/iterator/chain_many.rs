use rayon::prelude::*;

use super::BatchedIterator;

pub struct ChainMany<I> {
    iters: Vec<I>,
}

impl<I> ChainMany<I> {
    pub fn new(mut iters: Vec<I>) -> Self {
        iters.reverse();
        Self { iters }
    }
}

impl<I> BatchedIterator for ChainMany<I>
where
    I: BatchedIterator,
    I::Item: Clone,
    I::Batch: IndexedParallelIterator,
{
    type Item = I::Item;
    type Batch = I::Batch;

    #[inline]
    fn next_batch(&mut self) -> Option<Self::Batch> {
        let batch = self.iters.last_mut()?.next_batch();
        if let Some(batch) = batch {
            Some(batch)
        } else {
            drop(batch);
            // The iterator is empty, so we remove it from the list of iterators.
            // If there are no more iterators, we return None.
            self.iters.pop()?;
            self.next_batch()
        }
    }

    fn len(&self) -> Option<usize> {
        self.iters.iter().map(|iter| iter.len()).sum()
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        iterator::{chain_many, BatchAdapter, BatchedIterator},
        BUFFER_SIZE,
    };

    #[test]
    fn test_chain_many() {
        let size = BUFFER_SIZE;
        let iter1 = BatchAdapter::from(0..size);
        let iter2 = BatchAdapter::from(size..(2 * size));

        let chained = chain_many([iter1, iter2]);
        assert_eq!(chained.to_vec(), (0..(2 * size)).collect::<Vec<_>>());
    }
}
