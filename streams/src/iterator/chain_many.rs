use rayon::prelude::*;

use crate::iterator::BatchedIteratorAssocTypes;

use super::BatchedIterator;

pub struct ChainMany<I> {
    iters: Vec<I>,
    cur_index: usize,
}

impl<I> ChainMany<I> {
    pub fn new(iters: Vec<I>) -> Self {
        Self {
            iters,
            cur_index: 0,
        }
    }
}

impl<I> BatchedIteratorAssocTypes for ChainMany<I>
where
    I: BatchedIterator,
    I::Item: Clone,
    for<'a> I::Batch<'a>: IndexedParallelIterator,
{
    type Item = I::Item;
    type Batch<'a> = I::Batch<'a>;
}

impl<I> BatchedIterator for ChainMany<I>
where
    I: BatchedIterator,
    I::Item: Clone,
    for<'a> I::Batch<'a>: IndexedParallelIterator,
{
    #[inline]
    fn next_batch<'a>(&'a mut self) -> Option<Self::Batch<'a>> {
        for iter in &mut self.iters[self.cur_index..] {
            if let Some(batch) = iter.next_batch() {
                return Some(batch);
            }
            self.cur_index += 1;
        }
        None
    }

    fn len(&self) -> Option<usize> {
        self.iters.iter().map(|iter| iter.len()).sum()
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        BUFFER_SIZE,
        iterator::{BatchAdapter, BatchedIterator, chain_many},
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
