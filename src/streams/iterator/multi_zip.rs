use rayon::prelude::*;
use smallvec::SmallVec;

use super::{BatchedIterator, BUFFER_SIZE};

pub type SVec<T> = SmallVec<[T; 4]>;


pub struct MultiZip<I> {
    iters: Vec<I>,
}

impl<I> MultiZip<I> {
    pub fn new(iters: Vec<I>) -> Self {
        Self { iters }
    }
}

impl<I> BatchedIterator for MultiZip<I>
where
    I: BatchedIterator,
    I::Item: Clone,
    I::Batch: IndexedParallelIterator,
{
    type Item = SVec<I::Item>;
    type Batch = rayon::vec::IntoIter<SVec<I::Item>>;
    fn next_batch(&mut self) -> Option<Self::Batch> {
        let mut batched = vec![SVec::with_capacity(self.iters.len()); BUFFER_SIZE];
        for iter in &mut self.iters {
            batched.par_iter_mut().zip(iter.next_batch()?).for_each(|(zipped, b)| zipped.push(b));
        }
        let start_of_empty = batched.par_iter().position_first(|x| x.is_empty()).unwrap_or(batched.len());
        batched.truncate(start_of_empty);
        Some(batched.into_par_iter())
    }
}


#[cfg(test)]
mod tests {
    use crate::streams::iterator::{multi_zip, BatchAdapter, BatchedIterator};

    #[test]
    fn test_multi_zip() {
        let iter1 = BatchAdapter::from(0..100).array_chunks::<2>();
        let iter2 = BatchAdapter::from(100..200).array_chunks::<2>();
        
        let _zipped = multi_zip(vec![iter1, iter2]);
    }
}