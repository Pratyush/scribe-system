use super::BatchedIterator;
use rayon::prelude::*;

pub struct Map<I: BatchedIterator, U: Send + Sync, F: Fn(I::Item) -> U + Send + Sync + Clone> {
    pub iter: I,
    pub f: F,
}

impl<I, U, F> BatchedIterator for Map<I, U, F> 
where
    I: BatchedIterator, U: Send + Sync, F: Fn(I::Item) -> U + Send + Sync + Clone
{
    type Item = U;
    type Batch = rayon::iter::Map<I::Batch, F>;
    
    fn next_batch(&mut self) -> Option<Self::Batch> {
            self.iter.next_batch().map(|i| i.map(self.f.clone()))
    }
}
