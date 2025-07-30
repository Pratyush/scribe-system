use crate::{BUFFER_SIZE, iterator::BatchedIteratorAssocTypes};

use super::BatchedIterator;

pub struct Repeat<T> {
    pub iter: T,
    pub count: usize,
}

impl<T> BatchedIteratorAssocTypes for Repeat<T>
where
    T: Send + Sync + Copy,
{
    type Item = T;
    type Batch<'a> = rayon::iter::RepeatN<T>;
}

impl<T> BatchedIterator for Repeat<T>
where
    T: Send + Sync + Copy,
{
    #[inline]
    fn next_batch<'a>(&'a mut self) -> Option<Self::Batch<'a>> {
        if self.count == 0 {
            return None;
        }
        let batch_size = self.count.min(BUFFER_SIZE);
        self.count -= batch_size;
        Some(rayon::iter::repeatn(self.iter, batch_size))
    }

    fn len(&self) -> Option<usize> {
        Some(self.count)
    }
}
