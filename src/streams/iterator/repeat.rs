use crate::streams::BUFFER_SIZE;

use super::BatchedIterator;

pub struct Repeat<T> {
    pub iter: T,
    pub count: usize,
}

impl<T> BatchedIterator for Repeat<T>
where
    T: Send + Sync + Copy,
{
    type Item = T;
    type Batch = rayon::iter::RepeatN<T>;

    fn next_batch(&mut self) -> Option<Self::Batch> {
        if self.count == 0 {
            return None;
        }
        let batch_size = if self.count < BUFFER_SIZE {
            self.count
        } else {
            BUFFER_SIZE
        };
        println!("repeat batch_size: {}", batch_size);
        self.count -= batch_size;
        Some(rayon::iter::repeatn(self.iter, batch_size))
    }
}
