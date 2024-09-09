use rayon::iter::{IntoParallelIterator, ParallelIterator};

use crate::streams::BUFFER_SIZE;

use super::BatchedIterator;

pub struct FromFn<F> {
    func: F,
    cur_pos: usize,
    max: usize,
}

impl<F> FromFn<F> {
    pub fn new(func: F, max: usize) -> Self {
        Self {
            func,
            cur_pos: 0,
            max,
        }
    }
}

impl<F, T> BatchedIterator for FromFn<F>
where
    F: Fn(usize) -> Option<T> + Send + Sync + Copy,
    T: Send + Sync + Clone,
{
    type Item = T;
    type Batch = rayon::iter::FilterMap<rayon::range::Iter<usize>, F>;

    #[inline]
    fn next_batch(&mut self) -> Option<Self::Batch> {
        if self.cur_pos >= self.max {
            return None;
        }
        let cur_pos = self.cur_pos;
        self.cur_pos += BUFFER_SIZE;
        Some(
            (cur_pos..cur_pos + BUFFER_SIZE)
                .into_par_iter()
                .filter_map(self.func),
        )
    }
}
