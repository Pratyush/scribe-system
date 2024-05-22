use rayon::prelude::*;

use super::BatchedIterator;

pub struct FlatMap<I, U, F>
where
    I: BatchedIterator,
    U: IntoParallelIterator + Send + Sync,
    F: Fn(I::Item) -> U,
{
    pub iter: I,
    pub f: F,
}

impl<I, U, F> BatchedIterator for FlatMap<I, U, F>
where
    I: BatchedIterator,
    U: IntoParallelIterator + Send + Sync,
    F: Fn(I::Item) -> U + Send + Sync + Clone,
    U::Item: Send + Sync,
{
    type Item = U::Item;
    type Batch = rayon::iter::FlatMap<I::Batch, F>;

    fn next_batch(&mut self) -> Option<Self::Batch> {
        let iter = self.iter.next_batch()?;
        Some(iter.flat_map(self.f.clone()))
    }
}


//  self.buf.clear();
//         self.buf.par_extend(self.iter.next_batch()?);
//         let batch = self
//             .buf
//             .par_chunks_exact(N)
//             .map(|chunk| <[I::Item; N]>::try_from(chunk).unwrap())
//             .collect::<Vec<_>>();
//         println!("array chunk batch: {:?}", batch);
//         Some(batch.into_par_iter())