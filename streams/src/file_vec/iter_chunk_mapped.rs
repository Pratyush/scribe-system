use crate::serialize::{DeserializeRaw, SerializeRaw};
use rayon::{prelude::*, vec::IntoIter};
use std::marker::PhantomData;

use crate::{iterator::BatchedIterator, BUFFER_SIZE};

use super::{avec, backend::InnerFile, AVec};

pub enum IterChunkMapped<'a, T, U, F, const N: usize>
where
    T: 'static + SerializeRaw + DeserializeRaw + Send + Sync + Copy,
    U: 'static + SerializeRaw + DeserializeRaw + Send + Sync + Copy,
    F: for<'b> Fn(&[T]) -> U + Sync + Send,
{
    File {
        file: InnerFile,
        lifetime: PhantomData<&'a T>,
        work_buffer: AVec,
        work_buffer_2: Vec<T>,
        temp_buffer: Vec<T>,
        first: bool,
        f: F,
    },
    Buffer {
        buffer: Vec<T>,
        f: F,
    },
}

impl<'a, T, U, F, const N: usize> IterChunkMapped<'a, T, U, F, N>
where
    T: 'static + SerializeRaw + DeserializeRaw + Send + Sync + Copy,
    U: 'static + SerializeRaw + DeserializeRaw + Send + Sync + Copy,
    F: for<'b> Fn(&[T]) -> U + Sync + Send,
{
    pub fn new_file(file: InnerFile, f: F) -> Self {
        assert!(N > 0, "N must be greater than 0");
        assert!(BUFFER_SIZE % N == 0, "BUFFER_SIZE must be divisible by N");
        assert_eq!(std::mem::align_of::<[T; N]>(), std::mem::align_of::<T>());
        assert_eq!(std::mem::size_of::<[T; N]>(), N * std::mem::size_of::<T>());
        let mut work_buffer = avec![];
        work_buffer.reserve(T::SIZE * BUFFER_SIZE);
        Self::File {
            file,
            lifetime: PhantomData,
            work_buffer,
            work_buffer_2: Vec::with_capacity(BUFFER_SIZE),
            temp_buffer: Vec::with_capacity(BUFFER_SIZE),
            first: true,
            f,
        }
    }

    pub fn new_buffer(buffer: Vec<T>, f: F) -> Self {
        assert!(N > 0, "N must be greater than 0");
        assert!(BUFFER_SIZE % N == 0, "BUFFER_SIZE must be divisible by N");
        assert_eq!(std::mem::align_of::<[T; N]>(), std::mem::align_of::<T>());
        assert_eq!(std::mem::size_of::<[T; N]>(), N * std::mem::size_of::<T>());
        Self::Buffer { buffer, f }
    }
}

impl<'a, T, U, F, const N: usize> BatchedIterator for IterChunkMapped<'a, T, U, F, N>
where
    T: 'static + SerializeRaw + DeserializeRaw + Send + Sync + Copy,
    U: 'static + SerializeRaw + DeserializeRaw + Send + Sync + Copy,
    F: for<'b> Fn(&[T]) -> U + Sync + Send,
{
    type Item = U;
    type Batch = IntoIter<U>;

    #[inline]
    fn next_batch(&mut self) -> Option<Self::Batch> {
        match self {
            Self::File {
                file,
                work_buffer,
                work_buffer_2: result,
                temp_buffer,
                f,
                first,
                ..
            } => {
                if *first {
                    T::deserialize_raw_batch(result, work_buffer, BUFFER_SIZE, &mut *file).ok()?;
                    *first = false;
                }
                if result.is_empty() {
                    None
                } else {
                    let (a, b) = rayon::join(
                        || result
                            .par_chunks_exact(N)
                            .map(|chunk| f(chunk))
                            .with_min_len(1 << 10)
                            .collect::<Vec<_>>()
                            .into_par_iter(),
                            || {
                                
                                T::deserialize_raw_batch(&mut *temp_buffer, work_buffer, BUFFER_SIZE, file).ok()
                            }
                    );
                    let _ = b?;
                    std::mem::swap(result, temp_buffer);
                    temp_buffer.clear();
                    Some(a)
                }
                
            },
            Self::Buffer { buffer, f } => {
                if buffer.is_empty() {
                    None
                } else {
                    Some(
                        std::mem::take(buffer)
                            .par_chunks_exact(N)
                            .map(|chunk| f(chunk))
                            .with_min_len(1 << 7)
                            .collect::<Vec<_>>()
                            .into_par_iter(),
                    )
                }
            },
        }
    }

    fn len(&self) -> Option<usize> {
        let len = match self {
            Self::File { file, .. } => file.len() / T::SIZE / N,
            Self::Buffer { buffer, .. } => buffer.len() / N,
        };
        Some(len)
    }
}
