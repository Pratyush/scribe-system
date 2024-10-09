use crate::streams::serialize::{DeserializeRaw, SerializeRaw};
use rayon::{prelude::*, vec::IntoIter};
use std::marker::PhantomData;

use crate::streams::{iterator::BatchedIterator, BUFFER_SIZE};

use super::backend::InnerFile;

pub enum IterChunkMapped<'a, T, U, F, const N: usize>
where
    T: 'static + SerializeRaw + DeserializeRaw + Send + Sync + Copy,
    U: 'static + SerializeRaw + DeserializeRaw + Send + Sync + Copy,
    F: for<'b> Fn(&[T]) -> U + Sync + Send,
{
    File {
        file: InnerFile,
        lifetime: PhantomData<&'a T>,
        work_buffer: Vec<u8>,
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
        let size = T::SIZE;
        assert!(N > 0, "N must be greater than 0");
        assert!(BUFFER_SIZE % N == 0, "BUFFER_SIZE must be divisible by N");
        assert_eq!(std::mem::align_of::<[T; N]>(), std::mem::align_of::<T>());
        assert_eq!(std::mem::size_of::<[T; N]>(), N * std::mem::size_of::<T>());
        Self::File {
            file,
            lifetime: PhantomData,
            work_buffer: Vec::with_capacity(size * BUFFER_SIZE),
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
                f,
                ..
            } => {
                let mut result = Vec::with_capacity(BUFFER_SIZE);
                T::deserialize_raw_batch(&mut result, work_buffer, BUFFER_SIZE, file).ok()?;
                if result.is_empty() {
                    None
                } else {
                    Some(
                        result
                            .par_chunks(N)
                            .map(|chunk| f(chunk))
                            .with_min_len(1 << 10)
                            .collect::<Vec<_>>()
                            .into_par_iter(),
                    )
                }
            },
            Self::Buffer { buffer, f } => {
                if buffer.is_empty() {
                    None
                } else {
                    Some(
                        std::mem::take(buffer)
                            .par_chunks(N)
                            .map(|chunk| f(chunk))
                            .with_min_len(1 << 7)
                            .collect::<Vec<_>>()
                            .into_par_iter(),
                    )
                }
            },
        }
    }
}
