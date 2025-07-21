use crate::{
    iterator::BatchedIteratorAssocTypes,
    serialize::{DeserializeRaw, SerializeRaw},
};
use rayon::{
    iter::{Copied, MinLen},
    prelude::*,
    slice::Iter,
};
use std::marker::PhantomData;

use crate::{BUFFER_SIZE, iterator::BatchedIterator};

use super::{AVec, avec, backend::InnerFile};

pub enum IterChunkMappedWithBuf<'a, T, U, F, const N: usize>
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
        result_buffer: &'a mut Vec<U>,
        first: bool,
        f: F,
    },
    Buffer {
        buffer: Vec<T>,
        result_buffer: Vec<U>,
        f: F,
    },
}

impl<'a, T, U, F, const N: usize> IterChunkMappedWithBuf<'a, T, U, F, N>
where
    T: 'static + SerializeRaw + DeserializeRaw + Send + Sync + Copy,
    U: 'static + SerializeRaw + DeserializeRaw + Send + Sync + Copy,
    F: for<'b> Fn(&[T]) -> U + Sync + Send,
{
    pub fn new_file(file: InnerFile, f: F, result_buffer: &'a mut Vec<U>) -> Self {
        assert!(N > 0, "N must be greater than 0");
        assert!(BUFFER_SIZE % N == 0, "BUFFER_SIZE must be divisible by N");
        assert_eq!(std::mem::align_of::<[T; N]>(), std::mem::align_of::<T>());
        assert_eq!(std::mem::size_of::<[T; N]>(), N * std::mem::size_of::<T>());
        let mut work_buffer = avec![];
        work_buffer.reserve(T::SIZE * BUFFER_SIZE);
        result_buffer.clear();
        Self::File {
            file,
            lifetime: PhantomData,
            work_buffer,
            work_buffer_2: Vec::with_capacity(BUFFER_SIZE),
            temp_buffer: Vec::with_capacity(BUFFER_SIZE),
            result_buffer,
            first: true,
            f,
        }
    }

    pub fn new_buffer(buffer: Vec<T>, f: F) -> Self {
        assert!(N > 0, "N must be greater than 0");
        assert!(BUFFER_SIZE % N == 0, "BUFFER_SIZE must be divisible by N");
        assert_eq!(std::mem::align_of::<[T; N]>(), std::mem::align_of::<T>());
        assert_eq!(std::mem::size_of::<[T; N]>(), N * std::mem::size_of::<T>());
        let len = buffer.len();
        Self::Buffer {
            buffer,
            f,
            result_buffer: Vec::with_capacity(len / N),
        }
    }
}

impl<'a, T, U, F, const N: usize> BatchedIteratorAssocTypes
    for IterChunkMappedWithBuf<'a, T, U, F, N>
where
    T: 'static + SerializeRaw + DeserializeRaw + Send + Sync + Copy,
    U: 'static + SerializeRaw + DeserializeRaw + Send + Sync + Copy,
    F: for<'b> Fn(&[T]) -> U + Sync + Send,
{
    type Item = U;
    type Batch<'b> = MinLen<Copied<Iter<'b, U>>>;
}

impl<'a, T, U, F, const N: usize> BatchedIterator for IterChunkMappedWithBuf<'a, T, U, F, N>
where
    T: 'static + SerializeRaw + DeserializeRaw + Send + Sync + Copy,
    U: 'static + SerializeRaw + DeserializeRaw + Send + Sync + Copy,
    F: for<'b> Fn(&[T]) -> U + Sync + Send,
{
    #[inline]
    fn next_batch<'b>(&'b mut self) -> Option<Self::Batch<'b>> {
        match self {
            Self::File {
                file,
                work_buffer,
                work_buffer_2: result,
                result_buffer,
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
                    result_buffer.clear();
                    let (_, b) = rayon::join(
                        || {
                            result
                                .par_chunks_exact(N)
                                .map(&*f)
                                .with_min_len(1 << 10)
                                .collect_into_vec(result_buffer);
                        },
                        || {
                            T::deserialize_raw_batch(
                                &mut *temp_buffer,
                                work_buffer,
                                BUFFER_SIZE,
                                file,
                            )
                            .ok()
                        },
                    );
                    b?;
                    std::mem::swap(result, temp_buffer);
                    temp_buffer.clear();
                    Some((*result_buffer).par_iter().copied().with_min_len(1 << 10))
                }
            },
            Self::Buffer {
                buffer,
                f,
                result_buffer,
            } => {
                if buffer.is_empty() {
                    None
                } else {
                    result_buffer.clear();
                    buffer
                        .par_chunks_exact(N)
                        .map(&*f)
                        .with_min_len(1 << 7)
                        .collect_into_vec(result_buffer);
                    Some(result_buffer.par_iter().copied().with_min_len(1 << 7))
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
