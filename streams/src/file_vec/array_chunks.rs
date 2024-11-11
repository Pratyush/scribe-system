use crate::serialize::{DeserializeRaw, SerializeRaw};
use rayon::{prelude::*, vec::IntoIter};
use std::marker::PhantomData;

use crate::{iterator::BatchedIterator, BUFFER_SIZE};

use super::{avec, backend::InnerFile, AVec};

pub enum ArrayChunks<'a, T, const N: usize>
where
    T: 'static + SerializeRaw + DeserializeRaw + Send + Sync + Copy,
{
    File {
        file: InnerFile,
        lifetime: PhantomData<&'a T>,
        work_buffer: AVec,
        work_buffer_2: Vec<T>,
    },
    Buffer {
        buffer: Vec<T>,
    },
}

impl<'a, T, const N: usize> ArrayChunks<'a, T, N>
where
    T: 'static + SerializeRaw + DeserializeRaw + Send + Sync + Copy,
{
    pub fn new_file(file: InnerFile) -> Self {
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
        }
    }

    pub fn new_buffer(buffer: Vec<T>) -> Self {
        assert!(N > 0, "N must be greater than 0");
        assert!(BUFFER_SIZE % N == 0, "BUFFER_SIZE must be divisible by N");
        assert_eq!(std::mem::align_of::<[T; N]>(), std::mem::align_of::<T>());
        assert_eq!(std::mem::size_of::<[T; N]>(), N * std::mem::size_of::<T>());
        Self::Buffer { buffer }
    }
}

impl<'a, T, const N: usize> BatchedIterator for ArrayChunks<'a, T, N>
where
    T: 'static + SerializeRaw + DeserializeRaw + Send + Sync + Copy,
{
    type Item = [T; N];
    type Batch = IntoIter<[T; N]>;

    #[inline]
    fn next_batch(&mut self) -> Option<Self::Batch> {
        match self {
            Self::File {
                file,
                work_buffer,
                work_buffer_2,
                ..
            } => {
                work_buffer_2.clear();
                T::deserialize_raw_batch(work_buffer_2, work_buffer, BUFFER_SIZE, file).ok()?;
                if work_buffer_2.is_empty() {
                    None
                } else {
                    Some(
                        work_buffer_2
                            .par_chunks(N)
                            .map(|chunk| <[T; N]>::try_from(chunk).unwrap())
                            .with_min_len(1 << 10)
                            .collect::<Vec<_>>()
                            .into_par_iter(),
                    )
                }
            },
            Self::Buffer { buffer } => {
                if buffer.is_empty() {
                    None
                } else {
                    Some(
                        std::mem::take(buffer)
                            .par_chunks(N)
                            .map(|chunk| <[T; N]>::try_from(chunk).unwrap())
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
            Self::File { file, .. } => file.len() / T::SIZE,
            Self::Buffer { buffer } => buffer.len(),
        };
        Some(len / N)
    }
}
