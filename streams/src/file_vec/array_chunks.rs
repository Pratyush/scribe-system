use crate::{
    iterator::BatchedIteratorAssocTypes,
    serialize::{DeserializeRaw, SerializeRaw},
};
use rayon::{prelude::*, vec::IntoIter};
use std::marker::PhantomData;

use crate::{BUFFER_SIZE, iterator::BatchedIterator};

use super::{AVec, avec, backend::InnerFile};

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

impl<'a, T, const N: usize> BatchedIteratorAssocTypes for ArrayChunks<'a, T, N>
where
    T: 'static + SerializeRaw + DeserializeRaw + Send + Sync + Copy,
{
    type Item = [T; N];
    type Batch<'b> = IntoIter<[T; N]>;
}

impl<'a, T, const N: usize> BatchedIterator for ArrayChunks<'a, T, N>
where
    T: 'static + SerializeRaw + DeserializeRaw + Send + Sync + Copy,
{
    #[inline]
    fn next_batch<'b>(&'b mut self) -> Option<Self::Batch<'b>> {
        match self {
            Self::File {
                file,
                work_buffer,
                work_buffer_2,
                ..
            } => {
                work_buffer_2.clear();
                T::deserialize_raw_batch(work_buffer_2, work_buffer, BUFFER_SIZE * N, file).ok()?;
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
            Self::File { file, .. } => (file.len() - file.position()) / T::SIZE / N,
            Self::Buffer { buffer } => buffer.len(),
        };
        Some(len / N)
    }
}

#[cfg(test)]
mod tests {
    use ark_bls12_381::Fr;
    use ark_std::{UniformRand, test_rng};

    use crate::{file_vec::FileVec, iterator::BatchedIterator};

    #[test]
    fn test_consistency() {
        let mut rng = test_rng();

        for log_size in 1..=20 {
            let size = 1 << log_size;
            let input: Vec<Fr> = (0..size).map(|_| Fr::rand(&mut rng)).collect();
            let fv = FileVec::from_iter(input.clone());

            let expected: Vec<[_; 2]> = input.chunks(2).map(|c| c.try_into().unwrap()).collect();

            let output_standard = fv.array_chunks::<2>().to_vec();

            assert_eq!(output_standard, expected, "Mismatch for size {size}",);
        }
    }
}
