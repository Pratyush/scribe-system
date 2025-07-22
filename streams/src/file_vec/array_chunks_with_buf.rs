use crate::{
    iterator::BatchedIteratorAssocTypes,
    serialize::{DeserializeRaw, SerializeRaw},
};
use rayon::{
    iter::{Copied, MinLen},
    prelude::*,
    slice::Iter,
};

use crate::{BUFFER_SIZE, iterator::BatchedIterator};

use super::{AVec, avec, backend::InnerFile};

pub enum ArrayChunksWithBuf<'a, T, const N: usize>
where
    T: 'static + SerializeRaw + DeserializeRaw + Send + Sync + Copy,
{
    File {
        file: InnerFile,
        work_buffer: AVec,
        work_buffer_2: &'a mut Vec<T>,
    },
    Buffer {
        last: bool,
        buffer: Vec<T>,
    },
}

impl<'a, T, const N: usize> ArrayChunksWithBuf<'a, T, N>
where
    T: 'static + SerializeRaw + DeserializeRaw + Send + Sync + Copy,
{
    pub fn new_file(file: InnerFile, buf: &'a mut Vec<T>) -> Self {
        assert!(N > 0, "N must be greater than 0");
        assert!(BUFFER_SIZE % N == 0, "BUFFER_SIZE must be divisible by N");
        assert_eq!(std::mem::align_of::<[T; N]>(), std::mem::align_of::<T>());
        assert_eq!(std::mem::size_of::<[T; N]>(), N * std::mem::size_of::<T>());

        let mut work_buffer = avec![];
        work_buffer.reserve(T::SIZE * BUFFER_SIZE);
        buf.clear();
        Self::File {
            file,
            work_buffer,
            work_buffer_2: buf,
        }
    }

    pub fn new_buffer(buffer: Vec<T>) -> Self {
        assert!(N > 0, "N must be greater than 0");
        assert!(BUFFER_SIZE % N == 0, "BUFFER_SIZE must be divisible by N");
        assert_eq!(std::mem::align_of::<[T; N]>(), std::mem::align_of::<T>());
        assert_eq!(std::mem::size_of::<[T; N]>(), N * std::mem::size_of::<T>());
        Self::Buffer {
            buffer,
            last: false,
        }
    }
}

impl<'a, T, const N: usize> BatchedIteratorAssocTypes for ArrayChunksWithBuf<'a, T, N>
where
    T: 'static + SerializeRaw + DeserializeRaw + Send + Sync + Copy,
{
    type Item = [T; N];
    type Batch<'b> = MinLen<Copied<Iter<'b, [T; N]>>>;
}

impl<'a, T, const N: usize> BatchedIterator for ArrayChunksWithBuf<'a, T, N>
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
                    assert_eq!(
                        work_buffer_2.len() % N,
                        0,
                        "slice length must be divisible by N"
                    );
                    let m = work_buffer_2.len() / N;
                    let slice;
                    unsafe {
                        slice = std::slice::from_raw_parts(
                            work_buffer_2.as_slice().as_ptr() as *const [T; N],
                            m,
                        )
                    };

                    Some(slice.par_iter().copied().with_min_len(1 << 10))
                }
            },
            Self::Buffer { buffer, last } => {
                if *last || buffer.is_empty() {
                    None
                } else {
                    assert_eq!(buffer.len() % N, 0, "slice length must be divisible by N");
                    let m = buffer.len() / N;
                    let slice;
                    unsafe {
                        slice = std::slice::from_raw_parts(
                            buffer.as_slice().as_ptr() as *const [T; N],
                            m,
                        )
                    };
                    *last = true;

                    Some(slice.par_iter().copied().with_min_len(1 << 10))
                }
            },
        }
    }

    fn len(&self) -> Option<usize> {
        let len = match self {
            Self::File { file, .. } => (file.len() - file.position()) / (T::SIZE * N),
            Self::Buffer { buffer, last } => {
                if *last {
                    0
                } else {
                    buffer.len()
                }
            },
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
    fn test_array_chunks_vs_with_buf() {
        let mut rng = test_rng();

        for log_size in 1..=20 {
            let size = 1 << log_size;
            let input: Vec<Fr> = (0..size).map(|_| Fr::rand(&mut rng)).collect();
            let fv = FileVec::from_iter(input.clone());

            let expected: Vec<[_; 2]> = input.chunks(2).map(|c| c.try_into().unwrap()).collect();

            let output_standard = fv.array_chunks::<2>().to_vec();

            let mut buf = vec![];
            let output_with_buf = fv.array_chunks_with_buf::<2>(&mut buf).to_vec();

            assert_eq!(output_standard, output_with_buf, "Mismatch for size {size}",);
            assert_eq!(expected, output_with_buf, "Mismatch for size {size}",);
        }
    }
}
