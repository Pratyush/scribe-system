use crate::{
    iterator::BatchedIteratorAssocTypes,
    serialize::{DeserializeRaw, SerializeRaw},
};
use rayon::{
    iter::{Copied, MinLen},
    prelude::*,
    slice::Iter,
};
use std::fmt::Debug;

use crate::{BUFFER_SIZE, iterator::BatchedIterator};

use super::{AVec, avec, backend::InnerFile};

pub enum IterWithBuf<'a, T: SerializeRaw + DeserializeRaw + 'static> {
    File {
        file: InnerFile,
        buffer: &'a mut Vec<T>,
        work_buffer: AVec,
    },
    Buffer {
        last: bool,
        buffer: &'a mut Vec<T>,
    },
}

impl<'a, T: SerializeRaw + DeserializeRaw> IterWithBuf<'a, T> {
    pub fn new_file_with_buf(file: InnerFile, buffer: &'a mut Vec<T>) -> Self {
        let mut work_buffer = avec![];
        work_buffer.reserve(T::SIZE * BUFFER_SIZE);
        buffer.clear();
        Self::File {
            file,
            buffer,
            work_buffer,
        }
    }

    pub fn new_buffer(buffer: &'a mut Vec<T>) -> Self {
        Self::Buffer {
            buffer,
            last: false,
        }
    }
}

impl<'a, T: 'static + SerializeRaw + DeserializeRaw + Send + Sync + Copy + Debug>
    BatchedIteratorAssocTypes for IterWithBuf<'a, T>
{
    type Item = T;
    type Batch<'b> = MinLen<Copied<Iter<'b, T>>>;
}

impl<'a, T: 'static + SerializeRaw + DeserializeRaw + Send + Sync + Copy + Debug> BatchedIterator
    for IterWithBuf<'a, T>
{
    #[inline]
    fn next_batch<'b>(&'b mut self) -> Option<Self::Batch<'b>> {
        match self {
            Self::File {
                file,
                work_buffer,
                buffer,
            } => {
                T::deserialize_raw_batch(buffer, work_buffer, BUFFER_SIZE, file).ok()?;
                if buffer.is_empty() {
                    None
                } else {
                    Some((*buffer).par_iter().copied().with_min_len(1 << 7))
                }
            },
            Self::Buffer { buffer, last } => {
                if *last || buffer.is_empty() {
                    None
                } else {
                    *last = true;
                    Some((*buffer).par_iter().copied().with_min_len(1 << 7))
                }
            },
        }
    }

    fn len(&self) -> Option<usize> {
        let len = match self {
            Self::File { file, .. } => file.len() / T::SIZE,
            Self::Buffer { buffer, last } => {
                if *last {
                    0
                } else {
                    buffer.len()
                }
            },
        };
        Some(len)
    }
}

#[cfg(test)]
mod tests {
    use ark_bls12_381::Fr;
    use ark_std::{UniformRand, test_rng};

    use crate::{file_vec::FileVec, iterator::BatchedIterator};

    #[test]
    fn test_iter_vs_with_buf() {
        let mut rng = test_rng();

        for log_size in 1..=20 {
            let size = 1 << log_size;
            let input: Vec<Fr> = (0..size).map(|_| Fr::rand(&mut rng)).collect();
            let fv = FileVec::from_iter(input.clone());

            let output_standard = fv.iter().to_vec();

            let mut buf = vec![];
            let output_with_buf = fv.iter_with_buf(&mut buf).to_vec();

            assert_eq!(output_standard, output_with_buf, "Mismatch for size {size}",);
            assert_eq!(input, output_with_buf, "Mismatch for size {size}",);
        }
    }
}
