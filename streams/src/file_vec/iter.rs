use crate::{
    iterator::BatchedIteratorAssocTypes,
    serialize::{DeserializeRaw, SerializeRaw},
};
use rayon::{iter::MinLen, prelude::*, vec::IntoIter};
use std::{fmt::Debug, marker::PhantomData};

use crate::{BUFFER_SIZE, iterator::BatchedIterator};

use super::{AVec, avec, backend::InnerFile};

pub enum Iter<'a, T: SerializeRaw + DeserializeRaw + 'static> {
    File {
        file: InnerFile,
        lifetime: PhantomData<&'a T>,
        work_buffer: AVec,
    },
    Buffer {
        buffer: Vec<T>,
    },
}

impl<'a, T: SerializeRaw + DeserializeRaw> Iter<'a, T> {
    pub fn new_file(file: InnerFile) -> Self {
        let mut work_buffer = avec![];
        work_buffer.reserve(T::SIZE * BUFFER_SIZE);
        Self::File {
            file,
            lifetime: PhantomData,
            work_buffer,
        }
    }

    pub fn new_buffer(buffer: Vec<T>) -> Self {
        Self::Buffer { buffer }
    }
}

impl<'a, T: 'static + SerializeRaw + DeserializeRaw + Send + Sync + Copy + Debug>
    BatchedIteratorAssocTypes for Iter<'a, T>
{
    type Item = T;
    type Batch<'b> = MinLen<IntoIter<T>>;
}

impl<'a, T: 'static + SerializeRaw + DeserializeRaw + Send + Sync + Copy + Debug> BatchedIterator
    for Iter<'a, T>
{
    #[inline]
    fn next_batch<'b>(&'b mut self) -> Option<Self::Batch<'b>> {
        match self {
            Iter::File {
                file, work_buffer, ..
            } => {
                let mut result = Vec::with_capacity(BUFFER_SIZE);
                T::deserialize_raw_batch(&mut result, work_buffer, BUFFER_SIZE, file).ok()?;
                if result.is_empty() {
                    None
                } else {
                    Some(result.into_par_iter().with_min_len(1 << 7))
                }
            },
            Iter::Buffer { buffer } => {
                if buffer.is_empty() {
                    None
                } else {
                    Some(std::mem::take(buffer).into_par_iter().with_min_len(1 << 7))
                }
            },
        }
    }

    fn len(&self) -> Option<usize> {
        let len = match self {
            Self::File { file, .. } => (file.len() - file.position()) / T::SIZE,
            Self::Buffer { buffer } => buffer.len(),
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
    fn test_consistency() {
        let mut rng = test_rng();

        for log_size in 1..=20 {
            let size = 1 << log_size;
            let input: Vec<Fr> = (0..size).map(|_| Fr::rand(&mut rng)).collect();
            let fv = FileVec::from_iter(input.clone());

            let output_standard = fv.iter().to_vec();

            assert_eq!(output_standard, input, "Mismatch for size {size}",);
        }
    }
}
