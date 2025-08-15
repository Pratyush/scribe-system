use crate::{
    BUFFER_SIZE,
    file_vec::{backend::InnerFile, double_buffered::Buffers},
    iterator::{BatchedIterator, BatchedIteratorAssocTypes},
    serialize::{DeserializeRaw, SerializeRaw},
};
use rayon::{iter::MinLen, prelude::*};
use std::{fmt::Debug, marker::PhantomData};

pub enum Iter<'a, T: SerializeRaw + DeserializeRaw + 'static> {
    File {
        file: InnerFile,
        buffer: Buffers<T>,
        lifetime: PhantomData<&'a T>,
    },
    Buffer {
        buffer: Vec<T>,
        remaining: bool,
    },
}

impl<'a, T: SerializeRaw + DeserializeRaw> Iter<'a, T> {
    pub fn new_file(file: InnerFile) -> Self {
        let buffer = Buffers::new();
        Self::File {
            file,
            buffer,
            lifetime: PhantomData,
        }
    }

    pub fn new_buffer(buffer: Vec<T>) -> Self {
        Self::Buffer {
            buffer,
            remaining: true,
        }
    }
}

impl<'a, T: 'static + SerializeRaw + DeserializeRaw + Send + Sync + Copy + Debug>
    BatchedIteratorAssocTypes for Iter<'a, T>
{
    type Item = T;
    type Batch<'b> = MinLen<rayon::iter::Copied<rayon::slice::Iter<'b, T>>>;
}

impl<'a, T: 'static + SerializeRaw + DeserializeRaw + Send + Sync + Copy + Debug> BatchedIterator
    for Iter<'a, T>
{
    #[inline]
    fn next_batch<'b>(&'b mut self) -> Option<Self::Batch<'b>> {
        match self {
            Iter::File { file, buffer, .. } => {
                buffer.clear();
                T::deserialize_raw_batch(&mut buffer.t_s, &mut buffer.bytes, BUFFER_SIZE, file)
                    .ok()?;
                if buffer.t_s.is_empty() {
                    // If the output buffer is empty, we have reached the end of the file
                    return None;
                }
                Some(buffer.t_s.par_iter().copied().with_min_len(1 << 7))
            },
            Iter::Buffer { buffer, remaining } => {
                if buffer.is_empty() || !*remaining {
                    None
                } else {
                    *remaining = false;
                    Some(buffer.par_iter().copied().with_min_len(1 << 7))
                }
            },
        }
    }

    fn len(&self) -> Option<usize> {
        match self {
            Self::File { file, .. } => Some((file.len() - file.position()) / T::SIZE),
            Self::Buffer { buffer, remaining } => remaining.then(|| buffer.len()),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{file_vec::FileVec, iterator::BatchedIterator};
    use ark_bls12_381::Fr;

    #[test]
    fn test_consistency() {
        for log_size in 1..=20 {
            let size = 1 << log_size;
            let input: Vec<Fr> = (0..size).map(|i| Fr::from(i)).collect();
            let fv = FileVec::from_iter(input.clone());

            let output = fv.iter().to_vec();
            for (i, (out, inp)) in output.chunks(100).zip(input.chunks(100)).enumerate() {
                assert_eq!(out, inp, "Mismatch for size {size} at chunk {i}");
            }

            assert_eq!(output, input, "Mismatch for size {size}",);
        }
    }
}
