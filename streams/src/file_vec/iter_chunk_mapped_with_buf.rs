use crate::{
    BUFFER_SIZE,
    file_vec::{backend::InnerFile, double_buffered::DoubleBufferedReader},
    iterator::{BatchedIterator, BatchedIteratorAssocTypes},
    serialize::{DeserializeRaw, SerializeRaw},
};
use rayon::{
    iter::{Copied, MinLen},
    prelude::*,
    slice::Iter,
};
use std::marker::PhantomData;

pub enum IterChunkMappedWithBuf<'a, T, U, F, const N: usize>
where
    T: 'static + SerializeRaw + DeserializeRaw + Send + Sync + Copy,
    U: 'static + SerializeRaw + DeserializeRaw + Send + Sync + Copy,
    F: for<'b> Fn(&[T]) -> U + Sync + Send,
{
    File {
        reader: DoubleBufferedReader<T>,
        lifetime: PhantomData<&'a T>,
        output: Vec<T>,
        result_buffer: &'a mut Vec<U>,
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
        result_buffer.clear();
        let reader = DoubleBufferedReader::new(file);
        let output = Vec::with_capacity(BUFFER_SIZE);
        Self::File {
            reader,
            lifetime: PhantomData,
            output,
            result_buffer,
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
                reader,
                output,
                result_buffer,
                f,
                ..
            } => {
                output.clear();
                result_buffer.clear();

                if reader.is_first_read() {
                    reader.do_first_read().ok()?;
                } else {
                    reader.harvest();
                }

                reader.read_output(output);
                if output.is_empty() {
                    return None;
                }
                reader.start_prefetches();

                output
                    .par_chunks_exact(N)
                    .map(&*f)
                    .with_min_len(1 << 10)
                    .collect_into_vec(result_buffer);
                Some(result_buffer.par_iter().copied().with_min_len(1 << 7))
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
                    buffer.clear();
                    Some(result_buffer.par_iter().copied().with_min_len(1 << 7))
                }
            },
        }
    }

    fn len(&self) -> Option<usize> {
        match self {
            Self::File { reader, .. } => reader.len().map(|s| s / N),
            Self::Buffer { buffer, .. } => Some(buffer.len() / N),
        }
    }
}

#[cfg(test)]
mod tests {
    use ark_bls12_381::Fr;
    use ark_std::{UniformRand, test_rng};

    use crate::{file_vec::FileVec, iterator::BatchedIterator};

    #[test]
    fn test_iter_chunk_mapped_vs_with_buf() {
        let mut rng = test_rng();

        for log_size in 1..=20 {
            let size = 1 << log_size;
            let input: Vec<Fr> = (0..size).map(|_| Fr::rand(&mut rng)).collect();
            let fv = FileVec::from_iter(input.clone());

            let expected = input
                .chunks_exact(2)
                .map(|c| c[0] + c[1])
                .collect::<Vec<_>>();

            let output_standard = fv.iter_chunk_mapped::<2, _, _>(|c| c[0] + c[1]).to_vec();

            let mut buf = vec![];
            let output_with_buf = fv
                .iter_chunk_mapped_with_buf::<2, _, _>(|c| c[0] + c[1], &mut buf)
                .to_vec();

            assert_eq!(output_standard, output_with_buf, "Mismatch for size {size}",);
            assert_eq!(expected, output_with_buf, "Mismatch for size {size}",);
        }
    }
}
