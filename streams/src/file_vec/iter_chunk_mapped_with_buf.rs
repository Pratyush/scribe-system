use crate::{
    BUFFER_SIZE,
    file_vec::{backend::InnerFile, double_buffered::Buffers},
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
        buffer: Buffers<T>,
        file: InnerFile,
        lifetime: PhantomData<&'a T>,
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
        let buffer = Buffers::new();
        Self::File {
            file,
            buffer,
            lifetime: PhantomData,
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
                file,
                buffer,
                result_buffer,
                f,
                ..
            } => {
                buffer.clear();
                result_buffer.clear();

                T::deserialize_raw_batch(&mut buffer.t_s, &mut buffer.bytes, BUFFER_SIZE, file)
                    .ok()?;
                if buffer.t_s.is_empty() {
                    return None;
                }

                buffer
                    .t_s
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
            Self::File { file, .. } => Some((file.len() - file.position()) / (N * T::SIZE)),
            Self::Buffer { buffer, .. } => Some(buffer.len() / N),
        }
    }
}

#[cfg(test)]
mod tests {
    use ark_bls12_381::Fr;
    use ark_std::{UniformRand, test_rng};
    use rayon::prelude::*;

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

    #[test]
    fn test_multi_iter_chunk_mapped_to_file_vec() {
        let mut rng = test_rng();

        for log_size in 1..=20 {
            let size = 1 << log_size;
            let input: Vec<Fr> = (0..size).map(|_| Fr::rand(&mut rng)).collect();
            let fv1 = FileVec::from_iter(input.clone());
            let fv2 = FileVec::from_iter(input.clone());
            let fv_s = [fv1, fv2];

            let output_standard: Vec<_> = fv_s
                .par_iter()
                .map(|fv| {
                    fv.iter_chunk_mapped::<2, _, _>(|c| c[0] + c[1])
                        .to_file_vec()
                })
                .collect();

            let output_with_buf = fv_s
                .par_iter()
                .map(|fv| {
                    let mut buf = vec![];
                    fv.iter_chunk_mapped_with_buf::<2, _, _>(|c| c[0] + c[1], &mut buf)
                        .to_file_vec()
                })
                .collect::<Vec<_>>();
            for (out_std, out_buf) in output_standard.iter().zip(output_with_buf.iter()) {
                let vec_std = out_std.iter().to_vec();
                let vec_buf = out_buf.iter().to_vec();
                assert_eq!(
                    vec_std, vec_buf,
                    "Mismatch in FileVec outputs for size {size}"
                );
            }
        }
    }
}
