use crate::{
    BUFFER_SIZE,
    file_vec::{backend::InnerFile, double_buffered::Buffers},
    iterator::{BatchedIterator, BatchedIteratorAssocTypes},
    serialize::{DeserializeRaw, SerializeRaw},
};
use rayon::{prelude::*, vec::IntoIter};
use std::marker::PhantomData;

pub enum IterChunkMapped<'a, T, U, F, const N: usize>
where
    T: 'static + SerializeRaw + DeserializeRaw + Send + Sync + Copy,
    U: 'static + SerializeRaw + DeserializeRaw + Send + Sync + Copy,
    F: for<'b> Fn(&[T]) -> U + Sync + Send,
{
    File {
        buffer: Buffers<T>,
        file: InnerFile,
        lifetime: PhantomData<&'a T>,
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
        assert!(N > 0, "N must be greater than 0");
        assert!(BUFFER_SIZE % N == 0, "BUFFER_SIZE must be divisible by N");
        assert_eq!(std::mem::align_of::<[T; N]>(), std::mem::align_of::<T>());
        assert_eq!(std::mem::size_of::<[T; N]>(), N * std::mem::size_of::<T>());
        let buffer = Buffers::new();
        Self::File {
            buffer,
            file,
            lifetime: PhantomData,
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

impl<'a, T, U, F, const N: usize> BatchedIteratorAssocTypes for IterChunkMapped<'a, T, U, F, N>
where
    T: 'static + SerializeRaw + DeserializeRaw + Send + Sync + Copy,
    U: 'static + SerializeRaw + DeserializeRaw + Send + Sync + Copy,
    F: for<'b> Fn(&[T]) -> U + Sync + Send,
{
    type Item = U;
    type Batch<'b> = IntoIter<U>;
}

impl<'a, T, U, F, const N: usize> BatchedIterator for IterChunkMapped<'a, T, U, F, N>
where
    T: 'static + SerializeRaw + DeserializeRaw + Send + Sync + Copy,
    U: 'static + SerializeRaw + DeserializeRaw + Send + Sync + Copy,
    F: for<'b> Fn(&[T]) -> U + Sync + Send,
{
    #[inline]
    fn next_batch<'b>(&'b mut self) -> Option<Self::Batch<'b>> {
        match self {
            Self::File {
                file, buffer, f, ..
            } => {
                buffer.clear();
                T::deserialize_raw_batch(&mut buffer.t_s, &mut buffer.bytes, BUFFER_SIZE, file)
                    .ok()?;

                if buffer.t_s.is_empty() {
                    return None;
                }
                let output = buffer
                    .t_s
                    .par_chunks_exact(N)
                    .map(&*f)
                    .with_min_len(1 << 10)
                    .collect::<Vec<_>>()
                    .into_par_iter();
                Some(output)
            },
            Self::Buffer { buffer, f } => {
                if buffer.is_empty() {
                    None
                } else {
                    Some(
                        std::mem::take(buffer)
                            .par_chunks_exact(N)
                            .map(&*f)
                            .with_min_len(1 << 7)
                            .collect::<Vec<_>>()
                            .into_par_iter(),
                    )
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

    use crate::{file_vec::FileVec, iterator::BatchedIterator};

    #[test]
    fn test_iter_chunk_mapped() {
        let mut rng = test_rng();

        for log_size in 1..=20 {
            let size = 1 << log_size;
            let input: Vec<Fr> = (0..size).map(|_| Fr::rand(&mut rng)).collect();
            let fv = FileVec::from_iter(input.clone());

            let expected = input
                .chunks_exact(2)
                .map(|c| c[0] + c[1])
                .collect::<Vec<_>>();

            let output = fv.iter_chunk_mapped::<2, _, _>(|c| c[0] + c[1]).to_vec();

            assert_eq!(expected, output, "Mismatch for size {size}",);
        }
    }
}
