use crate::{
    BUFFER_SIZE,
    file_vec::{backend::InnerFile, double_buffered::DoubleBufferedReader},
    iterator::BatchedIterator,
    iterator::BatchedIteratorAssocTypes,
    serialize::{DeserializeRaw, SerializeRaw},
};
use rayon::{iter::MinLen, prelude::*, vec::IntoIter};
use std::marker::PhantomData;

pub enum ArrayChunks<'a, T, const N: usize>
where
    T: 'static + SerializeRaw + DeserializeRaw + Send + Sync + Copy,
{
    File {
        reader: DoubleBufferedReader<[T; N]>,
        lifetime: PhantomData<&'a T>,
        t_n_buffer: Vec<[T; N]>,
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

        let reader = DoubleBufferedReader::new(file);
        Self::File {
            reader,
            lifetime: PhantomData,
            t_n_buffer: Vec::with_capacity(BUFFER_SIZE),
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

    type Batch<'b> = MinLen<IntoIter<[T; N]>>;
}

impl<'a, T, const N: usize> BatchedIterator for ArrayChunks<'a, T, N>
where
    T: 'static + SerializeRaw + DeserializeRaw + Send + Sync + Copy,
{
    #[inline]
    fn next_batch<'b>(&'b mut self) -> Option<Self::Batch<'b>> {
        match self {
            Self::File {
                reader, t_n_buffer, ..
            } => {
                t_n_buffer.clear();

                if reader.is_first_read() {
                    reader.do_first_read().ok()?;
                } else {
                    reader.harvest();
                }

                reader.read_output(t_n_buffer);

                if t_n_buffer.is_empty() {
                    return None;
                }
                reader.start_prefetches();

                Some(t_n_buffer.to_vec().into_par_iter().with_min_len(1 << 10))
            },
            Self::Buffer { buffer } => {
                if buffer.is_empty() {
                    None
                } else {
                    Some(
                        std::mem::take(buffer)
                            .par_chunks(N)
                            .map(|chunk| <[T; N]>::try_from(chunk).unwrap())
                            .with_min_len(1 << 10)
                            .collect::<Vec<_>>()
                            .into_par_iter()
                            .with_min_len(1 << 10),
                    )
                }
            },
        }
    }

    fn len(&self) -> Option<usize> {
        match self {
            Self::File { reader, .. } => reader.len(),
            Self::Buffer { buffer } => Some(buffer.len() / N),
        }
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
