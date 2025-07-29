use crate::{
    BUFFER_SIZE,
    file_vec::{backend::InnerFile, double_buffered::BuffersRef},
    iterator::{BatchedIterator, BatchedIteratorAssocTypes},
    serialize::{DeserializeRaw, SerializeRaw},
};
use rayon::{
    iter::{Copied, MinLen},
    prelude::*,
    slice::Iter,
};

pub enum ArrayChunksWithBuf<'a, T, const N: usize>
where
    T: 'static + SerializeRaw + DeserializeRaw + Send + Sync + Copy,
{
    File {
        file: InnerFile,
        buffer: BuffersRef<'a, [T; N]>,
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
    pub fn new_file(file: InnerFile, buf: &'a mut Vec<[T; N]>) -> Self {
        assert!(N > 0, "N must be greater than 0");
        assert!(BUFFER_SIZE % N == 0, "BUFFER_SIZE must be divisible by N");
        assert_eq!(std::mem::align_of::<[T; N]>(), std::mem::align_of::<T>());
        assert_eq!(std::mem::size_of::<[T; N]>(), N * std::mem::size_of::<T>());

        buf.clear();
        let buffer = BuffersRef::new(buf);

        Self::File { file, buffer }
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
            Self::File { file, buffer } => {
                buffer.clear();
                <[T; N]>::deserialize_raw_batch(
                    &mut buffer.t_s,
                    &mut buffer.bytes,
                    BUFFER_SIZE,
                    file,
                )
                .ok()?;
                if buffer.t_s.is_empty() {
                    return None;
                }

                Some(buffer.t_s.par_iter().copied().with_min_len(1 << 10))
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
        match self {
            Self::File { file, .. } => Some((file.len() - file.position()) / (N * T::SIZE)),
            Self::Buffer { buffer, last } => {
                let len = if *last { 0 } else { buffer.len() };
                Some(len / N)
            },
        }
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
