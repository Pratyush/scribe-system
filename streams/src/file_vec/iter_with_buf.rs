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
use std::fmt::Debug;

pub enum IterWithBuf<'a, T: SerializeRaw + DeserializeRaw + 'static> {
    File {
        file: InnerFile,
        buffer: BuffersRef<'a, T>,
    },
    Buffer {
        last: bool,
        buffer: &'a mut Vec<T>,
    },
}

impl<'a, T: SerializeRaw + DeserializeRaw> IterWithBuf<'a, T> {
    pub fn new_file_with_buf(file: InnerFile, buffer: &'a mut Vec<T>) -> Self {
        buffer.clear();
        let buffer = BuffersRef::new(buffer);
        Self::File { file, buffer }
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
    // We want to use double-buffering to avoid blocking the main thread while reading
    // from the file. In this way, we can process the data that we have read, while
    // the next batch is being read in the background.
    //
    // Our strategy is as follows. For the first read, we of course have to read it synchronously.
    // After that, however, we will spawn a thread that reads the next batch in the background.
    // To communicate the result of the I/O thread, we will use a channel.
    //
    #[inline]
    fn next_batch<'b>(&'b mut self) -> Option<Self::Batch<'b>> {
        match self {
            Self::File { file, buffer } => {
                buffer.clear();
                T::deserialize_raw_batch(&mut buffer.t_s, &mut buffer.bytes, BUFFER_SIZE, file)
                    .ok()?;
                if buffer.t_s.is_empty() {
                    return None;
                }
                Some(buffer.t_s.par_iter().copied().with_min_len(1 << 7))
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
        match self {
            Self::File { file, .. } => Some((file.len() - file.position()) / T::SIZE),
            Self::Buffer { buffer, last } => {
                if *last {
                    Some(0)
                } else {
                    Some(buffer.len())
                }
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
    fn test_iter_vs_with_buf() {
        let mut rng = test_rng();

        for log_size in 1..=20 {
            let size = 1 << log_size;
            let input: Vec<Fr> = (0..size).map(|_| Fr::rand(&mut rng)).collect();
            let fv = FileVec::from_iter(input.clone());

            let output_standard = fv.iter().to_vec();

            let mut buf = vec![];
            let output_with_buf = fv.iter_with_buf(&mut buf).to_vec();
            assert_eq!(
                output_standard.len(),
                output_with_buf.len(),
                "Length mismatch for size {size}",
            );
            assert_eq!(output_standard, output_with_buf, "Mismatch for size {size}",);
            assert_eq!(input, output_with_buf, "Mismatch for size {size}",);
        }
    }
}
