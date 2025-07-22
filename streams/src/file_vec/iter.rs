use crate::{
    BUFFER_SIZE,
    file_vec::{double_buffered::DoubleBufferedReader, backend::InnerFile}, iterator::{BatchedIterator, BatchedIteratorAssocTypes}, serialize::{DeserializeRaw, SerializeRaw}
};
use rayon::{iter::MinLen, prelude::*, vec::IntoIter};
use std::{fmt::Debug, marker::PhantomData};

pub enum Iter<'a, T: SerializeRaw + DeserializeRaw + 'static> {
    File {
        reader: DoubleBufferedReader<T>,
        lifetime: PhantomData<&'a T>,
    },
    Buffer {
        buffer: Vec<T>,
    },
}

impl<'a, T: SerializeRaw + DeserializeRaw> Iter<'a, T> {
    pub fn new_file(file: InnerFile) -> Self {
        let reader = DoubleBufferedReader::new(file);
        Self::File {
            reader,
            lifetime: PhantomData,
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
                reader, ..
            } => {
                let mut output_buffer = Vec::with_capacity(BUFFER_SIZE);
                if reader.is_first_read() {
                    // If this is the first read, we have to do it synchronously
                    if let Err(e) = reader.do_first_read() {
                        eprintln!("Error during first read: {e}");
                        return None;
                    }
                } else {
                    // If this is not the first read, we can use the prefetched batch
                    reader.get_prefetched_batch();
                }
                // Swap out the batch stored in the reader with the output buffer
                reader.swap_t_buffer(&mut output_buffer);
                
                if output_buffer.is_empty() {
                    // If the output buffer is empty, we have reached the end of the file
                    return None;
                }

                // 3. overlap I/O for the *next* batch
                reader.start_prefetch();

                Some(output_buffer.into_par_iter().with_min_len(1 << 7))

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
        match self {
            Self::File { reader, .. } => reader.len(),
            Self::Buffer { buffer } => Some(buffer.len()),
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

            let output_standard = fv.iter().to_vec();

            assert_eq!(output_standard, input, "Mismatch for size {size}",);
        }
    }
}
