use crate::{
    file_vec::{double_buffered::DoubleBufferedReader, backend::InnerFile}, iterator::{BatchedIterator, BatchedIteratorAssocTypes}, serialize::{DeserializeRaw, SerializeRaw}
};
use rayon::{
    iter::{Copied, MinLen},
    prelude::*,
    slice::Iter,
};
use std::fmt::Debug;

pub enum IterWithBuf<'a, T: SerializeRaw + DeserializeRaw + 'static> {
    File {
        reader:   DoubleBufferedReader<T>,
        output_buffer: &'a mut Vec<T>,
    },
    Buffer {
        last: bool,
        buffer: &'a mut Vec<T>,
    },
}

impl<'a, T: SerializeRaw + DeserializeRaw> IterWithBuf<'a, T> {
    pub fn new_file_with_buf(file: InnerFile, buffer: &'a mut Vec<T>) -> Self {
        let reader = DoubleBufferedReader::new(file);
        buffer.clear();
        Self::File {
            reader, output_buffer: buffer,
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
            Self::File {
                reader,
                output_buffer,
            } => {
                output_buffer.clear();
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
                reader.swap_t_buffer(output_buffer);
                
                if output_buffer.is_empty() {
                    // If the output buffer is empty, we have reached the end of the file
                    return None;
                }

                // 3. overlap I/O for the *next* batch
                reader.start_prefetch();

                Some(output_buffer.par_iter().copied().with_min_len(1 << 7))
                
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
            Self::File {reader, .. } => reader.len(),
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
            assert_eq!(output_standard.len(), output_with_buf.len(), "Length mismatch for size {size}",);
            assert_eq!(output_standard, output_with_buf, "Mismatch for size {size}",);
            assert_eq!(input, output_with_buf, "Mismatch for size {size}",);
        }
    }
}
