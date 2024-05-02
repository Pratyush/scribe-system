use ark_std::{borrow::Borrow, cfg_chunks_mut, cfg_iter, cfg_iter_mut, fmt};

#[cfg(feature = "parallel")]
use rayon::prelude::*;

pub const BUFFER_SIZE: usize = 1 << 17;

pub mod dense_mle;
pub use dense_mle::*;

pub mod file_vec;
pub mod iterator;

pub trait ReadWriteStream: Send + Sync + Sized {
    type Item: 'static + Send + Sync + fmt::Debug + fmt::Display;

    fn with_path<'a>(
        num_vars: usize,
        read_path: impl Into<Option<&'a str>>,
        write_path: impl Into<Option<&'a str>>,
    ) -> Self;

    fn new_single_stream(num_vars: usize, path: Option<&str>) -> Self;

    fn new_from_tempfile(num_vars: usize) -> Self;

    fn read_restart(&mut self);

    fn write_restart(&mut self);

    fn num_vars(&self) -> usize;

    fn swap_read_write(&mut self);

    fn new_read_stream(&mut self);

    fn read_next_unchecked(&mut self) -> Option<Self::Item>;

    fn read_next(&mut self) -> Option<Self::Item>;

    // Assumes that `buffer` is empty.
    fn read_to_buf(&mut self, buffer: &mut Vec<Self::Item>, buffer_size: usize) -> Option<()> {
        for _ in 0..buffer_size {
            match self.read_next() {
                Some(val) => buffer.push(val),
                None => break,
            }
        }
        if buffer.is_empty() {
            None
        } else {
            Some(())
        }
    }

    fn write_next(&mut self, field: impl Borrow<Self::Item>) -> Option<()>;

    fn write_next_unchecked(&mut self, field: impl Borrow<Self::Item>) -> Option<()>;

    fn write_buf(&mut self, buffer: &[impl Borrow<Self::Item>]) -> Option<()> {
        for val in buffer {
            self.write_next_unchecked(val.borrow())?;
        }
        Some(())
    }

    fn map_in_place(&mut self, f: impl Fn(&Self::Item) -> Self::Item + Sync) -> Option<()> {
        let mut buffer = Vec::with_capacity(BUFFER_SIZE);
        while self.read_to_buf(&mut buffer, BUFFER_SIZE).is_some() {
            cfg_iter_mut!(buffer).for_each(|val| *val = f(&*val));
            self.write_buf(&buffer)?;
            buffer.clear();
        }
        self.swap_read_write();
        self.read_restart();
        Some(())
    }

    fn fold_odd_even(
        &mut self,
        f: impl Fn(&Self::Item, &Self::Item) -> Self::Item + Sync,
    ) -> Option<()> {
        let mut buffer = Vec::with_capacity(BUFFER_SIZE);
        while self.read_to_buf(&mut buffer, BUFFER_SIZE).is_some() {
            cfg_chunks_mut!(buffer, 2).for_each(|vals| vals[0] = f(&vals[0], &vals[1]));
            self.write_buf(&buffer)?;
            buffer.clear();
        }

        self.swap_read_write();
        self.read_restart();
        Some(())
    }

    fn expand_odd_even(
        &mut self,
        f: impl Fn(&Self::Item) -> (Self::Item, Self::Item) + Sync,
    ) -> Option<()> {
        let mut buffer = Vec::with_capacity(2 * BUFFER_SIZE);
        while self.read_to_buf(&mut buffer, BUFFER_SIZE).is_some() {
            buffer = cfg_iter!(buffer)
                .flat_map(|val| {
                    let (f_0, f_1) = f(val);
                    [f_0, f_1]
                })
                .collect();
            self.write_buf(&buffer);
            buffer.clear();
        }

        self.swap_read_write();
        self.read_restart();
        Some(())
    }

    fn combine_in_place(
        &mut self,
        other: &mut Self,
        f: impl Fn(&Self::Item, &Self::Item) -> Self::Item + Sync,
    ) -> Option<()> {
        assert_eq!(self.num_vars(), other.num_vars());
        let mut buffer_1 = Vec::with_capacity(BUFFER_SIZE / 2);
        let mut buffer_2 = Vec::with_capacity(BUFFER_SIZE / 2);
        while self.read_to_buf(&mut buffer_1, BUFFER_SIZE / 2).is_some()
            && other.read_to_buf(&mut buffer_2, BUFFER_SIZE / 2).is_some()
        {
            cfg_iter_mut!(buffer_1)
                .zip(&buffer_2)
                .for_each(|(v1, v2)| *v1 = f(v1, v2));
            self.write_buf(&buffer_1)?;
            buffer_1.clear();
            buffer_2.clear();
        }
        self.swap_read_write();
        self.read_restart();
        other.read_restart();
        Some(())
    }

    fn combine_with(
        &mut self,
        other: &mut Self,
        f: impl Fn(&Self::Item, &Self::Item) -> Self::Item + Sync,
    ) -> Option<Self> {
        assert_eq!(self.num_vars(), other.num_vars());
        let mut result = Self::new_from_tempfile(self.num_vars());
        let mut buffer_1 = Vec::with_capacity(BUFFER_SIZE / 2);
        let mut buffer_2 = Vec::with_capacity(BUFFER_SIZE / 2);
        while self.read_to_buf(&mut buffer_1, BUFFER_SIZE / 2).is_some()
            && other.read_to_buf(&mut buffer_2, BUFFER_SIZE / 2).is_some()
        {
            cfg_iter_mut!(buffer_1)
                .zip(&buffer_2)
                .for_each(|(v1, v2)| *v1 = f(v1, v2));
            result.write_buf(&buffer_1)?;
            buffer_1.clear();
            buffer_2.clear();
        }
        result.swap_read_write();
        result.read_restart();
        self.read_restart();
        other.read_restart();
        Some(result)
    }

    /* fn combine_many_with(
        streams: &[&mut Self],
        f: impl Fn(&mut Self::Item, &Self::Item) + Sync
    ) -> Option<Self> {
        if streams.len() == 1 {
            return None // TODO return a copy of the stream
        }
        let num_vars = streams
            .first()
            .unwrap()
            .num_vars();
        let mut result = Self::new_from_tempfile(num_vars);
        let mut buffers = streams.iter().map(|_| Vec::with_capacity(BUFFER_SIZE)).collect::<Vec<_>>();
        while streams.iter().zip(&mut buffers).all(|(s, mut buf)| s.read_to_buf(&mut buf, BUFFER_SIZE).is_some()) {
            buffers.iter_mut().reduce(|acc, buf| {
                cfg_iter_mut!(acc).zip(buf).for_each(f);
                acc
            });
            result.write_buf(&buffers[0]);
            buffers.iter_mut().for_each(|buffer| buffer.clear());
        }
        result.swap_read_write();
        result.read_restart();
        streams.iter().for_each(|stream| stream.read_restart());
        Some(result)
    } */
}

/* #[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Fr;
    use ark_serialize::Write;
    use ark_std::rand::distributions::{Distribution, Standard};
    use ark_std::rand::rngs::StdRng;
    use ark_std::rand::SeedableRng;
    use ark_poly::DenseMultilinearExtension as DenseMLPoly;
    use std::time::Instant;

    // Helper to create a stream from a list of Fr values.
    fn create_stream_from_values(
        num_vars: usize,
        values: Vec<Fr>,
    ) -> DenseMLPolyStream<Fr> {
        let stream = DenseMLPolyStream::from_evaluations_vec(num_vars, values, None, None);
    }

    #[test]
    fn test_poly_functionality() {
        let mut rng = StdRng::seed_from_u64(42); // Fixed seed for reproducibility

        // Generate random Fr elements for our streams
        let values_stream_1: Vec<Fr> = (0..10).map(|_| Standard.sample(&mut rng)).collect();
        let values_stream_2: Vec<Fr> = (0..10).map(|_| Standard.sample(&mut rng)).collect();

        // Create streams from these values
        let stream_1 = create_stream_from_values(0, values_stream_1.clone());
        let stream_2 = create_stream_from_values(0, values_stream_2.clone());

        // Define products (coefficient, indices of streams)
        // Example: Add stream 1 and 2
        let products_add = vec![(Fr::ONE, vec![0]), (Fr::ONE, vec![1])];
        // Example: Multiply stream 1 and 2 (twice)
        let products_mul = vec![(Fr::from(3), vec![0, 1, 1])];

        // Use poly for addition and multiplication
        let result_add_stream = DenseMLPoly::poly(
            vec![stream_1.clone(), stream_2.clone()],
            products_add,
            None,
            None,
        );
        let result_mul_stream =
            DenseMLPoly::poly(vec![stream_1, stream_2], products_mul, None, None);

        // Manually calculate the expected results for addition and multiplication
        let expected_add = values_stream_1
            .iter()
            .zip(values_stream_2.iter())
            .map(|(a, b)| *a + *b)
            .collect::<Vec<Fr>>();
        let expected_mul = values_stream_1
            .iter()
            .zip(values_stream_2.iter())
            .map(|(a, b)| Fr::from(3) * *a * *b * *b)
            .collect::<Vec<Fr>>();

        // Compare results from poly with manually calculated results
        for (expected, mut result_stream) in [expected_add, expected_mul]
            .iter()
            .zip([result_add_stream, result_mul_stream].into_iter())
        {
            let mut result_values = Vec::new();
            for _ in 0..10 {
                // Assuming we know the expected length
                if let Some(val) = result_stream.read_next() {
                    result_values.push(val);
                }
            }
            assert_eq!(
                *expected, result_values,
                "The stream values do not match the expected values."
            );
        }
    }

    #[test]
    fn test_one_field() {
        let mut rng = StdRng::seed_from_u64(42); // Seed for reproducibility

        // Sample a random Fp<P, N> value
        let random_value: Fr = Standard.sample(&mut rng);

        // Create a temporary file for the stream
        let mut stream = DenseMLPolyStream::new_from_tempfile(0);

        // Write to stream
        stream.write_next(random_value).expect("Failed to write");
        stream.swap_read_write();

        // Seek to the beginning of the file for reading
        stream.read_restart();

        // Read from stream
        let read_value = stream.read_next().expect("Failed to read");
        assert_eq!(
            read_value, random_value,
            "The read value should match the written value"
        );
    }

    #[test]
    fn test_multiple_random_fields() {
        let mut rng = StdRng::seed_from_u64(42); // Seed for reproducibility

        // Generate 512 random Fr fields
        let mut written_values = Vec::new();
        for _ in 0..512 {
            let random_value: Fr = Standard.sample(&mut rng);
            written_values.push(random_value);
        }

        let mut stream = DenseMLPolyStream::new_from_tempfile(0);
        // Write all fields to the stream
        for value in &written_values {
            stream
                .write_next_unchecked(*value)
                .expect("Failed to write");
        }
        stream.swap_read_write();

        // Seek to the beginning of the file for reading
        stream.read_restart();

        // Read fields from the stream
        let mut read_values = Vec::new();
        for _ in 0..512 {
            if let Some(val) = stream.read_next() {
                read_values.push(val);
            }
        }

        // Compare written and read values
        assert_eq!(
            written_values, read_values,
            "Written and read values should match"
        );
    }

    #[test]
    fn benchmark_streaming_time() {
        let mut log_write_times = Vec::new();
        let mut log_seek_times = Vec::new();
        let mut log_read_times = Vec::new();

        for n in 1..=20 {
            let num_fields = 2usize.pow(n);
            let mut rng = StdRng::seed_from_u64(42); // Seed for reproducibility

            // Generate random fields
            let written_values: Vec<Fr> =
                (0..num_fields).map(|_| Standard.sample(&mut rng)).collect();

            let mut stream = DenseMLPolyStream::new_from_tempfile(0);

            // Measure write time
            let start_write = Instant::now();
            for value in &written_values {
                stream
                    .write_next_unchecked(*value)
                    .expect("Failed to write");
            }
            let duration_write = start_write.elapsed().as_secs_f64();
            log_write_times.push(duration_write.ln());

            // Measure seek time
            let start_seek = Instant::now();
            stream.swap_read_write();
            let duration_seek = start_seek.elapsed().as_secs_f64();
            log_seek_times.push(duration_seek.ln());

            // Measure read time
            let start_read = Instant::now();
            let mut read_values = Vec::new();
            for _ in 0..num_fields {
                if let Some(val) = stream.read_next() {
                    read_values.push(val);
                }
            }
            let duration_read = start_read.elapsed().as_secs_f64();
            log_read_times.push(duration_read.ln());

            // Compare written and read values
            assert_eq!(
                written_values, read_values,
                "Written and read values should match"
            );

            println!(
                "n = {}: Write Time: {:?}, Seek Time: {:?}, Read Time: {:?}",
                n, duration_write, duration_seek, duration_read
            );
        }
    }

    #[test]
    fn test_prod_multi() {
        // Create input streams
        let stream1 = DenseMLPolyStream::with_path(2, None, None);
        let stream2 = DenseMLPolyStream::with_path(2, None, None);
        let stream3 = DenseMLPolyStream::with_path(2, None, None);

        // Write values to input streams
        stream1.write_next_unchecked(Fr::from(2));
        stream1.write_next_unchecked(Fr::from(3));
        stream1.write_next_unchecked(Fr::from(4));
        stream1.swap_read_write();

        stream2.write_next_unchecked(Fr::from(5));
        stream2.write_next_unchecked(Fr::from(6));
        stream2.write_next_unchecked(Fr::from(7));
        stream2.swap_read_write();

        stream3.write_next_unchecked(Fr::from(8));
        stream3.write_next_unchecked(Fr::from(9));
        stream3.write_next_unchecked(Fr::from(10));
        stream3.swap_read_write();

        // Call the `prod_multi` function
        let result = DenseMLPolyStream::prod_multi(vec![stream1, stream2, stream3].as_slice()).unwrap();

        // Assert the expected result
        assert_eq!(result.read_next(), Some(Fr::from(2 * 5 * 8)));
        assert_eq!(result.read_next(), Some(Fr::from(3 * 6 * 9)));
        assert_eq!(result.read_next(), Some(Fr::from(4 * 7 * 10)));
        assert_eq!(result.read_next(), None);
    }

    #[test]
    fn test_batch_inversion_buffer() {
        // Create the from stream with values [1, 2, 3, 4, 5, 6, 7]
        let from_stream = DenseMLPolyStream::from_evaluations_vec(
            3,
            vec![
                Fr::from(1),
                Fr::from(2),
                Fr::from(3),
                Fr::from(4),
                Fr::from(5),
                Fr::from(6),
                Fr::from(7),
            ],
            None,
            None,
        );

        // Create the to stream and call the `batch_inversion_buffer` function with batch size 2
        let to_stream = from_stream.batch_inversion().unwrap();

        // Verify the values in the to stream
        let to_stream_values = {
            let mut values = Vec::new();
            while let Some(val) = to_stream.read_next() {
                values.push(val);
            }
            values
        };

        // Expected output: [1/1, 1/2, 1/3, 1/4, 1/5, 1/6, 1/7]
        (1..8).for_each(|i| {
            assert_eq!(
                to_stream_values[i - 1],
                Fr::from(i as u64).inverse().unwrap()
            );
        });
    }

    #[test]
    fn test_single_stream() {
        let mut stream = DenseMLPolyStream::new_single_stream(2, None);
        stream.write_next_unchecked(Fr::from(1));
        stream.write_next_unchecked(Fr::from(2));
        assert_eq!(stream.read_pointer.stream_position().unwrap(), 0);
        assert_eq!(stream.write_pointer.stream_position().unwrap(), 64);
        stream.write_restart();
        assert_eq!(stream.write_pointer.stream_position().unwrap(), 0);
        let elem_0 = stream.read_next();
        assert_eq!(elem_0, Some(Fr::from(1)));
        assert_eq!(stream.read_pointer.stream_position().unwrap(), 32);
        assert_eq!(stream.write_pointer.stream_position().unwrap(), 0);
        stream.write_next_unchecked(Fr::from(3));
        assert_eq!(stream.read_pointer.stream_position().unwrap(), 32);
        assert_eq!(stream.write_pointer.stream_position().unwrap(), 32);
        stream.write_restart();
        assert_eq!(stream.read_pointer.stream_position().unwrap(), 32);
        assert_eq!(stream.write_pointer.stream_position().unwrap(), 0);
        let elem_1 = stream.read_next();
        assert_eq!(elem_1, Some(Fr::from(2)));
        assert_eq!(stream.read_pointer.stream_position().unwrap(), 64);
        assert_eq!(stream.write_pointer.stream_position().unwrap(), 0);
    }

    #[test]
    fn test_single_stream_read_2() {
        let mut stream = DenseMLPolyStream::new_single_stream(2, None);
        stream.write_next_unchecked(Fr::from(1));
        stream.write_next_unchecked(Fr::from(2));

        // stream.write_pointer.stream_position().unwrap();
        stream.write_pointer.flush().unwrap();

        let elem_0 = stream.read_next_unchecked();
        assert_eq!(elem_0, Some(Fr::from(1)));
    }
}
 */
