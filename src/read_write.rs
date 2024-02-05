use ark_ff::BigInteger;
use ark_ff::Field;
use ark_ff::PrimeField;
use ark_serialize::Read;
use ark_std::end_timer;
use ark_std::rand::RngCore;
use ark_std::start_timer;
use core::marker::PhantomData;
use std::fs::read;
use std::io::Seek;
use std::sync::Arc;
use std::sync::Mutex;
use std::{
    fs::File,
    io::{BufReader, BufWriter},
};
use tempfile::tempfile;

pub trait ReadWriteStream: Send + Sync {
    type Item;

    fn new(num_vars: usize, read_path: Option<&str>, write_path: Option<&str>) -> Self;

    fn read_next(&mut self) -> Option<Self::Item>;

    fn read_next_unchecked(&mut self) -> Option<Self::Item>;

    fn read_restart(&mut self);

    fn write_next(&mut self, field: Self::Item) -> Option<()>;

    fn write_next_unchecked(&mut self, field: Self::Item) -> Option<()>;

    fn write_restart(&mut self);

    fn num_vars(&self) -> usize;

    fn swap_read_write(&mut self);
}

#[derive(Debug)]
pub struct DenseMLPolyStream<F: Field> {
    pub read_pointer: BufReader<File>,
    write_pointer: BufWriter<File>,
    pub num_vars: usize,
    f: PhantomData<F>,
}

impl<F: Field> ReadWriteStream for DenseMLPolyStream<F> {
    type Item = F;

    fn new(num_vars: usize, read_path: Option<&str>, write_path: Option<&str>) -> Self {
        if let (Some(read_path), Some(write_path)) = (read_path, write_path) {
            Self::new_from_path(num_vars, read_path, write_path)
        } else {
            Self::new_from_tempfile(num_vars)
        }
    }

    fn read_next(&mut self) -> Option<F> {
        #[cfg(debug_assertions)]
        {
            // Get current positions of read_pointer and write_pointer
            let read_pos = self.read_pointer.stream_position().unwrap();
            let write_pos = self.write_pointer.stream_position().unwrap();

            // Check if read position is ahead of write position and print error if not
            if read_pos < write_pos {
                println!("Read position: {}", read_pos);
                println!("Write position: {}", write_pos);
                eprintln!("`read_next` Error: Read position is not ahead of write position.");
                return None;
            }
        }

        // Proceed with deserialization
        F::deserialize_uncompressed_unchecked(&mut self.read_pointer).ok()
    }

    // used for creating eq_x_r, recursively building which requires reading one element while writing two elements
    fn read_next_unchecked(&mut self) -> Option<Self::Item> {
        F::deserialize_uncompressed_unchecked(&mut self.read_pointer).ok()
    }

    fn read_restart(&mut self) {
        self.read_pointer.rewind().expect("Failed to seek");
    }

    fn write_next(&mut self, field: Self::Item) -> Option<()> {
        #[cfg(debug_assertions)]
        {
            // Get current positions of read_pointer and write_pointer
            let read_pos = self.read_pointer.stream_position().unwrap();
            let write_pos = self.write_pointer.stream_position().unwrap();

            // Check if read position is ahead of write position and print error if not
            if read_pos < write_pos {
                println!("Read position: {}", read_pos);
                println!("Write position: {}", write_pos);
                eprintln!("`write_next` Error: Read position is not ahead of write position.");
                return None;
            }
        }

        // Proceed with serialization
        field.serialize_uncompressed(&mut self.write_pointer).ok()
    }

    // Used for testing purpose when writing to a random stream without checking read and write pointer positions
    fn write_next_unchecked(&mut self, field: F) -> Option<()> {
        field.serialize_uncompressed(&mut self.write_pointer).ok()
    }

    fn write_restart(&mut self) {
        self.write_pointer.rewind().expect("Failed to seek");
    }

    fn num_vars(&self) -> usize {
        self.num_vars
    }

    fn swap_read_write(&mut self) {
        // Truncate the read file to the current position
        let cur_read_pos = self.read_pointer.stream_position().unwrap();
        self.read_pointer.get_ref().set_len(cur_read_pos).unwrap();
        // Seek to the beginning of the file for reading
        self.read_restart();

        // Truncate the write file to the current position
        let cur_write_pos = self.write_pointer.stream_position().unwrap();
        self.write_pointer.get_ref().set_len(cur_write_pos).unwrap();
        // Seek to the beginning of the file for writing
        self.write_restart();

        // Swap the read and write pointers, only if current write pointer position isn't zero, while read should always be ahead of write
        if cur_write_pos != 0 {
            std::mem::swap(self.read_pointer.get_mut(), self.write_pointer.get_mut());
        }
    }
}

impl<F: Field> DenseMLPolyStream<F> {
    pub fn new_from_path(num_vars: usize, read_path: &str, write_path: &str) -> Self {
        let read_pointer = BufReader::new(File::open(read_path).unwrap());
        let write_pointer = BufWriter::new(File::create(write_path).unwrap());
        Self {
            read_pointer,
            write_pointer,
            num_vars,
            f: PhantomData,
        }
    }

    pub fn new_from_tempfile(num_vars: usize) -> Self {
        let read_pointer = BufReader::new(tempfile().expect("Failed to create a temporary file"));
        let write_pointer = BufWriter::new(tempfile().expect("Failed to create a temporary file"));
        Self {
            read_pointer,
            write_pointer,
            num_vars,
            f: PhantomData,
        }
    }

    pub fn from_evaluations_vec(
        num_vars: usize,
        evaluations: Vec<F>,
        read_path: Option<&str>,
        write_path: Option<&str>,
    ) -> Self {
        let mut stream = Self::new(num_vars, read_path, write_path);
        for e in evaluations {
            stream.write_next_unchecked(e).expect("Failed to write");
        }
        stream.swap_read_write();
        stream
    }

    pub fn decrement_num_vars(&mut self) {
        if self.num_vars <= 0 {
            panic!("Cannot decrement num_vars below 0");
        }
        self.num_vars -= 1;
    }

    // store the result in a tempfile; might provide an option for writing to a new file path instead
    // original version spits out a new poly, while we modify the original poly (stream)
    pub fn fix_variables(&mut self, partial_point: &[F]) {
        assert!(
            partial_point.len() <= self.num_vars,
            "invalid size of partial point"
        );

        // println!("fix_variables challenge: {:?}", partial_point);
        // let mut poly = self.evaluations.to_vec();
        // let nv = dbg!(self.num_vars);
        // let dim = dbg!(partial_point.len());
        // let one = F::one();

        // let mut return_stream = Self::new_from_tempfile(self.num_vars - partial_point.len());

        // evaluate single variable of partial point from left to right
        // for i in 1..dim + 1 {
        //     let r = partial_point[i - 1];
        //     let one = F::one();

        //     if i == dim {
        //         while let (Some(even), Some(odd)) = (self.read_next(), self.read_next()) {
        //             return_stream.write_next(even * (one - r) + odd * r);
        //         }
        //     } else {
        //         while let (Some(even), Some(odd)) = (self.read_next(), self.read_next()) {
        //             self.write_next(even * (one - r) + odd * r);
        //         }
        //         self.swap_read_write();
        //     }
        // }

        // return_stream

        // evaluate single variable of partial point from left to right
        // self.read_restart();
        for &r in partial_point {
            // if self.read_next().is_none() {
            //     println!("Failed to read");
            // }
            while let (Some(even), Some(odd)) = (self.read_next(), self.read_next()) {
                // println!("fix_variables even: {}", even);
                // println!("fix_variables odd: {}", odd);
                self.write_next(even + r * (odd - even));
            }
            self.decrement_num_vars();
            self.swap_read_write();
        }
    }

    // Evaluate at a specific point to one field element
    pub fn evaluate(&mut self, point: &[F]) -> Option<F> {
        if point.len() == self.num_vars {
            // dbg!(self.read_pointer.stream_position().unwrap());
            self.fix_variables(point);

            // println!("===post evaluation===");
            // // print all elements of read stream and write stream
            // self.read_restart();
            // self.write_restart();
            // while let Some(read) = self.read_next() {
            //     println!("read: {}", read);
            // }
            // self.swap_read_write();
            // while let Some(write) = self.read_next() {
            //     println!("write: {}", write);
            // }
            // println!("===post evaluation===");
            // self.swap_read_write();

            Some(self.read_next().expect("Failed to read"))
        } else {
            None
        }
    }

    pub fn rand<R: RngCore>(num_vars: usize, rng: &mut R) -> Self {
        Self::from_evaluations_vec(
            num_vars,
            (0..(1 << num_vars)).map(|_| F::rand(rng)).collect(),
            None,
            None,
        )
    }

    // create a vector of random field elements for each stream
    // then load the vector into the stream
    // vectosr are loaded in memory so this might not be scalable
    pub fn random_mle_list<R: RngCore>(
        nv: usize,
        degree: usize,
        rng: &mut R,
        read_path: Option<&str>,
        write_path: Option<&str>,
    ) -> (Vec<Arc<Mutex<DenseMLPolyStream<F>>>>, F) {
        let start = start_timer!(|| "sample random mle list");
        let mut multiplicands = Vec::with_capacity(degree);
        for _ in 0..degree {
            multiplicands.push(Vec::with_capacity(1 << nv))
        }
        let mut sum = F::zero();

        for _ in 0..(1 << nv) {
            let mut product = F::one();

            for e in multiplicands.iter_mut() {
                let val = F::rand(rng);
                e.push(val);
                // println!("val: {}", val);
                product *= val;
            }
            sum += product;
        }

        // println!("length of multiplicands: {:?}", multiplicands.len());

        // println!("length of stream: {:?}", multiplicands[0].len());

        let list = multiplicands
            .into_iter()
            .map(|x| {
                Arc::new(Mutex::new(DenseMLPolyStream::from_evaluations_vec(
                    nv, x, read_path, write_path,
                )))
            })
            .collect();

        end_timer!(start);
        (list, sum)
    }

    // Build a randomize list of mle-s whose sum is zero.
    // loaded to streams from vectors and therefore is for testing purpose only.
    // for multiple multiplicands (streams), the first stream is zero everywhere while the rest of the streams are arbitrary.
    pub fn random_zero_mle_list<R: RngCore>(
        nv: usize,
        degree: usize,
        rng: &mut R,
    ) -> Vec<Arc<Mutex<DenseMLPolyStream<F>>>> {
        let start = start_timer!(|| "sample random zero mle list");

        let mut multiplicands = Vec::with_capacity(degree);
        for _ in 0..degree {
            multiplicands.push(Vec::with_capacity(1 << nv))
        }
        for _ in 0..(1 << nv) {
            multiplicands[0].push(F::zero());
            for e in multiplicands.iter_mut().skip(1) {
                e.push(F::rand(rng));
            }
        }

        let list = multiplicands
            .into_iter()
            .map(|x| {
                Arc::new(Mutex::new(DenseMLPolyStream::from_evaluations_vec(
                    nv, x, None, None,
                )))
            })
            .collect();

        end_timer!(start);
        list
    }
}

// currently not very efficient as it reads and writes one field element at a time
// in the future we could optimize by:
// 1. read multiple streams in parallel
// 2. read off multiple field elements to a memory buffer
// to implement these, we also need a memory usage threshold to upper bound the # of streams in parallel times the memory buffer size for each stream
pub trait DenseMLPoly<F: Field>: ReadWriteStream<Item = F> {
    fn add(mut self, mut other: Self, read_path: Option<&str>, write_path: Option<&str>) -> Self
    where
        Self: Sized,
    {
        // Create a new stream for the result.
        let mut result_stream = Self::new(self.num_vars(), read_path, write_path);

        // Restart both input streams to ensure they are read from the beginning
        self.read_restart();
        other.read_restart();

        while let (Some(a), Some(b)) = (self.read_next(), other.read_next()) {
            // Perform addition and write the result to the new stream
            result_stream.write_next_unchecked(a + b);
        }

        result_stream
    }

    fn prod(mut self, mut other: Self, read_path: Option<&str>, write_path: Option<&str>) -> Self
    where
        Self: Sized,
    {
        // Create a new stream for the result.
        let mut result_stream = Self::new(self.num_vars(), read_path, write_path);

        // Restart both input streams to ensure they are read from the beginning
        self.read_restart();
        other.read_restart();

        while let (Some(a), Some(b)) = (self.read_next(), other.read_next()) {
            // Perform multiplication and write the result to the new stream
            result_stream.write_next_unchecked(a * b);
        }

        result_stream
    }

    // not super efficient as streams are sequentially accessed and read one field element only
    // used temporary variable to store the current field element for each stream, to take care of scenarios where a stream adds to itself
    fn add_multi(
        streams: Vec<Arc<Mutex<Self>>>,
        read_path: Option<&str>,
        write_path: Option<&str>,
    ) -> Self
    where
        Self: Sized,
    {
        let num_vars = streams
            .first()
            .expect("Streams cannot be empty")
            .lock()
            .expect("Failed to lock stream")
            .num_vars();
        let mut result_stream = Self::new(num_vars, read_path, write_path);

        loop {
            let mut values = Vec::new(); // Temporarily store values for this iteration
            let mut end_of_streams = false;

            for stream in &streams {
                let value = stream.lock().expect("Failed to lock stream").read_next();
                match value {
                    Some(val) => values.push(val),
                    None => {
                        end_of_streams = true;
                        break;
                    }
                }
            }

            if end_of_streams {
                break;
            }

            let sum = values.iter().fold(F::zero(), |acc, &val| acc + val); // Perform addition
            result_stream.write_next_unchecked(sum);
        }

        result_stream
    }

    fn prod_multi(
        streams: Vec<Arc<Mutex<Self>>>,
        read_path: Option<&str>,
        write_path: Option<&str>,
    ) -> Self
    where
        Self: Sized,
    {
        let num_vars = streams
            .first()
            .expect("Streams cannot be empty")
            .lock()
            .expect("Failed to lock stream")
            .num_vars();
        let mut result_stream = Self::new(num_vars, read_path, write_path);

        loop {
            let mut values = Vec::new(); // Temporarily store values for this iteration
            let mut end_of_streams = false;

            for stream in &streams {
                let value = stream.lock().expect("Failed to lock stream").read_next();
                match value {
                    Some(val) => values.push(val),
                    None => {
                        end_of_streams = true;
                        break;
                    }
                }
            }

            if end_of_streams {
                break;
            }

            let prod = values.iter().fold(F::one(), |acc, &val| acc * val); // Perform multiplication
            result_stream.write_next_unchecked(prod);
        }

        result_stream
    }

    fn poly(
        streams: Vec<Arc<Mutex<Self>>>,
        products: Vec<(F, Vec<usize>)>,
        read_path: Option<&str>,
        write_path: Option<&str>,
    ) -> Self
    where
        Self: Sized,
    {
        if streams.is_empty() {
            panic!("Streams cannot be empty");
        }

        let num_vars = streams.first().unwrap().lock().unwrap().num_vars();
        let mut result_stream = Self::new(num_vars, read_path, write_path);

        // Ensure all streams start from the beginning
        for stream in &streams {
            stream.lock().unwrap().read_restart();
        }

        let mut current_values: Vec<Option<F>> = vec![None; streams.len()];

        // Initially populate current_values with the first value from each stream
        for (i, stream) in streams.iter().enumerate() {
            let value = stream.lock().unwrap().read_next();
            current_values[i] = value;
        }

        // Loop until the first stream is exhausted
        while let Some(Some(_)) = current_values.first() {
            let mut sum = F::zero(); // Reset sum for each new value from the first stream

            // Check if any stream (other than the first) required for the current operation is exhausted
            if products
                .iter()
                .any(|(_, indices)| indices.iter().any(|&i| current_values[i].is_none()))
            {
                panic!("Error: One or more required streams are exhausted before the first stream");
            }

            // For each product term, calculate its value
            for (coefficient, indices) in &products {
                let mut product_value = *coefficient; // Start with the coefficient

                // Multiply with the current value for each specified stream
                for &index in indices {
                    if let Some(value) = current_values[index] {
                        product_value = product_value * value;
                    } else {
                        // This should not happen due to the earlier panic check, but it's here for robustness
                        panic!("Unexpectedly encountered a None value in current_values");
                    }
                }

                // Add the product to the sum
                sum = sum + product_value;
            }

            // Write the sum (resulting from the current set of stream values) into the result stream
            result_stream.write_next_unchecked(sum);

            // Update current_values for the next iteration
            for (value, stream) in current_values.iter_mut().zip(streams.iter()) {
                *value = stream.lock().unwrap().read_next();
            }

            // If the first stream is now exhausted, break the loop
            if current_values.first().unwrap().is_none() {
                break;
            }
        }

        result_stream.swap_read_write();

        result_stream
    }

    // fn hadamard(self, other: impl DenseMLPoly<F>) -> impl DenseMLPoly<F>;
}

impl<F: Field> DenseMLPoly<F> for DenseMLPolyStream<F> {}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::rand::distributions::{Distribution, Standard};
    use ark_std::rand::rngs::StdRng; // Using StdRng for the example
    use ark_std::rand::SeedableRng;
    use ark_test_curves::bls12_381::Fr;
    use std::time::Instant;

    // Helper to create a stream from a list of Fr values.
    fn create_stream_from_values(
        num_vars: usize,
        values: Vec<Fr>,
    ) -> Arc<Mutex<DenseMLPolyStream<Fr>>> {
        let stream = DenseMLPolyStream::from_evaluations_vec(num_vars, values, None, None);
        Arc::new(Mutex::new(stream))
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
            stream.write_next(*value).expect("Failed to write");
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
                stream.write_next(*value).expect("Failed to write");
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
}
