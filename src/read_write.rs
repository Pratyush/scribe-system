use ark_ff::Field;
use core::marker::PhantomData;
use std::fs::File;
use std::io::{Seek, SeekFrom};
use tempfile::tempfile;

pub trait ReadStream: Send + Sync {
    type Item;

    fn read_next(&mut self) -> Option<Self::Item>;

    fn read_restart(&mut self);
}

pub trait WriteStream: Send + Sync {
    type Item;

    fn write_next(&mut self, field: Self::Item) -> Option<()>;

    fn write_restart(&mut self);
}

pub struct DenseMLPolyStream<F: Field> {
    read_pointer: File,
    write_pointer: File,
    pub num_vars: usize,
    num_evals: usize,
    f: PhantomData<F>,
}

impl<F: Field> ReadStream for DenseMLPolyStream<F> {
    type Item = F;

    fn read_next(&mut self) -> Option<F> {
        match F::deserialize_uncompressed_unchecked(&mut self.read_pointer) {
            Ok(field) => {
                // println!("Deserialized field: {:?}", field);
                Some(field)
            }
            Err(_) => {
                // Handle error or EOF
                None
            }
        }
    }

    fn read_restart(&mut self) {
        self.read_pointer
            .seek(SeekFrom::Start(0))
            .expect("Failed to seek");
    }
}

impl<F: Field> WriteStream for DenseMLPolyStream<F> {
    type Item = F;

    fn write_next(&mut self, field: Self::Item) -> Option<()> {
        match field.serialize_uncompressed(&mut self.write_pointer) {
            Ok(_) => {
                // println!("Field serialized and written successfully.");
                Some(())
            }
            Err(_) => {
                // Handle serialization or write error
                None
            }
        }
    }

    fn write_restart(&mut self) {
        self.write_pointer
            .seek(SeekFrom::Start(0))
            .expect("Failed to seek");
    }
}

impl<F: Field> DenseMLPolyStream<F> {
    pub fn new_from_path(num_vars: usize, num_evals: usize, read_path: &str, write_path: &str) -> Self {
        let read_pointer = File::open(read_path).unwrap();
        let write_pointer = File::create(write_path).unwrap();
        Self {
            read_pointer,
            write_pointer,
            num_vars,
            num_evals,
            f: PhantomData,
        }
    }

    pub fn new_from_tempfile(num_vars: usize, num_evals: usize) -> Self {
        let read_pointer = tempfile().expect("Failed to create a temporary file");
        let write_pointer = read_pointer.try_clone().expect("Failed to clone the file handle");
        Self {
            read_pointer,
            write_pointer,
            num_vars,
            num_evals,
            f: PhantomData,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::rand::distributions::{Distribution, Standard};
    use ark_std::rand::rngs::StdRng; // Using StdRng for the example
    use ark_std::rand::SeedableRng;
    use ark_test_curves::bls12_381::Fr;
    use std::marker::PhantomData;
    use std::time::Instant;
    use tempfile::tempfile; // Import Rng trait and SeedableRng for deterministic rng in tests

    #[test]
    fn test_one_field() {
        let mut rng = StdRng::seed_from_u64(42); // Seed for reproducibility

        // Sample a random Fp<P, N> value
        let random_value: Fr = Standard.sample(&mut rng);

        // Create a temporary file for the stream
        let file = tempfile().expect("Failed to create a temporary file");
        let file_clone = file.try_clone().expect("Failed to clone the file handle");

        let mut stream = DenseMLPolyStream {
            read_pointer: file,
            write_pointer: file_clone,
            num_vars: 0,  // example value
            num_evals: 0, // example value
            f: PhantomData,
        };

        // Write to stream
        stream.write_next(random_value).expect("Failed to write");

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

        // Create a temporary file for the stream
        let file = tempfile().expect("Failed to create a temporary file");
        let file_clone = file.try_clone().expect("Failed to clone the file handle");

        let mut stream = DenseMLPolyStream {
            read_pointer: file,
            write_pointer: file_clone,
            num_vars: 0,  // example value
            num_evals: 0, // example value
            f: PhantomData,
        };

        // Write all fields to the stream
        for value in &written_values {
            stream.write_next(*value).expect("Failed to write");
        }

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

            // Create a temporary file for the stream
            let file = tempfile().expect("Failed to create a temporary file");
            let file_clone = file.try_clone().expect("Failed to clone the file handle");

            let mut stream = DenseMLPolyStream {
                read_pointer: file,
                write_pointer: file_clone,
                num_vars: 0,  // example value
                num_evals: 0, // example value
                f: PhantomData,
            };

            // Measure write time
            let start_write = Instant::now();
            for value in &written_values {
                stream.write_next(*value).expect("Failed to write");
            }
            let duration_write = start_write.elapsed().as_secs_f64();
            log_write_times.push(duration_write.ln());

            // Measure seek time
            let start_seek = Instant::now();
            stream.read_restart();
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
