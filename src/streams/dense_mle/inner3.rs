use ark_ff::batch_inversion;
use ark_ff::Field;
use ark_ff::PrimeField;
use ark_std::end_timer;
use ark_std::rand::RngCore;
use ark_std::start_timer;
use core::marker::PhantomData;

use std::{borrow::Borrow, io::Seek};
use std::sync::Arc;
use std::sync::Mutex;
use ark_std::{
    fs::File,
    io::{BufReader, BufWriter},
};
use tempfile::tempfile;
use tempfile::NamedTempFile;

use crate::{hyperplonk::arithmetic::errors::ArithErrors, streams::{ReadWriteStream, BUFFER_SIZE}};



#[derive(Debug)]
pub struct Inner<F: Field> {
    pub read_pointer: BufReader<File>,
    pub write_pointer: BufWriter<File>,
    pub num_vars: usize,
    f: PhantomData<F>,
}

impl<F: Field> ReadWriteStream for Inner<F> {
    type Item = F;

    fn with_path<'a>(num_vars: usize, read_path: impl Into<Option<&'a str>>, write_path: impl Into<Option<&'a str>>) -> Self {
        if let (Some(read_path), Some(write_path)) = (read_path.into(), write_path.into()) {
            Self::new_from_path(num_vars, read_path, write_path)
        } else {
            Self::new_from_tempfile(num_vars)
        }
    }
    
    fn new_from_tempfile(num_vars: usize) -> Self {
        let read_pointer = BufReader::with_capacity(
            1 << 20,
            tempfile().expect("Failed to create a temporary file"),
        );
        let write_pointer = BufWriter::with_capacity(
            1 << 20,
            tempfile().expect("Failed to create a temporary file"),
        );
        Inner {
            read_pointer,
            write_pointer,
            num_vars,
            f: PhantomData,
        }
    }

    fn new_single_stream(num_vars: usize, path: Option<&str>) -> Self {
        if let Some(path) = path {
            Self::new_from_path_single_stream(num_vars, path)
        } else {
            Self::new_from_tempfile_single_stream(num_vars)
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
                eprintln!("`read_next` Error: Read position ({read_pos}) is not ahead of write position ({write_pos}).");
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


    fn write_next(&mut self, field: impl Borrow<Self::Item>) -> Option<()> {
        #[cfg(debug_assertions)]
        {
            // Get current positions of read_pointer and write_pointer
            let read_pos = self.read_pointer.stream_position().unwrap();
            let write_pos = self.write_pointer.stream_position().unwrap();

            // Check if read position is ahead of write position and print error if not
            if read_pos < write_pos {
                eprintln!("`write_next` Error: Read position ({read_pos}) is not ahead of write position ({write_pos}).");
                return None;
            }
        }

        // Proceed with serialization
        field.borrow().serialize_uncompressed(&mut self.write_pointer).ok()
    }

    // Used for testing purpose when writing to a random stream without checking read and write pointer positions
    fn write_next_unchecked(&mut self, field: impl Borrow<Self::Item>) -> Option<()> {
        field.borrow().serialize_uncompressed(&mut self.write_pointer).ok()
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

    fn new_read_stream(&mut self) {
        self.read_pointer = BufReader::with_capacity(
            1 << 20,
            tempfile().expect("Failed to create a temporary file"),
        );
    }
}

impl<F: Field> Inner<F> {
    pub fn new_from_path(num_vars: usize, read_path: &str, write_path: &str) -> Self {
        let read_pointer = BufReader::with_capacity(1 << 20, File::create(read_path).unwrap());
        let write_pointer = BufWriter::with_capacity(1 << 20, File::create(write_path).unwrap());
        Self {
            read_pointer,
            write_pointer,
            num_vars,
            f: PhantomData,
        }
    }

    pub fn new_from_path_single_stream(num_vars: usize, path: &str) -> Self {
        let file_read = File::create(path).unwrap();
        let file_write = File::open(path).unwrap();
        let read_pointer = BufReader::with_capacity(1 << 20, file_read);
        let write_pointer = BufWriter::with_capacity(1 << 20, file_write);
        Self {
            read_pointer,
            write_pointer,
            num_vars,
            f: PhantomData,
        }
    }

    

    pub fn new_from_tempfile_single_stream(num_vars: usize) -> Self {
        let file = NamedTempFile::new().expect("failed to create temp file");
        let file_read = file.reopen().unwrap();
        let file_write = file.reopen().unwrap();
        let read_pointer = BufReader::with_capacity(1 << 20, file_read);
        let write_pointer = BufWriter::with_capacity(1 << 20, file_write);
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
        let mut stream = Self::with_path(num_vars, read_path, write_path);
        for e in evaluations {
            stream.write_next_unchecked(e).expect("Failed to write");
        }
        stream.swap_read_write();
        stream
    }

    pub fn from_evaluations_slice(
        num_vars: usize,
        evaluations: &[F],
        read_path: Option<&str>,
        write_path: Option<&str>,
    ) -> Self {
        Self::from_evaluations_vec(num_vars, evaluations.to_vec(), read_path, write_path)
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

        for &r in partial_point {
            while let (Some(even), Some(odd)) = (self.read_next(), self.read_next()) {
                self.write_next(even + r * (odd - even));
            }
            self.decrement_num_vars();
            self.swap_read_write();
        }
    }

    // Evaluate at a specific point to one field element
    pub fn evaluate(&mut self, point: &[F]) -> Option<F> {
        if point.len() == self.num_vars {
            self.fix_variables(point);

            let result = self.read_next().expect("Failed to read");

            self.read_restart();

            Some(result)
        } else {
            None
        }
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
    ) -> (Vec<Self>, F) {
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

        let list = multiplicands
            .into_iter()
            .map(|x| {
                Inner::from_evaluations_vec(nv, x, read_path, write_path)
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
    ) -> Vec<Self> {
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
                Self::from_evaluations_vec(
                    nv, x, None, None,
                    )
            })
            .collect();

        end_timer!(start);
        list
    }

    pub fn const_mle(
        c: F,
        nv: usize,
        read_path: Option<&str>,
        write_path: Option<&str>,
    ) -> Self {
        let mut stream = Self::with_path(nv, read_path, write_path);
        for _ in 0..(1 << nv) {
            stream.write_next_unchecked(c).expect("Failed to write");
        }
        stream.swap_read_write();
        stream
    }
    
    pub fn copy(
        &mut self,
        read_path: Option<&str>,
        write_path: Option<&str>,
    ) -> Self {
        let mut new_stream = Self::with_path(self.num_vars, read_path, write_path);
        while let Some(e) = self.read_next() {
            new_stream.write_next_unchecked(e).expect("Failed to write");
        }
        self.read_restart();
        new_stream.swap_read_write();
        new_stream
    }
    
    /* /// merge a set of polynomials. Returns an error if the
    /// polynomials do not share a same number of nvs.
    pub fn merge(polynomials: &mut [Self], num_vars: usize) -> Result<Self, ArithErrors> {
        let target_num_vars = ((polynomials.len() as f64).log2().ceil() as usize) + num_vars;

        for poly in polynomials.iter() {
            if poly.lock().unwrap().num_vars != num_vars {
                return Err(ArithErrors::InvalidParameters(
                    "num_vars do not match for polynomials".to_string(),
                ));
            }
        }

        let result = Inner::with_path(
            target_num_vars,
            None,
            None,
        );

        // read all poly till none and write each read element to res_stream
        for poly in polynomials.iter() {
            while let Some(elem) = poly.read_next() {
                result.write_next_unchecked(elem);
            }
        }

        // restart all poly
        for poly in polynomials.iter() {
            poly.read_restart();
        }

        // pad the rest with zero
        for _ in 0..((1 << target_num_vars) - polynomials.len() * (1 << num_vars)) {
            result.write_next_unchecked(F::zero());
        }

        result.swap_read_write();

        Ok(result)
    } */
    
    fn add_assign(&mut self, (coeff, other): (F, &mut Self)) -> Option<()> {
        self.combine_in_place(other, |a, b| *a + coeff * *b)
    }
    
    /* fn product(streams: &[Self]) -> Option<Self> {
        Self::combine_many_with(streams, |a, b| *a = *a * b)
    } */
}



/// A list of MLEs that represents an identity permutation
pub fn identity_permutation_mles<F: PrimeField>(
    num_vars: usize,
    num_chunks: usize,
) -> Vec<Inner<F>> {
    let mut res = vec![];
    for i in 0..num_chunks {
        let mut stream = Inner::with_path(num_vars, None, None);
        let shift = (i * (1 << num_vars)) as u64;
        (shift..shift + (1u64 << num_vars)).for_each(|i| {
            stream.write_next_unchecked(F::from(i as u64));
        });
        stream.swap_read_write();
        res.push(stream);
    }
    res
}

pub fn random_permutation<F: PrimeField, R: RngCore>(
    num_vars: usize,
    num_chunks: usize,
    rng: &mut R,
) -> Vec<F> {
    let len = (num_chunks as u64) * (1u64 << num_vars);
    let mut s_id_vec: Vec<F> = (0..len).map(F::from).collect();
    let mut s_perm_vec = vec![];
    for _ in 0..len {
        let index = rng.next_u64() as usize % s_id_vec.len();
        s_perm_vec.push(s_id_vec.remove(index));
    }
    s_perm_vec
}

/// A list of MLEs that represent a random permutation
pub fn random_permutation_mles<F: PrimeField, R: RngCore>(
    num_vars: usize,
    num_chunks: usize,
    rng: &mut R,
) -> Vec<Inner<F>> {
    let s_perm_vec = random_permutation(num_vars, num_chunks, rng);
    let mut res = vec![];
    let n = 1 << num_vars;
    for i in 0..num_chunks {
        res.push(
            Inner::from_evaluations_vec(
                num_vars,
                s_perm_vec[i * n..i * n + n].to_vec(),
                None,
                None,
            ),
        );
    }
    res
}

// currently not very efficient as it reads and writes one field element at a time
// in the future we could optimize by:
// 1. read multiple streams in parallel
// 2. read off multiple field elements to a memory buffer
// to implement these, we also need a memory usage threshold to upper bound the # of streams in parallel times the memory buffer size for each stream
pub trait DenseMLPoly<F: Field>: ReadWriteStream<Item = F> {
    

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
        let mut result_stream = Self::with_path(num_vars, read_path, write_path);

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

}