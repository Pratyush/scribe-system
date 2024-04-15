use std::{iter::repeat, ops::{AddAssign, MulAssign, SubAssign}, path::Path};

use ark_ff::{batch_inversion, Field};
use rayon::prelude::*;

use crate::streams::{file_vec::FileVec, iterator::BatchedIterator};

#[derive(Debug, Hash, PartialEq, Eq)]
pub struct Inner<F: Field> {
    pub evals: FileVec<F>,
    pub num_vars: usize,
}

impl<F: Field> Inner<F> {
    pub fn new(num_vars: usize) -> Self {
        let evals = FileVec::new();
        Self { evals, num_vars }
    }
    
    pub fn with_path(num_vars: usize, path: impl AsRef<Path>) -> Self {
        let evals = FileVec::with_name(path);
        Self { evals, num_vars }
    }
    
    pub fn from_evals(evals: FileVec<F>, num_vars: usize) -> Self {
        Self { evals, num_vars }
    }
    
    /// Construct a polynomial with coefficients specified by `evals`.
    /// 
    /// This should only be used for testing.
    pub fn from_evals_vec(evals: Vec<F>, num_vars: usize) -> Self {
        assert_eq!(evals.len(), 1 << num_vars);
        let evals = FileVec::from_iter(evals);
        Self { evals, num_vars }
    }
    
    pub fn evals(&self) -> &FileVec<F> {
        &self.evals
    }
    
    pub fn to_evals(self) -> FileVec<F> {
        self.evals
    }
    
    pub fn num_vars(&self) -> usize {
        self.num_vars
    }
    
    /// Construct a polynomial with all coefficients equal to `coeff`
    pub fn constant(coeff: F, num_vars: usize) -> Self {
        let evals = FileVec::from_iter(repeat(coeff).take(1 << num_vars));
        Self::from_evals(evals, num_vars)
    }
    
    pub fn identity_permutation(num_vars: usize) -> Self {
        let evals = FileVec::from_iter((0u64..(1 << num_vars)).map(F::from));
        Self::from_evals(evals, num_vars)
    }
    
    pub fn rand<R: ark_std::rand::RngCore>(num_vars: usize, rng: &mut R) -> Self {
        let evals = FileVec::from_iter((0..(1 << num_vars)).map(|_| F::rand(rng)));
        Self::from_evals(evals, num_vars)
    }
    
    
    pub fn decrement_num_vars(&mut self) {
        if self.num_vars <= 0 {
            panic!("Cannot decrement num_vars below 0");
        }
        self.num_vars -= 1;
    }
    
    /// Modifies self by fixing the first `partial_point.len()` variables to 
    /// the values in `partial_point`.
    /// The number of variables is decremented by `partial_point.len()`.
    /// 
    /// # Panics
    /// Panics if `partial_point.len() > self.num_vars`.
    pub fn fix_variables_in_place(&mut self, partial_point: &[F]) {
        assert!(
            partial_point.len() <= self.num_vars,
            "invalid size of partial point"
        );

        for &r in partial_point {
            // Decrements num_vars internally.
            self.fold_odd_even_in_place(|even, odd| *even + r * (*odd - even));
        }
    }
    
    /// Creates a new polynomial by fixing the first `partial_point.len()` variables to
    /// the values in `partial_point`.
    /// The number of variables in the result is `self.num_vars() - partial_point.len()`.
    pub fn fix_variables(&self, partial_point: &[F]) -> Self {
        assert!(
            partial_point.len() <= self.num_vars,
            "invalid size of partial point"
        );
        
        let mut result = None;

        for &r in partial_point {
            // Decrements num_vars internally.
            if result.is_none() {
                result = Some(self.fold_odd_even(|even, odd| *even + r * (*odd - even)));
            } else {
                result.as_mut().map(|s| s.fold_odd_even_in_place(|even, odd| *even + r * (*odd - even)));
            }
        }
        result.unwrap_or_else(|| self.deep_copy())
    }

    /// Evaluates `self` at the given point. 
    /// Returns `None` if the point has the wrong length.
    pub fn evaluate(&self, point: &[F]) -> Option<F> {
        if point.len() == self.num_vars {
            let mut tmp = self.deep_copy();
            tmp.fix_variables_in_place(point);

            // The result is the first element in the stream
            Some(tmp.evals.iter().next_batch()?.collect::<Vec<_>>()[0])
        } else {
            None
        }
    }

    
    /// Modifies self by folding the evaluations over the hypercube with the function `f`.
    /// After each fold, the number of variables is reduced by 1.
    pub fn fold_odd_even_in_place(&mut self, f: impl Fn(&F, &F) -> F + Sync) {
        assert!((1 << self.num_vars) % 2 == 0);
        self.evals = self.evals.iter().array_chunks::<2>().map(|chunk| {
            f(&chunk[0], &chunk[1])
        }).to_file_vec();
        self.decrement_num_vars();
    }
    
    /// Creates a new polynomial whose evaluations are folded versions of `self`,
    /// folded according to the function `f`.
    /// After each fold, the number of variables is reduced by 1.
    pub fn fold_odd_even(&self, f: impl Fn(&F, &F) -> F + Sync) -> Self {
        assert!((1 << self.num_vars) % 2 == 0);
        let evals = self.evals.iter().array_chunks::<2>().map(|chunk| {
            f(&chunk[0], &chunk[1])
        }).to_file_vec();
        Self { evals, num_vars: self.num_vars - 1 }
    }
    

    /// Modifies self by replacing evaluations over the hypercube with their inverse. 
    pub fn invert_in_place(&mut self) {
        self.evals.batched_for_each(|mut chunk| batch_inversion(&mut chunk));
    }
    
    /// Creates a new polynomial whose evaluations over the hypercube are 
    /// the inverses of the evaluations of this polynomial.
    pub fn invert(&self) -> Self {
        let mut result = self.deep_copy();
        result.invert_in_place();
        result
    }
    
    /// Creates a deep copy of the polynomial by copying the evaluations to a new stream.
    pub fn deep_copy(&self) -> Self {
        Self::from_evals(self.evals.deep_copy().into(), self.num_vars)
    }
    
    /// Sample `degree` random polynomials, and returns the sum of their Hadamard product.
    pub fn rand_product_with_sum<R: ark_std::rand::RngCore>(num_vars: usize, degree: usize, rng: &mut R) -> (Vec<Self>, F) {
        let polys = (0..degree).map(|_| Self::rand(num_vars, rng)).collect::<Vec<_>>();
        let product_poly = polys.iter().fold(Self::constant(F::one(), num_vars), |mut acc, p| {
            acc.evals.zipped_for_each(p.evals.iter(), |a, b| *a *= b);
            acc
        });
        (polys, product_poly.evals.iter().sum())
    }
    
    pub fn rand_product_summing_to_zero<R: ark_std::rand::RngCore>(num_vars: usize, degree: usize, rng: &mut R) -> Vec<Self> {
        (0..(degree - 1)).map(|_| Self::rand(num_vars, rng)).chain([Self::constant(F::zero(), num_vars)]).collect()
    }

}

impl<F: Field> MulAssign<F> for Inner<F> {
    fn mul_assign(&mut self, other: F) {
        self.evals.for_each(|mut e| *e *= other);
    }
}

impl<F: Field> AddAssign<Self> for Inner<F> {
    fn add_assign(&mut self, other: Self) {
        self.evals.zipped_for_each(other.evals.iter(), |a, b| *a += b);
    }
}

impl<'a, F: Field> AddAssign<&'a Self> for Inner<F> {
    fn add_assign(&mut self, other: &'a Self) {
        self.evals.zipped_for_each(other.evals.iter(), |a, b| *a += b);
    }
}

impl<F: Field> SubAssign<Self> for Inner<F> {
    fn sub_assign(&mut self, other: Self) {
        self.evals.zipped_for_each(other.evals.iter(), |a, b| *a -= b);
    }
}

impl<'a, F: Field> SubAssign<&'a Self> for Inner<F> {
    fn sub_assign(&mut self, other: &'a Self) {
        self.evals.zipped_for_each(other.evals.iter(), |a, b| *a -= b);
    }
}

impl<F: Field> AddAssign<(F, Self)> for Inner<F> {
    fn add_assign(&mut self, (f, other): (F, Self)) {
        self.evals.zipped_for_each(other.evals.iter(), |a, b| *a += f * b);
    }
}

impl<'a, F: Field> AddAssign<(F, &'a Self)> for Inner<F> {
    fn add_assign(&mut self, (f, other): (F, &'a Self)) {
        self.evals.zipped_for_each(other.evals.iter(), |a, b| *a += f * b);
    }
}

impl<F: Field> SubAssign<(F, Self)> for Inner<F> {
    fn sub_assign(&mut self, (f, other): (F, Self)) {
        self.evals.zipped_for_each(other.evals.iter(), |a, b| *a -= f * b);
    }
}

impl<'a, F: Field> SubAssign<(F, &'a Self)> for Inner<F> {
    fn sub_assign(&mut self, (f, other): (F, &'a Self)) {
        self.evals.zipped_for_each(other.evals.iter(), |a, b| *a -= f * b);
    }
}

/* impl<F: Field> Inner<F> {
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

    pub fn rand<R: RngCore>(num_vars: usize, rng: &mut R) -> Self {
        let step = start_timer!(|| format!("generate random stream for nv = {}", num_vars));
        let mut stream = Self::with_path(num_vars, None, None);

        for _ in 0..(1 << num_vars) {
            stream.write_next_unchecked(F::rand(rng));
        }

        stream.swap_read_write();
        end_timer!(step);

        stream
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
    
    fn batch_inversion(&mut self) -> Option<Self> {
        let mut result = Self::new_from_tempfile(self.num_vars());
        let mut buffer = Vec::with_capacity(BUFFER_SIZE);
        while self.read_to_buf(&mut buffer, BUFFER_SIZE).is_some() {
            batch_inversion(&mut buffer);
            result.write_buf(&buffer)?;
            buffer.clear();
        }
        result.swap_read_write();
        result.read_restart();
        self.read_restart();
        Some(result)
    }
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

// doesn't crash memory way of creating the identity stream
pub fn identity_permutation_mle<F: PrimeField>(
    num_vars: usize,
) -> Inner<F> {
    let mut res = Inner::with_path(num_vars, None, None);
    (0..1 << num_vars).for_each(|i| {
        res.write_next_unchecked(F::from(i as u64));
    });
    res.swap_read_write();
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

} */