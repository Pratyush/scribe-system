use std::{
    ops::{AddAssign, MulAssign, SubAssign},
    path::Path,
};

use ark_ff::batch_inversion;
use ark_std::rand::RngCore;
use rayon::prelude::*;

use crate::streams::{
    file_vec::FileVec,
    iterator::{from_fn, repeat, BatchedIterator},
    serialize::RawField,
    LOG_BUFFER_SIZE,
};

#[derive(Debug, Hash, PartialEq, Eq)]
pub struct Inner<F: RawField> {
    pub evals: FileVec<F>,
    pub num_vars: usize,
}

impl<F: RawField> Inner<F> {
    pub fn new(num_vars: usize) -> Self {
        let evals = FileVec::with_prefix("evals");
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

    pub fn evals_mut(&mut self) -> &mut FileVec<F> {
        &mut self.evals
    }

    pub fn to_evals(self) -> FileVec<F> {
        self.evals
    }

    pub fn num_vars(&self) -> usize {
        self.num_vars
    }

    /// Construct a polynomial with all coefficients equal to `coeff`
    pub fn constant(coeff: F, num_vars: usize) -> Self {
        let evals = FileVec::from_batched_iter(repeat(coeff, 1 << num_vars));
        Self::from_evals(evals, num_vars)
    }

    /// Creates multiple identity permutation streams equal to the number of witness streams
    /// Identity permutations are continuous from one to another
    pub fn identity_permutation(num_vars: usize, num_chunks: usize) -> Vec<Self> {
        let shift = (1 << num_vars) as u64;
        (0..num_chunks as u64)
            .map(|i| {
                let evals = from_fn(
                    |j| (j < shift as usize).then(|| F::from(i * shift + (j as u64))),
                    shift as usize,
                )
                .to_file_vec();
                Self::from_evals(evals, num_vars)
            })
            .collect()
    }

    /// For testing only
    pub fn random_permutation<R: RngCore>(
        num_vars: usize,
        num_chunks: usize,
        rng: &mut R,
    ) -> Vec<Self> {
        let len = (num_chunks as u64) * (1u64 << num_vars);
        let mut s_id_vec: Vec<F> = (0..len).map(F::from).collect();
        let mut s_perm_vec = vec![];
        for _ in 0..len {
            let index = rng.next_u64() as usize % s_id_vec.len();
            s_perm_vec.push(s_id_vec.remove(index));
        }

        let shift = (1 << num_vars) as u64;
        (0..num_chunks as u64)
            .map(|i| {
                Self::from_evals_vec(
                    s_perm_vec[(i * shift) as usize..((i + 1) * shift) as usize].to_vec(),
                    num_vars,
                )
            })
            .collect()
    }

    pub fn rand<R: ark_std::rand::RngCore>(num_vars: usize, rng: &mut R) -> Self {
        println!("rand poly gen");
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
                result
                    .as_mut()
                    .map(|s| s.fold_odd_even_in_place(|even, odd| *even + r * (*odd - even)));
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
        if self.num_vars <= LOG_BUFFER_SIZE as usize {
            self.evals.convert_to_buffer();
        }
        match self.evals {
            FileVec::File { .. } => {
                self.evals = self
                    .evals
                    .iter()
                    .array_chunks::<2>()
                    .map(|chunk| f(&chunk[0], &chunk[1]))
                    .to_file_vec();
            }
            FileVec::Buffer { ref mut buffer } => {
                let new_buffer = std::mem::replace(buffer, Vec::new());
                *buffer = new_buffer
                    .par_chunks(2)
                    .map(|chunk| f(&chunk[0], &chunk[1]))
                    .collect();
            }
        }
        self.decrement_num_vars();
    }

    /// Creates a new polynomial whose evaluations are folded versions of `self`,
    /// folded according to the function `f`.
    /// After each fold, the number of variables is reduced by 1.
    pub fn fold_odd_even(&self, f: impl Fn(&F, &F) -> F + Sync) -> Self {
        assert!((1 << self.num_vars) % 2 == 0);
        let evals = self
            .evals
            .iter()
            .array_chunks::<2>()
            .map(|chunk| f(&chunk[0], &chunk[1]))
            .to_file_vec();
        Self {
            evals,
            num_vars: self.num_vars - 1,
        }
    }

    /// Modifies self by replacing evaluations over the hypercube with their inverse.
    pub fn invert_in_place(&mut self) {
        self.evals
            .batched_for_each(|mut chunk| batch_inversion(&mut chunk));
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
    pub fn rand_product_with_sum<R: ark_std::rand::RngCore>(
        num_vars: usize,
        degree: usize,
        rng: &mut R,
    ) -> (Vec<Self>, F) {
        let polys = (0..degree)
            .map(|_| Self::rand(num_vars, rng))
            .collect::<Vec<_>>();
        let product_poly = polys
            .iter()
            .fold(Self::constant(F::one(), num_vars), |mut acc, p| {
                acc.evals.zipped_for_each(p.evals.iter(), |a, b| *a *= b);
                acc
            });

        (polys, product_poly.evals.iter().sum())
    }

    pub fn rand_product_summing_to_zero<R: ark_std::rand::RngCore>(
        num_vars: usize,
        degree: usize,
        rng: &mut R,
    ) -> Vec<Self> {
        (0..(degree - 1))
            .map(|_| Self::rand(num_vars, rng))
            .chain([Self::constant(F::zero(), num_vars)])
            .collect()
    }
}

impl<F: RawField> MulAssign<Self> for Inner<F> {
    fn mul_assign(&mut self, other: Self) {
        self.evals
            .zipped_for_each(other.evals.iter(), |a, b| *a *= b);
    }
}

impl<'a, F: RawField> MulAssign<&'a Self> for Inner<F> {
    fn mul_assign(&mut self, other: &'a Self) {
        self.evals
            .zipped_for_each(other.evals.iter(), |a, b| *a *= b);
    }
}

impl<F: RawField> AddAssign<Self> for Inner<F> {
    fn add_assign(&mut self, other: Self) {
        self.evals
            .zipped_for_each(other.evals.iter(), |a, b| *a += b);
    }
}

impl<'a, F: RawField> AddAssign<&'a Self> for Inner<F> {
    fn add_assign(&mut self, other: &'a Self) {
        self.evals
            .zipped_for_each(other.evals.iter(), |a, b| *a += b);
    }
}

impl<F: RawField> SubAssign<Self> for Inner<F> {
    fn sub_assign(&mut self, other: Self) {
        self.evals
            .zipped_for_each(other.evals.iter(), |a, b| *a -= b);
    }
}

impl<'a, F: RawField> SubAssign<&'a Self> for Inner<F> {
    fn sub_assign(&mut self, other: &'a Self) {
        self.evals
            .zipped_for_each(other.evals.iter(), |a, b| *a -= b);
    }
}

impl<F: RawField> MulAssign<(F, Self)> for Inner<F> {
    fn mul_assign(&mut self, (f, other): (F, Self)) {
        self.evals
            .zipped_for_each(other.evals.iter(), |a, b| *a *= f * b);
    }
}

impl<'a, F: RawField> MulAssign<(F, &'a Self)> for Inner<F> {
    fn mul_assign(&mut self, (f, other): (F, &'a Self)) {
        self.evals
            .zipped_for_each(other.evals.iter(), |a, b| *a *= f * b);
    }
}

impl<F: RawField> AddAssign<(F, Self)> for Inner<F> {
    fn add_assign(&mut self, (f, other): (F, Self)) {
        self.evals
            .zipped_for_each(other.evals.iter(), |a, b| *a += f * b);
    }
}

impl<'a, F: RawField> AddAssign<(F, &'a Self)> for Inner<F> {
    fn add_assign(&mut self, (f, other): (F, &'a Self)) {
        self.evals
            .zipped_for_each(other.evals.iter(), |a, b| *a += f * b);
    }
}

impl<F: RawField> SubAssign<(F, Self)> for Inner<F> {
    fn sub_assign(&mut self, (f, other): (F, Self)) {
        self.evals
            .zipped_for_each(other.evals.iter(), |a, b| *a -= f * b);
    }
}

impl<'a, F: RawField> SubAssign<(F, &'a Self)> for Inner<F> {
    fn sub_assign(&mut self, (f, other): (F, &'a Self)) {
        self.evals
            .zipped_for_each(other.evals.iter(), |a, b| *a -= f * b);
    }
}
