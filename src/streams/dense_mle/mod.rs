mod inner;
use std::{
    ops::{AddAssign, MulAssign, SubAssign},
    path::Path,
    sync::Arc,
};

use ark_ff::Field;
use ark_std::{end_timer, rand::RngCore, start_timer};
pub use inner::*;

use crate::arithmetic::errors::ArithError;

use super::{file_vec::FileVec, iterator::BatchedIterator, LOG_BUFFER_SIZE};

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct MLE<F: Field>(Arc<Inner<F>>);

impl<F: Field> MLE<F> {
    fn from_inner(inner: Inner<F>) -> Self {
        Self(Arc::new(inner))
    }

    fn map<T>(&self, f: impl FnOnce(&Inner<F>) -> T + Send + Sync) -> T {
        f(&*self.0)
    }

    fn map_in_place<'a, T>(&'a mut self, f: impl FnOnce(&'a mut Inner<F>) -> T + Send + Sync) -> T {
        let inner = Arc::get_mut(&mut self.0)
            .expect("failed to get mutable reference: multiple references exist");
        f(inner)
    }

    fn map_in_place_2(&mut self, other: &Self, f: impl FnOnce(&mut Inner<F>, &Inner<F>)) {
        let inner = Arc::get_mut(&mut self.0)
            .expect("failed to get mutable reference: multiple references exist");
        f(inner, &*other.0)
    }
}

impl<F: Field> From<Inner<F>> for MLE<F> {
    fn from(inner: Inner<F>) -> Self {
        Self::from_inner(inner)
    }
}

impl<F: Field> MLE<F> {
    pub fn with_path<'a>(num_vars: usize, path: impl AsRef<Path>) -> Self {
        Inner::with_path(num_vars, path).into()
    }

    pub fn new(num_vars: usize) -> Self {
        Inner::new(num_vars).into()
    }

    pub fn num_vars(&self) -> usize {
        self.map(|inner| inner.num_vars())
    }

    pub fn decrement_num_vars(&mut self) {
        self.map_in_place(|inner| inner.decrement_num_vars());
    }

    pub fn from_evals(evals: FileVec<F>, num_vars: usize) -> Self {
        Inner::from_evals(evals, num_vars).into()
    }

    pub fn from_evals_vec(evals: Vec<F>, num_vars: usize) -> Self {
        Inner::from_evals_vec(evals, num_vars).into()
    }

    pub fn evals(&self) -> &FileVec<F> {
        self.0.evals()
    }

    pub fn evals_mut(&mut self) -> &mut FileVec<F> {
        self.map_in_place(|inner| inner.evals_mut())
    }

    pub fn to_evals(self) -> FileVec<F> {
        let inner =
            Arc::try_unwrap(self.0).expect("failed to unwrap Arc: multiple references exist");
        inner.to_evals()
    }

    pub fn constant(c: F, num_vars: usize) -> Self {
        Inner::constant(c, num_vars).into()
    }

    pub fn eq_x_r(r: &[F]) -> Result<Self, ArithError> {
        let step = start_timer!(|| "construct eq_x_r polynomial");
        let res = eq_x_r_helper(r).map(|evals| Self::from_evals(evals, r.len()));
        end_timer!(step);
        res
    }

    pub fn identity_permutation_mles(num_vars: usize, num_chunk: usize) -> Vec<Self> {
        Inner::identity_permutation(num_vars, num_chunk)
            .into_iter()
            .map(From::from)
            .collect()
    }

    pub fn random_permutation_mles<R: RngCore>(
        num_vars: usize,
        num_chunk: usize,
        rng: &mut R,
    ) -> Vec<Self> {
        Inner::random_permutation(num_vars, num_chunk, rng)
            .into_iter()
            .map(From::from)
            .collect()
    }

    pub fn rand<R: ark_std::rand::RngCore>(num_vars: usize, rng: &mut R) -> Self {
        Inner::rand(num_vars, rng).into()
    }

    /// Sample `degree` random polynomials, and returns the sum of their Hadamard product.
    pub fn rand_product_with_sum<R: ark_std::rand::RngCore>(
        num_vars: usize,
        degree: usize,
        rng: &mut R,
    ) -> (Vec<Self>, F) {
        let (v, f) = Inner::rand_product_with_sum(num_vars, degree, rng);
        (v.into_iter().map(From::from).collect(), f)
    }

    pub fn rand_product_summing_to_zero<R: ark_std::rand::RngCore>(
        num_vars: usize,
        degree: usize,
        rng: &mut R,
    ) -> Vec<Self> {
        Inner::rand_product_summing_to_zero(num_vars, degree, rng)
            .into_iter()
            .map(From::from)
            .collect()
    }

    /// Modifies self by fixing the first `partial_point.len()` variables to
    /// the values in `partial_point`.
    /// The number of variables is decremented by `partial_point.len()`.
    ///
    /// # Panics
    /// Panics if `partial_point.len() > self.num_vars`.
    pub fn fix_variables_in_place(&mut self, partial_point: &[F]) {
        self.map_in_place(|inner| inner.fix_variables_in_place(partial_point))
    }

    /// Creates a new polynomial by fixing the first `partial_point.len()` variables to
    /// the values in `partial_point`.
    /// The number of variables in the result is `self.num_vars() - partial_point.len()`.
    pub fn fix_variables(&self, partial_point: &[F]) -> Self {
        self.map(|inner| inner.fix_variables(partial_point)).into()
    }

    /// Evaluates `self` at the given point.
    /// Returns `None` if the point has the wrong length.
    pub fn evaluate(&self, point: &[F]) -> Option<F> {
        self.map(|inner| inner.evaluate(point))
    }

    /// Modifies self by folding the evaluations over the hypercube with the function `f`.
    /// After each fold, the number of variables is reduced by 1.
    pub fn fold_odd_even_in_place(&mut self, f: impl Fn(&F, &F) -> F + Send + Sync) {
        self.map_in_place(|inner| inner.fold_odd_even_in_place(f));
    }

    /// Creates a new polynomial whose evaluations over the hypercube are the folded
    /// versions of the evaluations of this polynomial.
    /// In more detail, `p[i] = f(p[2i], p[2i+1]) for i in 0..(p.len()/2)`.
    ///
    /// Note that the number of variables in the result is `self.num_vars() - 1`.
    pub fn fold_odd_even(&self, f: impl Fn(&F, &F) -> F + Send + Sync) -> Self {
        self.map(|inner| inner.fold_odd_even(f)).into()
    }

    /// Modifies self by replacing evaluations over the hypercube with their inverse.
    pub fn invert_in_place(&mut self) {
        self.map_in_place(|inner| inner.invert_in_place());
    }

    /// Creates a new polynomial whose evaluations over the hypercube are
    /// the inverses of the evaluations of this polynomial.
    pub fn invert(&self) -> Self {
        self.map(|inner| inner.invert()).into()
    }
}

impl<F: Field> MulAssign<Self> for MLE<F> {
    fn mul_assign(&mut self, other: Self) {
        self.map_in_place_2(&other, |inner, other| inner.mul_assign(other));
    }
}

impl<'a, F: Field> MulAssign<&'a Self> for MLE<F> {
    fn mul_assign(&mut self, other: &'a Self) {
        self.map_in_place_2(&other, |inner, other| inner.mul_assign(other));
    }
}

impl<F: Field> MulAssign<(F, Self)> for MLE<F> {
    fn mul_assign(&mut self, (f, other): (F, Self)) {
        self.map_in_place_2(&other, |inner, other| inner.mul_assign((f, other)));
    }
}

impl<'a, F: Field> MulAssign<(F, &'a Self)> for MLE<F> {
    fn mul_assign(&mut self, (f, other): (F, &'a Self)) {
        self.map_in_place_2(&other, |inner, other| inner.mul_assign((f, other)));
    }
}

impl<F: Field> AddAssign<Self> for MLE<F> {
    fn add_assign(&mut self, other: Self) {
        self.map_in_place_2(&other, |inner, other| inner.add_assign(other));
    }
}

impl<'a, F: Field> AddAssign<&'a Self> for MLE<F> {
    fn add_assign(&mut self, other: &'a Self) {
        self.map_in_place_2(&other, |inner, other| inner.add_assign(other));
    }
}

impl<F: Field> SubAssign<Self> for MLE<F> {
    fn sub_assign(&mut self, other: Self) {
        self.map_in_place_2(&other, |inner, other| inner.sub_assign(other));
    }
}

impl<'a, F: Field> SubAssign<&'a Self> for MLE<F> {
    fn sub_assign(&mut self, other: &'a Self) {
        self.map_in_place_2(&other, |inner, other| inner.sub_assign(other));
    }
}

impl<F: Field> AddAssign<(F, Self)> for MLE<F> {
    fn add_assign(&mut self, (f, other): (F, Self)) {
        self.map_in_place_2(&other, |inner, other| inner.add_assign((f, other)));
    }
}

impl<'a, F: Field> AddAssign<(F, &'a Self)> for MLE<F> {
    fn add_assign(&mut self, (f, other): (F, &'a Self)) {
        self.map_in_place_2(&other, |inner, other| inner.add_assign((f, other)));
    }
}

impl<F: Field> SubAssign<(F, Self)> for MLE<F> {
    fn sub_assign(&mut self, (f, other): (F, Self)) {
        self.map_in_place_2(&other, |inner, other| inner.sub_assign((f, other)));
    }
}

impl<'a, F: Field> SubAssign<(F, &'a Self)> for MLE<F> {
    fn sub_assign(&mut self, (f, other): (F, &'a Self)) {
        self.map_in_place_2(&other, |inner, other| inner.sub_assign((f, other)));
    }
}

/// A helper function to build eq(x, r) recursively.
fn eq_x_r_helper<F: Field>(r: &[F]) -> Result<FileVec<F>, ArithError> {
    if r.is_empty() {
        Err(ArithError::InvalidParameters("r length is 0".to_string()))
    } else if r.len() <= LOG_BUFFER_SIZE as usize {
        let result = crate::arithmetic::virtual_polynomial::build_eq_x_r_vec(r).unwrap();
        // initializing the buffer with [1-r_0, r_0]
        Ok(FileVec::from_iter(result))
    } else {
        let prev = eq_x_r_helper(&r[1..])?;
        Ok(prev
            .iter()
            .flat_map(|cur| {
                let tmp = r[0] * cur;
                [cur - tmp, tmp]
            })
            .to_file_vec())
    }
}
