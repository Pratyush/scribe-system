mod inner;
use std::{
    ops::{AddAssign, MulAssign, SubAssign},
    path::Path,
    sync::Arc,
};

use ark_std::{end_timer, rand::RngCore, start_timer};
pub use inner::*;

use crate::arithmetic::errors::ArithError;

use super::{file_vec::FileVec, iterator::BatchedIterator, serialize::RawField, LOG_BUFFER_SIZE};

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct MLE<F: RawField>(Arc<Inner<F>>);

impl<F: RawField> MLE<F> {
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

impl<F: RawField> From<Inner<F>> for MLE<F> {
    fn from(inner: Inner<F>) -> Self {
        Self::from_inner(inner)
    }
}

impl<F: RawField> MLE<F> {
    pub fn with_path(num_vars: usize, path: impl AsRef<Path>) -> Self {
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

impl<F: RawField> MulAssign<Self> for MLE<F> {
    fn mul_assign(&mut self, other: Self) {
        self.map_in_place_2(&other, |inner, other| inner.mul_assign(other));
    }
}

impl<'a, F: RawField> MulAssign<&'a Self> for MLE<F> {
    fn mul_assign(&mut self, other: &'a Self) {
        self.map_in_place_2(&other, |inner, other| inner.mul_assign(other));
    }
}

impl<F: RawField> MulAssign<(F, Self)> for MLE<F> {
    fn mul_assign(&mut self, (f, other): (F, Self)) {
        self.map_in_place_2(&other, |inner, other| inner.mul_assign((f, other)));
    }
}

impl<'a, F: RawField> MulAssign<(F, &'a Self)> for MLE<F> {
    fn mul_assign(&mut self, (f, other): (F, &'a Self)) {
        self.map_in_place_2(&other, |inner, other| inner.mul_assign((f, other)));
    }
}

impl<F: RawField> AddAssign<Self> for MLE<F> {
    fn add_assign(&mut self, other: Self) {
        self.map_in_place_2(&other, |inner, other| inner.add_assign(other));
    }
}

impl<'a, F: RawField> AddAssign<&'a Self> for MLE<F> {
    fn add_assign(&mut self, other: &'a Self) {
        self.map_in_place_2(&other, |inner, other| inner.add_assign(other));
    }
}

impl<F: RawField> SubAssign<Self> for MLE<F> {
    fn sub_assign(&mut self, other: Self) {
        self.map_in_place_2(&other, |inner, other| inner.sub_assign(other));
    }
}

impl<'a, F: RawField> SubAssign<&'a Self> for MLE<F> {
    fn sub_assign(&mut self, other: &'a Self) {
        self.map_in_place_2(&other, |inner, other| inner.sub_assign(other));
    }
}

impl<F: RawField> AddAssign<(F, Self)> for MLE<F> {
    fn add_assign(&mut self, (f, other): (F, Self)) {
        self.map_in_place_2(&other, |inner, other| inner.add_assign((f, other)));
    }
}

impl<'a, F: RawField> AddAssign<(F, &'a Self)> for MLE<F> {
    fn add_assign(&mut self, (f, other): (F, &'a Self)) {
        self.map_in_place_2(&other, |inner, other| inner.add_assign((f, other)));
    }
}

impl<F: RawField> SubAssign<(F, Self)> for MLE<F> {
    fn sub_assign(&mut self, (f, other): (F, Self)) {
        self.map_in_place_2(&other, |inner, other| inner.sub_assign((f, other)));
    }
}

impl<'a, F: RawField> SubAssign<(F, &'a Self)> for MLE<F> {
    fn sub_assign(&mut self, (f, other): (F, &'a Self)) {
        self.map_in_place_2(&other, |inner, other| inner.sub_assign((f, other)));
    }
}

/// A helper function to build eq(x, r) recursively.
fn eq_x_r_helper<F: RawField>(r: &[F]) -> Result<FileVec<F>, ArithError> {
    if r.is_empty() {
        Err(ArithError::InvalidParameters("r length is 0".to_string()))
    } else if r.len() <= LOG_BUFFER_SIZE as usize {
        println!("eq_x_r buffer");
        let result = crate::arithmetic::virtual_polynomial::build_eq_x_r_vec(r).unwrap();
        // initializing the buffer with [1-r_0, r_0]
        Ok(FileVec::from_iter(result))
    } else {
        println!("eq_x_r file");
        let prev = eq_x_r_helper(&r[1..])?;
        Ok(prev
            .iter()
            .flat_map(|cur| {
                let tmp = r[0] * cur;
                println!("cur eq_x_r file elem: {:?}", cur);
                [cur - tmp, tmp]
            })
            .to_file_vec())
    }
}

#[cfg(test)]
mod test {
    use super::MLE;
    use crate::arithmetic::virtual_polynomial::VirtualPolynomial;
    use ark_bls12_381::Fr;
    use ark_std::rand::rngs::StdRng;
    use ark_std::rand::SeedableRng;
    use ark_std::test_rng;
    use ark_std::UniformRand;

    #[test]
    fn test_eq_x_r() {
        let seed = [
            1, 0, 0, 0, 23, 0, 0, 0, 200, 1, 0, 0, 210, 30, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0,
        ];
        let mut rng = StdRng::from_seed(seed);

        let r: Vec<Fr> = (0..3).map(|_| Fr::rand(&mut rng)).collect::<Vec<_>>();
        let eq_x_r = MLE::eq_x_r(&r).unwrap();
        println!("{:?}", eq_x_r.evals());
    }
}

// Buffer { buffer: [BigInt([11091219084094443142, 4010008289479289305, 3139266430053181684, 1161211522812571285]), BigInt([9822150885673284880, 15400504344459953975, 2282615559425841091, 865030216231708633]), BigInt([15468738206133273609, 5713111823994055412, 8021618164619295792, 7214559998083271659]), BigInt([9763440026807441989, 6238059692177119888, 1572673752554939620, 1173253155448292303]), BigInt([16544975391993553601, 12536994293839119218, 14191849839123728213, 6619274875552936476]), BigInt([16820177190113810734, 12775374885969670184, 16650339122569395119, 1165065650630765330]), BigInt([18335621969920165164, 3456775633753981671, 4615225256654173118, 2621584562126356209]), BigInt([12834141674636434693, 13311881483069712098, 15940300792047415167, 4240570597507446158])] }
