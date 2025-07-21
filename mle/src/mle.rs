use std::{
    fmt::{Debug, Display},
    io::Write,
    ops::{AddAssign, Mul, MulAssign, SubAssign},
    sync::Arc,
};

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Valid};
use ark_std::{end_timer, rand::RngCore, start_timer};

use crate::inner::Inner;
use scribe_streams::{
    LOG_BUFFER_SIZE, file_vec::FileVec, iterator::BatchedIterator, serialize::RawField,
};

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct MLE<F: RawField>(Arc<Inner<F>>);

impl<F: RawField> MLE<F> {
    #[inline(always)]
    fn from_inner(inner: Inner<F>) -> Self {
        Self(Arc::new(inner))
    }

    #[inline(always)]
    fn map<T>(&self, f: impl FnOnce(&Inner<F>) -> T + Send + Sync) -> T {
        f(&*self.0)
    }

    #[inline(always)]
    fn map_in_place<'a, T>(&'a mut self, f: impl FnOnce(&'a mut Inner<F>) -> T + Send + Sync) -> T {
        let inner = Arc::get_mut(&mut self.0)
            .expect("failed to get mutable reference: multiple references exist");
        f(inner)
    }

    #[inline(always)]
    fn map_in_place_2(&mut self, other: &Self, f: impl FnOnce(&mut Inner<F>, &Inner<F>)) {
        let inner = Arc::get_mut(&mut self.0)
            .expect("failed to get mutable reference: multiple references exist");
        f(inner, &*other.0)
    }
}

impl<F: RawField> From<Inner<F>> for MLE<F> {
    #[inline(always)]
    fn from(inner: Inner<F>) -> Self {
        Self::from_inner(inner)
    }
}

impl<F: RawField> MLE<F> {
    #[inline(always)]
    pub fn new(num_vars: usize) -> Self {
        Inner::new(num_vars).into()
    }

    #[inline(always)]
    pub fn num_vars(&self) -> usize {
        self.map(|inner| inner.num_vars())
    }

    #[inline(always)]
    pub fn decrement_num_vars(&mut self) {
        self.map_in_place(|inner| inner.decrement_num_vars());
    }

    #[inline(always)]
    pub fn from_evals(evals: FileVec<F>, num_vars: usize) -> Self {
        Inner::from_evals(evals, num_vars).into()
    }

    #[inline(always)]
    pub fn from_evals_vec(evals: Vec<F>, num_vars: usize) -> Self {
        Inner::from_evals_vec(evals, num_vars).into()
    }

    #[inline(always)]
    pub fn evals(&self) -> &FileVec<F> {
        self.0.evals()
    }

    #[inline(always)]
    pub fn evals_mut(&mut self) -> &mut FileVec<F> {
        self.map_in_place(|inner| inner.evals_mut())
    }

    #[inline(always)]
    pub fn to_evals(self) -> FileVec<F> {
        let inner =
            Arc::try_unwrap(self.0).expect("failed to unwrap Arc: multiple references exist");
        inner.to_evals()
    }

    #[inline(always)]
    pub fn zero(num_vars: usize) -> Self {
        Self::constant(F::zero(), num_vars)
    }

    #[inline(always)]
    pub fn constant(c: F, num_vars: usize) -> Self {
        Inner::constant(c, num_vars).into()
    }

    pub fn deep_copy(&self) -> Self {
        self.map(|inner| inner.deep_copy()).into()
    }

    #[inline(always)]
    pub fn eq_x_r(r: &[F]) -> Self {
        let step = start_timer!(|| "construct eq_x_r polynomial");
        let res = eq_x_r_helper(r)
            .map(|evals| Self::from_evals(evals, r.len()))
            .unwrap();
        end_timer!(step);
        res
    }

    #[inline(always)]
    pub fn identity_permutation_mles(num_vars: usize, num_chunk: usize) -> Vec<Self> {
        Inner::identity_permutation(num_vars, num_chunk)
            .into_iter()
            .map(From::from)
            .collect()
    }

    #[inline(always)]
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

    #[inline(always)]
    pub fn rand<R: ark_std::rand::RngCore>(num_vars: usize, rng: &mut R) -> Self {
        Inner::rand(num_vars, rng).into()
    }

    /// Sample `degree` random polynomials, and returns the sum of their Hadamard product.
    #[inline(always)]
    pub fn rand_product_with_sum<R: ark_std::rand::RngCore>(
        num_vars: usize,
        degree: usize,
        rng: &mut R,
    ) -> (Vec<Self>, F) {
        let (v, f) = Inner::rand_product_with_sum(num_vars, degree, rng);
        (v.into_iter().map(From::from).collect(), f)
    }

    #[inline(always)]
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
    #[inline(always)]
    pub fn fix_variables_in_place(&mut self, partial_point: &[F]) {
        self.map_in_place(|inner| inner.fix_variables_in_place(partial_point))
    }

    /// Creates a new polynomial by fixing the first `partial_point.len()` variables to
    /// the values in `partial_point`.
    /// The number of variables in the result is `self.num_vars() - partial_point.len()`.
    #[inline(always)]
    pub fn fix_variables(&self, partial_point: &[F]) -> Self {
        self.map(|inner| inner.fix_variables(partial_point)).into()
    }

    /// Evaluates `self` at the given point.
    /// Returns `None` if the point has the wrong length.
    #[inline(always)]
    pub fn evaluate(&self, point: &[F]) -> Option<F> {
        self.map(|inner| inner.evaluate(point))
    }

    /// Modifies self by folding the evaluations over the hypercube with the function `f`.
    /// After each fold, the number of variables is reduced by 1.
    #[inline(always)]
    pub fn fold_odd_even_in_place(&mut self, f: impl Fn(&F, &F) -> F + Send + Sync) {
        self.map_in_place(|inner| inner.fold_odd_even_in_place(f));
    }

    /// Creates a new polynomial whose evaluations over the hypercube are the folded
    /// versions of the evaluations of this polynomial.
    /// In more detail, `p[i] = f(p[2i], p[2i+1]) for i in 0..(p.len()/2)`.
    ///
    /// Note that the number of variables in the result is `self.num_vars() - 1`.
    #[inline(always)]
    pub fn fold_odd_even(&self, f: impl Fn(&F, &F) -> F + Send + Sync) -> Self {
        self.map(|inner| inner.fold_odd_even(f)).into()
    }

    /// Modifies self by replacing evaluations over the hypercube with their inverse.
    #[inline(always)]
    pub fn invert_in_place(&mut self) {
        self.map_in_place(|inner| inner.invert_in_place());
    }

    /// Creates a new polynomial whose evaluations over the hypercube are
    /// the inverses of the evaluations of this polynomial.
    #[inline(always)]
    pub fn invert(&self) -> Self {
        self.map(|inner| inner.invert()).into()
    }
}

impl<F: RawField> MulAssign<Self> for MLE<F> {
    #[inline(always)]
    fn mul_assign(&mut self, other: Self) {
        self.map_in_place_2(&other, |inner, other| inner.mul_assign(other));
    }
}

impl<'a, F: RawField> MulAssign<&'a Self> for MLE<F> {
    #[inline(always)]
    fn mul_assign(&mut self, other: &'a Self) {
        self.map_in_place_2(other, |inner, other| inner.mul_assign(other));
    }
}

impl<F: RawField> MulAssign<(F, Self)> for MLE<F> {
    #[inline(always)]
    fn mul_assign(&mut self, (f, other): (F, Self)) {
        self.map_in_place_2(&other, |inner, other| inner.mul_assign((f, other)));
    }
}

impl<'a, F: RawField> MulAssign<(F, &'a Self)> for MLE<F> {
    #[inline(always)]
    fn mul_assign(&mut self, (f, other): (F, &'a Self)) {
        self.map_in_place_2(other, |inner, other| inner.mul_assign((f, other)));
    }
}

impl<F: RawField> MulAssign<F> for MLE<F> {
    #[inline(always)]
    fn mul_assign(&mut self, f: F) {
        self.map_in_place(|inner| inner.mul_assign(f));
    }
}

impl<F: RawField> Mul<F> for &MLE<F> {
    type Output = MLE<F>;

    #[inline(always)]
    fn mul(self, other: F) -> Self::Output {
        self.map(|inner| inner.mul(other)).into()
    }
}

impl<F: RawField> AddAssign<Self> for MLE<F> {
    #[inline(always)]
    fn add_assign(&mut self, other: Self) {
        self.map_in_place_2(&other, |inner, other| inner.add_assign(other));
    }
}

impl<'a, F: RawField> AddAssign<&'a Self> for MLE<F> {
    #[inline(always)]
    fn add_assign(&mut self, other: &'a Self) {
        self.map_in_place_2(other, |inner, other| inner.add_assign(other));
    }
}

impl<F: RawField> SubAssign<Self> for MLE<F> {
    #[inline(always)]
    fn sub_assign(&mut self, other: Self) {
        self.map_in_place_2(&other, |inner, other| inner.sub_assign(other));
    }
}

impl<'a, F: RawField> SubAssign<&'a Self> for MLE<F> {
    #[inline(always)]
    fn sub_assign(&mut self, other: &'a Self) {
        self.map_in_place_2(other, |inner, other| inner.sub_assign(other));
    }
}

impl<F: RawField> AddAssign<(F, Self)> for MLE<F> {
    #[inline(always)]
    fn add_assign(&mut self, (f, other): (F, Self)) {
        self.map_in_place_2(&other, |inner, other| inner.add_assign((f, other)));
    }
}

impl<'a, F: RawField> AddAssign<(F, &'a Self)> for MLE<F> {
    #[inline(always)]
    fn add_assign(&mut self, (f, other): (F, &'a Self)) {
        self.map_in_place_2(other, |inner, other| inner.add_assign((f, other)));
    }
}

impl<F: RawField> SubAssign<(F, Self)> for MLE<F> {
    #[inline(always)]
    fn sub_assign(&mut self, (f, other): (F, Self)) {
        self.map_in_place_2(&other, |inner, other| inner.sub_assign((f, other)));
    }
}

impl<'a, F: RawField> SubAssign<(F, &'a Self)> for MLE<F> {
    #[inline(always)]
    fn sub_assign(&mut self, (f, other): (F, &'a Self)) {
        self.map_in_place_2(other, |inner, other| inner.sub_assign((f, other)));
    }
}

impl<F: RawField> Display for MLE<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        <Inner<F> as Display>::fmt(&*self.0, f)
    }
}

// serialize:
// File: use our local serialization to read the entire file to a Vec<T>, and call T::serialize_uncompressed on Vec<T>
// Buffer: call T::serialize_uncompressed directly on the inner content (automatically writes length first)
impl<F: RawField> CanonicalSerialize for MLE<F> {
    fn serialize_with_mode<W: Write>(
        &self,
        mut writer: W,
        compress: ark_serialize::Compress,
    ) -> Result<(), ark_serialize::SerializationError> {
        (*self.0).serialize_with_mode(&mut writer, compress)
    }

    fn serialized_size(&self, _compress: ark_serialize::Compress) -> usize {
        todo!()
    }
}

// deserialize:
// read the length first
// if length greater than buffer size, it's a file
//        a. create a new file
//        b. read a batch of T at a time using canonicaldeserialize (call T::deserialize_uncompressed_unchecked from Canonical)
//        c. use SerializeRaw to write each T to the File
// if the length less than buffer size, it's a buffer
//        a. read one buffer batch and return it directly (just a Vec) Vec<T>::deserialize_uncompressed_unchecked
impl<F: RawField> CanonicalDeserialize for MLE<F> {
    fn deserialize_with_mode<R: ark_serialize::Read>(
        mut reader: R,
        compress: ark_serialize::Compress,
        validate: ark_serialize::Validate,
    ) -> Result<Self, ark_serialize::SerializationError> {
        Inner::<F>::deserialize_with_mode(&mut reader, compress, validate).map(Self::from_inner)
    }
}

impl<F: RawField + Valid> Valid for MLE<F> {
    fn check(&self) -> Result<(), ark_serialize::SerializationError> {
        unimplemented!()
    }

    fn batch_check<'a>(
        _: impl Iterator<Item = &'a Self> + Send,
    ) -> Result<(), ark_serialize::SerializationError>
    where
        Self: 'a,
    {
        unimplemented!()
    }
}

/// A helper function to build eq(x, r) recursively.
#[inline]
fn eq_x_r_helper<F: RawField>(r: &[F]) -> Option<FileVec<F>> {
    if r.is_empty() {
        None
    } else if r.len() <= LOG_BUFFER_SIZE as usize {
        let result = crate::util::build_eq_x_r_vec(r).unwrap();
        Some(FileVec::from_iter(result))
    } else {
        let prev = eq_x_r_helper(&r[1..])?;
        let result = prev
            .into_iter()
            .map(|cur| {
                let tmp = r[0] * cur;
                [cur - tmp, tmp]
            })
            .to_file_vec()
            .reinterpret_type();
        Some(result)
    }
}

#[cfg(test)]
mod test {
    use std::fs::File;

    use super::MLE;
    use crate::util::build_eq_x_r_vec;
    use ark_bls12_381::Fr;
    use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
    use ark_std::UniformRand;
    use ark_std::test_rng;
    use scribe_streams::{LOG_BUFFER_SIZE, file_vec::FileVec, iterator::BatchedIterator};

    #[test]
    fn multi_eq_x_r() {
        for i in 0..=8 {
            let num_vars = i + LOG_BUFFER_SIZE as usize;
            let r: Vec<Fr> = (0..num_vars).map(|_| Fr::rand(&mut test_rng())).collect();
            let eq_1 = MLE::eq_x_r(&r);
            let eq_2 = FileVec::from_iter(build_eq_x_r_vec(&r).unwrap().into_iter());
            eq_1.to_evals().zipped_for_each(eq_2.into_iter(), |a, b| {
                assert_eq!(*a, b);
            });
        }
    }

    #[test]
    fn test_serialize_mle() {
        let rng = &mut test_rng();
        let mle = MLE::<Fr>::rand(4, rng);
        let mut file = File::create("mle.test").unwrap();
        mle.serialize_uncompressed(&mut file).unwrap();

        let mut file_2 = File::open("mle.test").unwrap();
        let mle_2 = MLE::<Fr>::deserialize_uncompressed_unchecked(&mut file_2).unwrap();

        let vec: Vec<Fr> = mle.to_evals().iter().to_vec();
        let vec_2: Vec<Fr> = mle_2.to_evals().iter().to_vec();

        assert_eq!(vec, vec_2);
    }
}
