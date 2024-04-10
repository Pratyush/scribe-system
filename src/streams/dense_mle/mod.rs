mod inner;
use std::{ops::{AddAssign, MulAssign, SubAssign}, path::Path, sync::Arc};

use ark_ff::Field;
pub use inner::*;

use crate::arithmetic::errors::ArithError;

use super::{iterator::BatchedIterator, file_vec::FileVec};

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct MLE<F: Field>(Arc<Inner<F>>);

impl<F: Field> MLE<F> {
    fn from_inner(inner: Inner<F>) -> Self {
        Self(Arc::new(inner))
    }

    fn map<T>(&self, f: impl FnOnce(&Inner<F>) -> T + Send + Sync) -> T {
        f(&*self.0)
    }   

    fn map_in_place<T>(&mut self, f: impl FnOnce(&mut Inner<F>) -> T + Send + Sync) -> T {
        let inner = Arc::get_mut(&mut self.0).expect("failed to get mutable reference: multiple references exist");
        f(inner)
    }
    
    fn map_in_place_2(&mut self, other: &Self, f: impl FnOnce(&mut Inner<F>, &Inner<F>)) {
        let inner = Arc::get_mut(&mut self.0).expect("failed to get mutable reference: multiple references exist");
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
    
    pub fn to_evals(self) -> FileVec<F> {
        let inner = Arc::try_unwrap(self.0).expect("failed to unwrap Arc: multiple references exist");
        inner.to_evals()
    }
    
    pub fn constant(c: F, num_vars: usize) -> Self {
        Inner::constant(c, num_vars).into()
    }
    
    pub fn eq_x_r(r: &[F]) -> Result<Self, ArithError> {
        eq_x_r_helper(r).map(|evals| Self::from_evals(evals, r.len()))
    }
    
    pub fn identity_permutation(num_vars: usize) -> Self {
        Inner::identity_permutation(num_vars).into()
    }
    
    pub fn rand<R: ark_std::rand::RngCore>(num_vars: usize, rng: &mut R) -> Self {
        Inner::rand(num_vars, rng).into()
    }
    
    /// Sample `degree` random polynomials, and returns the sum of their Hadamard product.
    pub fn rand_product_with_sum<R: ark_std::rand::RngCore>(num_vars: usize, degree: usize, rng: &mut R) -> (Vec<Self>, F) {
        let (v, f) = Inner::rand_product_with_sum(num_vars, degree, rng);
        (v.into_iter().map(From::from).collect(), f)
    }
    
    pub fn rand_product_summing_to_zero<R: ark_std::rand::RngCore>(num_vars: usize, degree: usize, rng: &mut R) -> Vec<Self> {
        Inner::rand_product_summing_to_zero(num_vars, degree, rng).into_iter().map(From::from).collect()
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


impl<F: Field> MulAssign<F> for MLE<F> {
    fn mul_assign(&mut self, other: F) {
        self.map_in_place(|inner| inner.mul_assign(other));
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
    } else if r.len() == 1 {
        // initializing the buffer with [1-r_0, r_0]
        Ok(FileVec::from_iter([F::one() - r[0], r[0]]))
    } else {
        let prev = eq_x_r_helper(&r[1..])?;
        Ok(prev.iter().flat_map(|cur| {
            let tmp = r[0] * cur;
            [cur - tmp, tmp]
        }).to_file_vec())
    }
}

// mod inner;
// use inner::Inner;

/* use crate::hyperplonk::arithmetic::errors::ArithErrors;

use super::ReadWriteStream;

#[derive(Debug)]
pub struct DenseMLPolyStream<F: Field>(Arc<Mutex<Inner<F>>>);




impl<F: Field> DenseMLPolyStream<F> {
    pub(super) fn with_path<'a>(num_vars: usize, read_path: impl Into<Option<&'a str>>, write_path: impl Into<Option<&'a str>>) -> Self {
        Inner::with_path(num_vars, read_path, write_path).into()
    }
    
    pub fn new_from_tempfile(num_vars: usize) -> Self {
        Inner::new_from_tempfile(num_vars).into()
    }

    pub fn new_single_stream(num_vars: usize, path: Option<&str>) -> Self {
        Inner::new_single_stream(num_vars, path).into()
    }

    pub(super) fn read_next(&mut self) -> Option<F> {
        self.map(|inner| inner.read_next())
    }
    
    // used for creating eq_x_r, recursively building which requires reading one element while writing two elements
    pub(super) fn read_next_unchecked(&mut self) -> Option<F> {
        self.map(|inner| inner.read_next_unchecked())
    }

    pub(super) fn read_restart(&mut self) {
        self.map(|inner| inner.read_restart());
    }


    pub(super) fn write_next(&mut self, field: impl Borrow<F>) -> Option<()> {
        self.map(|inner| inner.write_next(field))
    }

    // Used for testing purpose when writing to a random stream without checking read and write pointer positions
    pub(super) fn write_next_unchecked(&mut self, field: impl Borrow<F>) -> Option<()> {
        self.map(|inner| inner.write_next_unchecked(field))
    }

    pub(super) fn write_restart(&mut self) {
        self.map(|inner| inner.write_restart());
    }

    pub fn num_vars(&self) -> usize {
        self.map(|inner| inner.num_vars())
    }

    pub(super) fn swap_read_write(&mut self) {
        self.map(|inner| inner.swap_read_write());
    }
    
    fn new_read_stream(&mut self) {
        self.map(|inner| inner.new_read_stream())
    }
    
     // Assumes that `buffer` is empty.
    fn read_to_buf(&mut self, buffer: &mut Vec<F>, buffer_size: usize) -> Option<()> {
        self.map(|inner| inner.read_to_buf(buffer, buffer_size))
    }

    fn write_buf(&mut self, buffer: &[impl Borrow<F>]) -> Option<()> {
        self.map(|inner| inner.write_buf(buffer))
    }
    
    pub fn map_in_place(&mut self, f: impl Fn(&F) -> F + Sync) -> Option<()> {
        self.map(|inner| inner.map_in_place(f))
    }
    
    pub fn fold_odd_even(&mut self, f: impl Fn(&F, &F) -> F + Sync) -> Option<()> {
        self.map(|inner| inner.fold_odd_even(f))
    }
    
    pub fn expand_odd_even(&mut self, f: impl Fn(&F) -> (F, F) + Sync) -> Option<()> {
        self.map(|inner| inner.expand_odd_even(f))
    }
    
    pub fn combine_in_place(
        &mut self, 
        other: &mut Self, 
        f: impl Fn(&F, &F) -> F + Sync
    ) -> Option<()> {
        self.map(|inner| inner.combine_in_place(other, f))
    }
    
    pub fn combine_with(
        &mut self, 
        other: &mut Self, 
        f: impl Fn(&F, &F) -> F + Sync
    ) -> Option<Self> {
        self.map(|inner| inner.combine_with(other, f))
    }
    
    pub fn combine_many_with(
        streams: &[&mut Self], 
        f: impl Fn(&mut F, &F) + Sync
    ) -> Option<Self> {
        let streams = streams.iter().map(|s| s.0.lock().unwrap()).collect::<Vec<_>>();
        let streams_mut = streams.iter().map(|s| s.borrow_mut()).collect::<Vec<_>>();
        Inner::combine_many_with(streams.as_slice(), f)
    }
    
    
    pub fn new_from_path(num_vars: usize, read_path: &str, write_path: &str) -> Self {
        Inner::new_from_path(num_vars, read_path, write_path).into()
    }

    pub fn new_from_path_single_stream(num_vars: usize, path: &str) -> Self {
        Inner::new_from_path_single_stream(num_vars, path).into()
    }

    pub fn new_from_tempfile_single_stream(num_vars: usize) -> Self {
        Inner::new_from_tempfile_single_stream(num_vars).into()
    }

    pub fn from_evaluations_vec(
        num_vars: usize,
        evaluations: Vec<F>,
        read_path: Option<&str>,
        write_path: Option<&str>,
    ) -> Self {
        Inner::from_evaluations_vec(num_vars, evaluations, read_path, write_path).into()
    }

    pub fn from_evaluations_slice(
        num_vars: usize,
        evaluations: &[F],
        read_path: Option<&str>,
        write_path: Option<&str>,
    ) -> Self {
        Inner::from_evaluations_slice(num_vars, evaluations, read_path, write_path).into()
    }

    pub fn decrement_num_vars(&mut self) {
        self.map(|inner| inner.decrement_num_vars());
    }

    // store the result in a tempfile; might provide an option for writing to a new file path instead
    // original version spits out a new poly, while we modify the original poly (stream)
    pub fn fix_variables(&mut self, partial_point: &[F]) {
        self.map(|inner| inner.fix_variables(partial_point));
    }

    // Evaluate at a specific point to one field element
    pub fn evaluate(&mut self, point: &[F]) -> Option<F> {
        self.map(|inner| inner.evaluate(point))
    }

    pub fn rand<R: RngCore>(num_vars: usize, rng: &mut R) -> Self {
        Inner::rand(num_vars, rng).into()
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
        let (v, f) = Inner::random_mle_list(nv, degree, rng, read_path, write_path);
        (v.into_iter().map(From::from).collect(), f)
    }

    // Build a randomize list of mle-s whose sum is zero.
    // loaded to streams from vectors and therefore is for testing purpose only.
    // for multiple multiplicands (streams), the first stream is zero everywhere while the rest of the streams are arbitrary.
    pub fn random_zero_mle_list<R: RngCore>(
        nv: usize,
        degree: usize,
        rng: &mut R,
    ) -> Vec<Self> {
        Inner::random_zero_mle_list(nv, degree, rng)
            .into_iter()
            .map(From::from)
            .collect()
    }

    pub fn const_mle(
        c: F,
        nv: usize,
        read_path: Option<&str>,
        write_path: Option<&str>,
    ) -> Self {
        Inner::const_mle(c, nv, read_path, write_path).into()
    }
    
    pub fn copy(
        &mut self,
        read_path: Option<&str>,
        write_path: Option<&str>,
    ) -> Self {
        self.map(|inner| inner.copy(read_path, write_path)).into()
    }
    
    /// merge a set of polynomials. Returns an error if the
    /// polynomials do not share a same number of nvs.
    pub fn merge(polynomials: &mut [Self], num_vars: usize) -> Result<Self, ArithErrors> {
        let polynomials = polynomials.iter().map(|s| s.0.lock().unwrap()).collect::<Vec<_>>();
        let polynomials_mut = polynomials.iter().map(|s| s.borrow_mut()).collect::<Vec<_>>();
        Inner::merge(polynomials_mut.as_mut_slice(), num_vars).map(From::from)
    }
    
    pub fn add_assign(&mut self, (coeff, other): (F, &mut Self)) -> Option<()> {
        self.combine_in_place(other, |a, b| *a + coeff * *b)
    }
    
    pub fn product(streams: &[Self]) -> Option<Self> {
        Self::combine_many_with(streams, |a, b| *a = *a * b)
    }
    
    pub fn batch_inversion(&mut self) -> Option<Self> {
        self.map(|inner| inner.batch_inversion())
    }
}
 */