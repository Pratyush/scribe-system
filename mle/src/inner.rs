use std::{
    fmt::Display,
    ops::{AddAssign, Mul, MulAssign, SubAssign},
};

use ark_ff::batch_inversion;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::RngCore;
use rayon::prelude::*;

use crate::eq_iter::EqEvalIterWithBuf;
use scribe_streams::{
    LOG_BUFFER_SIZE,
    file_vec::FileVec,
    iterator::{BatchedIterator, from_fn, repeat},
    serialize::RawField,
};

#[derive(Debug, Hash, PartialEq, Eq, CanonicalDeserialize, CanonicalSerialize)]
pub struct Inner<F: RawField> {
    pub evals: FileVec<F>,
    pub num_vars: usize,
}

impl<F: RawField> Inner<F> {
    #[inline(always)]
    pub fn new(num_vars: usize) -> Self {
        let evals = FileVec::with_prefix_and_space("evals", 1 << num_vars);
        Self { evals, num_vars }
    }

    #[inline(always)]
    pub fn from_evals(evals: FileVec<F>, num_vars: usize) -> Self {
        Self { evals, num_vars }
    }

    /// Construct a polynomial with coefficients specified by `evals`.
    ///
    /// This should only be used for testing.
    #[inline(always)]
    pub fn from_evals_vec(evals: Vec<F>, num_vars: usize) -> Self {
        assert_eq!(evals.len(), 1 << num_vars);
        let evals = FileVec::from_iter(evals);
        Self { evals, num_vars }
    }

    #[inline(always)]
    pub fn evals(&self) -> &FileVec<F> {
        &self.evals
    }

    #[inline(always)]
    pub fn evals_mut(&mut self) -> &mut FileVec<F> {
        &mut self.evals
    }

    #[inline(always)]
    pub fn to_evals(self) -> FileVec<F> {
        self.evals
    }

    #[inline(always)]
    pub fn num_vars(&self) -> usize {
        self.num_vars
    }

    /// Construct a polynomial with all coefficients equal to `coeff`
    #[inline(always)]
    pub fn constant(coeff: F, num_vars: usize) -> Self {
        let evals = FileVec::from_batched_iter(repeat(coeff, 1 << num_vars));
        Self::from_evals(evals, num_vars)
    }

    /// Creates multiple identity permutation streams equal to the number of witness streams
    /// Identity permutations are continuous from one to another
    #[inline(always)]
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

    #[inline(always)]
    pub fn rand<R: ark_std::rand::RngCore>(num_vars: usize, rng: &mut R) -> Self {
        let evals = FileVec::from_iter((0..(1 << num_vars)).map(|_| F::rand(rng)));
        Self::from_evals(evals, num_vars)
    }

    #[inline(always)]
    pub fn decrement_num_vars(&mut self) {
        if self.num_vars == 0 {
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
    #[inline]
    pub fn fix_variables_in_place(&mut self, partial_point: &[F]) {
        assert!(
            partial_point.len() <= self.num_vars,
            "invalid size of partial point"
        );

        for &r in partial_point {
            // Decrements num_vars internally.
            self.fold_odd_even_in_place(|even, odd| r * (*odd - even) + even);
        }
    }

    /// Creates a new polynomial by fixing the first `partial_point.len()` variables to
    /// the values in `partial_point`.
    /// The number of variables in the result is `self.num_vars() - partial_point.len()`.
    #[inline]
    pub fn fix_variables(&self, partial_point: &[F]) -> Self {
        assert!(
            partial_point.len() <= self.num_vars,
            "invalid size of partial point"
        );

        let mut result: Option<Self> = None;

        for &r in partial_point {
            // Decrements num_vars internally.
            if let Some(s) = result.as_mut() {
                s.fold_odd_even_in_place(|even, odd| *even + r * (*odd - even))
            } else {
                result = Some(self.fold_odd_even(|even, odd| *even + r * (*odd - even)));
            }
        }
        result.unwrap_or_else(|| self.deep_copy())
    }

    /// Evaluates `self` at the given point.
    /// Returns `None` if the point has the wrong length.
    #[inline]
    pub fn evaluate(&self, point: &[F]) -> Option<F> {
        self.evaluate_with_bufs(point, &mut vec![], &mut vec![])
    }

    /// Evaluates `self` at the given point.
    /// Returns `None` if the point has the wrong length.
    #[inline]
    pub fn evaluate_with_bufs(
        &self,
        point: &[F],
        self_buf: &mut Vec<F>,
        eq_buf: &mut Vec<F>,
    ) -> Option<F> {
        if point.len() == self.num_vars {
            Some(
                self.evals
                    .iter_with_buf(self_buf)
                    .zip(EqEvalIterWithBuf::new(point.to_vec(), eq_buf))
                    .map(|(a, b)| a * b)
                    .sum(),
            )
        } else {
            None
        }
    }

    /// Modifies self by folding the evaluations over the hypercube with the function `f`.
    /// After each fold, the number of variables is reduced by 1.
    #[inline]
    pub fn fold_odd_even_in_place(&mut self, f: impl Fn(&F, &F) -> F + Sync) {
        assert!((1 << self.num_vars) % 2 == 0);
        if self.num_vars <= LOG_BUFFER_SIZE as usize {
            self.evals.convert_to_buffer_in_place();
        }

        match self.evals {
            FileVec::File { .. } => {
                self.evals = self
                    .evals
                    .iter_chunk_mapped_with_buf::<2, _, _>(
                        |chunk| f(&chunk[0], &chunk[1]),
                        &mut vec![],
                    )
                    .to_file_vec();
            },
            FileVec::Buffer { ref mut buffer } => {
                let new_buffer = std::mem::take(buffer);
                *buffer = new_buffer
                    .par_chunks(2)
                    .map(|chunk| f(&chunk[0], &chunk[1]))
                    .with_min_len(1 << 8)
                    .collect();
            },
        }
        self.decrement_num_vars();
    }

    /// Creates a new polynomial whose evaluations are folded versions of `self`,
    /// folded according to the function `f`.
    /// After each fold, the number of variables is reduced by 1.
    #[inline]
    pub fn fold_odd_even(&self, f: impl Fn(&F, &F) -> F + Sync) -> Self {
        assert!((1 << self.num_vars) % 2 == 0);
        let evals = self
            .evals
            .iter_chunk_mapped_with_buf::<2, _, _>(|chunk| f(&chunk[0], &chunk[1]), &mut vec![])
            .to_file_vec();
        Self {
            evals,
            num_vars: self.num_vars - 1,
        }
    }

    /// Modifies self by replacing evaluations over the hypercube with their inverse.
    #[inline]
    pub fn invert_in_place(&mut self) {
        self.evals.batched_for_each(|chunk| batch_inversion(chunk));
    }

    /// Creates a new polynomial whose evaluations over the hypercube are
    /// the inverses of the evaluations of this polynomial.
    #[inline]
    pub fn invert(&self) -> Self {
        let mut result = self.deep_copy();
        result.invert_in_place();
        result
    }

    /// Creates a deep copy of the polynomial by copying the evaluations to a new stream.
    #[inline]
    pub fn deep_copy(&self) -> Self {
        Self::from_evals(self.evals.deep_copy(), self.num_vars)
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
        let mut buf = vec![];
        let product_poly = polys
            .iter()
            .fold(Self::constant(F::one(), num_vars), |mut acc, p| {
                acc.evals
                    .zipped_for_each(p.evals.iter_with_buf(&mut buf), |a, b| *a *= b);
                acc
            });

        (polys, product_poly.evals.iter_with_buf(&mut buf).sum())
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
    #[inline(always)]
    fn mul_assign(&mut self, other: Self) {
        self.evals
            .zipped_for_each(other.evals.iter_with_buf(&mut vec![]), |a, b| *a *= b);
    }
}

impl<'a, F: RawField> MulAssign<&'a Self> for Inner<F> {
    #[inline(always)]
    fn mul_assign(&mut self, other: &'a Self) {
        self.evals
            .zipped_for_each(other.evals.iter_with_buf(&mut vec![]), |a, b| *a *= b);
    }
}

impl<F: RawField> AddAssign<Self> for Inner<F> {
    #[inline(always)]
    fn add_assign(&mut self, other: Self) {
        self.evals
            .zipped_for_each(other.evals.iter_with_buf(&mut vec![]), |a, b| *a += b);
    }
}

impl<'a, F: RawField> AddAssign<&'a Self> for Inner<F> {
    #[inline(always)]
    fn add_assign(&mut self, other: &'a Self) {
        self.evals
            .zipped_for_each(other.evals.iter_with_buf(&mut vec![]), |a, b| *a += b);
    }
}

impl<F: RawField> SubAssign<Self> for Inner<F> {
    #[inline(always)]
    fn sub_assign(&mut self, other: Self) {
        self.evals
            .zipped_for_each(other.evals.iter_with_buf(&mut vec![]), |a, b| *a -= b);
    }
}

impl<'a, F: RawField> SubAssign<&'a Self> for Inner<F> {
    #[inline(always)]
    fn sub_assign(&mut self, other: &'a Self) {
        self.evals
            .zipped_for_each(other.evals.iter_with_buf(&mut vec![]), |a, b| *a -= b);
    }
}

impl<F: RawField> MulAssign<(F, Self)> for Inner<F> {
    #[inline(always)]
    fn mul_assign(&mut self, (f, other): (F, Self)) {
        if f.is_one() {
            *self *= other;
        } else {
            self.evals
                .zipped_for_each(other.evals.iter_with_buf(&mut vec![]), |a, b| *a *= f * b);
        }
    }
}

impl<'a, F: RawField> MulAssign<(F, &'a Self)> for Inner<F> {
    #[inline(always)]
    fn mul_assign(&mut self, (f, other): (F, &'a Self)) {
        if f.is_one() {
            *self *= other;
        } else {
            self.evals
                .zipped_for_each(other.evals.iter_with_buf(&mut vec![]), |a, b| *a *= f * b);
        }
    }
}

impl<F: RawField> MulAssign<F> for Inner<F> {
    #[inline(always)]
    fn mul_assign(&mut self, f: F) {
        if !f.is_one() {
            self.evals.for_each(|a| *a *= f);
        }
    }
}

impl<F: RawField> Mul<F> for &Inner<F> {
    type Output = Inner<F>;
    #[inline(always)]
    fn mul(self, f: F) -> Self::Output {
        if f.is_one() {
            self.deep_copy()
        } else {
            let evals = self
                .evals
                .iter_with_buf(&mut vec![])
                .map(|a| f * a)
                .to_file_vec();
            Inner::from_evals(evals, self.num_vars)
        }
    }
}

impl<F: RawField> AddAssign<(F, Self)> for Inner<F> {
    #[inline(always)]
    fn add_assign(&mut self, (f, other): (F, Self)) {
        if f.is_one() {
            *self += other;
        } else {
            self.evals
                .zipped_for_each(other.evals.iter_with_buf(&mut vec![]), |a, b| *a += f * b);
        }
    }
}

impl<'a, F: RawField> AddAssign<(F, &'a Self)> for Inner<F> {
    #[inline(always)]
    fn add_assign(&mut self, (f, other): (F, &'a Self)) {
        if f.is_one() {
            *self += other;
        } else {
            self.evals
                .zipped_for_each(other.evals.iter_with_buf(&mut vec![]), |a, b| *a += f * b);
        }
    }
}

impl<F: RawField> SubAssign<(F, Self)> for Inner<F> {
    #[inline(always)]
    fn sub_assign(&mut self, (f, other): (F, Self)) {
        if f.is_one() {
            *self -= other;
        } else {
            self.evals
                .zipped_for_each(other.evals.iter_with_buf(&mut vec![]), |a, b| *a -= f * b);
        }
    }
}

impl<'a, F: RawField> SubAssign<(F, &'a Self)> for Inner<F> {
    #[inline(always)]
    fn sub_assign(&mut self, (f, other): (F, &'a Self)) {
        if f.is_one() {
            *self -= other;
        } else {
            self.evals
                .zipped_for_each(other.evals.iter_with_buf(&mut vec![]), |a, b| *a -= f * b);
        }
    }
}

impl<F: RawField> Display for Inner<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.evals.fmt(f)
    }
}

#[cfg(test)]
mod tests {
    use ark_bls12_381::Fr;
    use ark_ff::Field;
    use ark_poly::{DenseMultilinearExtension, MultilinearExtension};
    use ark_std::UniformRand;
    use rayon::prelude::*;

    use crate::MLE;
    use scribe_streams::{
        LOG_BUFFER_SIZE,
        iterator::{BatchAdapter, BatchedIterator},
    };

    #[test]
    fn evaluate() {
        let mut rng = ark_std::test_rng();
        for num_vars in LOG_BUFFER_SIZE..=(LOG_BUFFER_SIZE + 5) {
            let num_vars = num_vars as usize;
            let lde = DenseMultilinearExtension::rand(num_vars, &mut rng);
            let point = (0..num_vars)
                .map(|_| Fr::rand(&mut rng))
                .collect::<Vec<_>>();
            let mle = MLE::from_evals_vec(lde.to_evaluations(), num_vars);
            let eval = lde.evaluate(&point).unwrap();
            let eval_2 = mle.evaluate(&point).unwrap();
            let lde_evals = BatchAdapter::from(lde.to_evaluations().into_iter());
            mle.evals()
                .iter()
                .zip(lde_evals)
                .for_each(|(a, b)| assert_eq!(a, b));
            assert_eq!(eval, evaluate_opt(&lde, &point));
            assert_eq!(eval, eval_2);
        }
    }

    pub fn evaluate_opt<F: Field>(poly: &DenseMultilinearExtension<F>, point: &[F]) -> F {
        assert_eq!(poly.num_vars, point.len());
        fix_variables(poly, point).evaluations[0]
    }

    pub fn fix_variables<F: Field>(
        poly: &DenseMultilinearExtension<F>,
        partial_point: &[F],
    ) -> DenseMultilinearExtension<F> {
        assert!(
            partial_point.len() <= poly.num_vars,
            "invalid size of partial point"
        );
        let nv = poly.num_vars;
        let mut poly = poly.evaluations.to_vec();
        let dim = partial_point.len();
        // evaluate single variable of partial point from left to right
        for (i, point) in partial_point.iter().enumerate().take(dim) {
            poly = fix_one_variable_helper(&poly, nv - i, point);
        }

        DenseMultilinearExtension::<F>::from_evaluations_slice(nv - dim, &poly[..(1 << (nv - dim))])
    }

    fn fix_one_variable_helper<F: Field>(data: &[F], nv: usize, point: &F) -> Vec<F> {
        let mut res = vec![F::zero(); 1 << (nv - 1)];

        res.par_iter_mut().enumerate().for_each(|(i, x)| {
            *x = data[i << 1] + (data[(i << 1) + 1] - data[i << 1]) * point;
        });

        res
    }
}
