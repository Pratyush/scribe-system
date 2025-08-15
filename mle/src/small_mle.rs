use std::{fmt::Display, sync::Arc};

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Valid};
use ark_std::rand::RngCore;
use rayon::prelude::*;

use crate::{MLE, eq_iter::EqEvalIter};
use scribe_streams::{file_vec::FileVec, iterator::BatchedIterator, serialize::RawField};

#[derive(Debug, Hash, PartialEq, Eq, Clone)]
pub struct SmallMLE<F: RawField> {
    pub evals: Arc<FileVec<u64>>,
    pub num_vars: usize,
    _phantom: std::marker::PhantomData<F>,
}

impl<F: RawField> CanonicalSerialize for SmallMLE<F> {
    fn serialize_with_mode<W: std::io::Write>(
        &self,
        mut writer: W,
        compress: ark_serialize::Compress,
    ) -> Result<(), ark_serialize::SerializationError> {
        self.num_vars.serialize_with_mode(&mut writer, compress)?;
        self.evals.serialize_with_mode(writer, compress)
    }

    fn serialized_size(&self, compress: ark_serialize::Compress) -> usize {
        self.num_vars.serialized_size(compress) + self.evals.serialized_size(compress)
    }
}

impl<F: RawField> Valid for SmallMLE<F> {
    fn check(&self) -> Result<(), ark_serialize::SerializationError> {
        Ok(())
    }
}

impl<F: RawField> CanonicalDeserialize for SmallMLE<F> {
    fn deserialize_with_mode<R: std::io::Read>(
        mut reader: R,
        compress: ark_serialize::Compress,
        validate: ark_serialize::Validate,
    ) -> Result<Self, ark_serialize::SerializationError> {
        let num_vars = usize::deserialize_with_mode(&mut reader, compress, validate)?;
        let evals = FileVec::<u64>::deserialize_with_mode(reader, compress, validate)?;
        Ok(Self {
            evals: Arc::new(evals),
            num_vars,
            _phantom: std::marker::PhantomData,
        })
    }
}

impl<F: RawField> SmallMLE<F> {
    #[inline(always)]
    pub fn new(num_vars: usize) -> Self {
        let evals = Arc::new(FileVec::with_prefix_and_space("evals", 1 << num_vars));
        Self {
            evals,
            num_vars,
            _phantom: std::marker::PhantomData,
        }
    }

    #[inline(always)]
    pub fn from_evals(evals: FileVec<u64>, num_vars: usize) -> Self {
        Self {
            evals: Arc::new(evals),
            num_vars,
            _phantom: std::marker::PhantomData,
        }
    }

    /// Construct a polynomial with coefficients specified by `evals`.
    ///
    /// This should only be used for testing.
    #[inline(always)]
    pub fn from_evals_vec(evals: Vec<u64>, num_vars: usize) -> Self {
        assert_eq!(evals.len(), 1 << num_vars);
        let evals = FileVec::from_iter(evals);
        Self::from_evals(evals, num_vars)
    }

    #[inline(always)]
    pub fn evals_iter(
        &self,
    ) -> impl for<'a> BatchedIterator<Item = F, Batch<'a>: IndexedParallelIterator<Item = F>> {
        self.evals.iter().map(F::from)
    }

    #[inline(always)]
    pub fn num_vars(&self) -> usize {
        self.num_vars
    }

    /// Creates multiple identity permutation streams equal to the number of witness streams
    /// Identity permutations are continuous from one to another
    #[inline(always)]
    pub fn identity_permutation(num_vars: usize, num_chunks: usize) -> Vec<Self> {
        let shift = (1 << num_vars) as u64;
        (0..num_chunks as u64)
            .map(|i| {
                let evals = scribe_streams::iterator::from_fn(
                    |j| (j < shift as usize).then(|| i * shift + (j as u64)),
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
        let mut s_id_vec: Vec<_> = (0..len).collect();
        let mut s_perm_vec = vec![];
        for _ in 0..len {
            let index = rng.next_u64() as usize % s_id_vec.len();
            s_perm_vec.push(s_id_vec.remove(index) as u64);
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
    pub fn decrement_num_vars(&mut self) {
        if self.num_vars == 0 {
            panic!("Cannot decrement num_vars below 0");
        }
        self.num_vars -= 1;
    }

    /// Creates a new polynomial by fixing the first `partial_point.len()` variables to
    /// the values in `partial_point`.
    /// The number of variables in the result is `self.num_vars() - partial_point.len()`.
    #[inline]
    pub fn fix_variables(&self, partial_point: &[F]) -> MLE<F> {
        assert!(
            partial_point.len() <= self.num_vars,
            "invalid size of partial point"
        );

        let mut result: Option<MLE<F>> = None;

        for &r in partial_point {
            // Decrements num_vars internally.
            if let Some(s) = result.as_mut() {
                s.fold_odd_even_in_place(move |even, odd| *even + r * (*odd - even));
            } else {
                result = Some(
                    self.fold_odd_even(move |even, odd| F::from(*even) + r * F::from(*odd - even)),
                );
            }
        }
        result.unwrap()
    }

    /// Evaluates `self` at the given point.
    /// Returns `None` if the point has the wrong length.
    #[inline]
    pub fn evaluate(&self, point: &[F]) -> Option<F> {
        self.evaluate_with_bufs(point, &mut vec![])
    }

    /// Evaluates `self` at the given point.
    /// Returns `None` if the point has the wrong length.
    #[inline]
    pub fn evaluate_with_bufs(&self, point: &[F], self_buf: &mut Vec<u64>) -> Option<F> {
        if point.len() == self.num_vars {
            Some(
                self.evals
                    .iter_with_buf(self_buf)
                    .zip_with_bufs(EqEvalIter::new(point.to_vec()), &mut vec![], &mut vec![])
                    .map(|(a, b)| F::from(a) * b)
                    .sum(),
            )
        } else {
            None
        }
    }

    /// Creates a new polynomial whose evaluations are folded versions of `self`,
    /// folded according to the function `f`.
    /// After each fold, the number of variables is reduced by 1.
    #[inline]
    pub fn fold_odd_even(
        &self,
        f: impl Fn(&u64, &u64) -> F + Sync + 'static + Send + Sync,
    ) -> MLE<F> {
        assert!((1 << self.num_vars) % 2 == 0);

        let evals = match *self.evals {
            FileVec::File { .. } => self
                .evals
                .iter_chunk_mapped::<2, _, _>(move |chunk| f(&chunk[0], &chunk[1]))
                .to_file_vec(),
            FileVec::Buffer { ref buffer } => {
                let buffer = buffer
                    .par_chunks(2)
                    .map(|chunk| f(&chunk[0], &chunk[1]))
                    .with_min_len(1 << 8)
                    .collect();
                FileVec::new_buffer(buffer)
            },
        };
        MLE::from_evals(evals, self.num_vars - 1)
    }

    /// Creates a deep copy of the polynomial by copying the evaluations to a new stream.
    #[inline]
    pub fn deep_copy(&self) -> Self {
        Self::from_evals(self.evals.deep_copy(), self.num_vars)
    }
}

impl<F: RawField> Display for SmallMLE<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.evals.fmt(f)
    }
}

#[cfg(test)]
mod tests {
    use ark_bls12_381::Fr;
    use ark_ff::Field;
    use ark_poly::{DenseMultilinearExtension, MultilinearExtension, Polynomial};
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
            let eval = lde.evaluate(&point);
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

    #[test]
    fn add_assign() {
        let mut rng = ark_std::test_rng();
        for num_vars in LOG_BUFFER_SIZE..=(LOG_BUFFER_SIZE + 5) {
            let num_vars = num_vars as usize;
            let lde1 = DenseMultilinearExtension::<Fr>::rand(num_vars, &mut rng);
            let lde2 = DenseMultilinearExtension::<Fr>::rand(num_vars, &mut rng);
            let mut mle1 = MLE::from_evals_vec(lde1.to_evaluations(), num_vars);
            let mle2 = MLE::from_evals_vec(lde2.to_evaluations(), num_vars);
            mle1 += &mle2;
            let lde_sum = &lde1 + &lde2;
            let mle_sum = MLE::from_evals_vec(lde_sum.to_evaluations(), num_vars);
            mle1.evals()
                .iter()
                .zip(mle_sum.evals().iter())
                .for_each(|(a, b)| assert_eq!(a, b));
        }
    }
}
