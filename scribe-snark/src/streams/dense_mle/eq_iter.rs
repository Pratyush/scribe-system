use itertools::Itertools;
use rayon::{iter::MinLen, prelude::*};

use crate::{
    arithmetic::eq_eval,
    streams::{iterator::BatchedIterator, serialize::RawPrimeField, BUFFER_SIZE},
};

/// An iterator that generates the evaluations of the polynomial
/// eq(r, y || x) over the Boolean hypercube.
///
/// Here y = `self.fixed_vars`, and r = `self.r`.
pub struct EqEvalIter<F> {
    multiplier: F,
    cur_index: usize,
    r: Vec<F>,
    one_minus_r: Vec<F>,
    zero_values: Vec<F>,
    one_values: Vec<F>,
    boolean_mask: usize,
    r_only_boolean: usize,
}

impl<F: RawPrimeField> EqEvalIter<F> {
    pub fn new(r: Vec<F>) -> Self {
        Self::new_with_multiplier(r, F::one())
    }

    pub fn new_with_multiplier(r: Vec<F>, multiplier: F) -> Self {
        let mut r_inv = r.clone();
        ark_ff::batch_inversion(&mut r_inv);
        assert_eq!(r.len(), r_inv.len());

        let one_minus_r = r.iter().map(|r| F::one() - r).collect::<Vec<_>>();
        let mut one_minus_r_inv = one_minus_r.clone();
        ark_ff::batch_inversion(&mut one_minus_r_inv);
        assert_eq!(r.len(), one_minus_r.len());
        let boolean_mask = r
            .iter()
            .enumerate()
            .map(|(i, r_j)| ((r_j.is_one() || r_j.is_zero()) as usize) << i)
            .sum::<usize>();
        let r_only_boolean = r
            .iter()
            .enumerate()
            .map(|(i, r_j)| (r_j.is_one() as usize) << i)
            .sum::<usize>();

        let zero_values = one_minus_r_inv
            .into_iter()
            .zip_eq(&r)
            .map(|(r, one_minus_r_inv)| r * one_minus_r_inv)
            .collect::<Vec<_>>();

        let one_values = r_inv
            .into_iter()
            .zip_eq(&one_minus_r)
            .map(|(one_minus_r, r_inv)| one_minus_r * r_inv)
            .collect::<Vec<_>>();

        EqEvalIter {
            cur_index: 0,
            multiplier,
            r,
            one_minus_r,
            zero_values,
            one_values,
            r_only_boolean,
            boolean_mask,
        }
    }

    pub fn new_with_fixed_vars(r: Vec<F>, fixed_vars: Vec<F>) -> Self {
        assert!(fixed_vars.len() <= r.len());
        let (first_r, rest_r) = r.split_at(fixed_vars.len());
        let multiplier = eq_eval(first_r, &fixed_vars).unwrap();
        Self::new_with_multiplier(rest_r.to_vec(), multiplier)
    }
}

impl<F: RawPrimeField> BatchedIterator for EqEvalIter<F> {
    type Item = F;
    type Batch = MinLen<rayon::vec::IntoIter<F>>;

    fn next_batch(&mut self) -> Option<Self::Batch> {
        let nv = self.r.len();
        let total_num_evals = 1 << nv;
        if self.cur_index >= total_num_evals {
            None
        } else {
            let batch_size = total_num_evals.min(BUFFER_SIZE);
            let batch_start = self.cur_index;
            let batch_end = self.cur_index + batch_size;

            let result = (batch_start..batch_end)
                .into_par_iter()
                .step_by(CHUNK_SIZE)
                .flat_map(|c_start| {
                    let c_end = c_start + CHUNK_SIZE.min(batch_size);
                    let starting_value =
                        compute_starting_value(&self, c_start, c_end) * self.multiplier;
                    p(&self, starting_value, c_start, c_end)
                })
                .collect::<Vec<_>>();
            self.cur_index += batch_size;
            Some(result.into_par_iter().with_min_len(1 << 7))
        }
    }
}

const CHUNK_SIZE: usize = if BUFFER_SIZE < (1 << 14) {
    BUFFER_SIZE
} else {
    1 << 14
};

fn p<F: RawPrimeField>(
    iter: &EqEvalIter<F>,
    starting_value: F,
    start: usize,
    end: usize,
) -> Vec<F> {
    let nv = iter.r.len();
    let mut next_m = starting_value;
    (start..end)
        .map(|i| {
            let next_i = i + 1;
            let this_m = next_m;
            let this_is_zero = ((i & iter.boolean_mask) ^ iter.r_only_boolean) != 0;

            for j in 0..nv {
                let r_j_is_boolean = (iter.boolean_mask & (1 << j)) != 0;
                if r_j_is_boolean {
                    continue;
                }
                let cur_bit = i & (1 << j);
                let next_bit = next_i & (1 << j);
                if cur_bit != next_bit {
                    if cur_bit == 0 {
                        next_m *= iter.zero_values[j];
                        break;
                    } else {
                        next_m *= iter.one_values[j];
                    }
                }
            }

            if this_is_zero {
                F::zero()
            } else {
                this_m
            }
        })
        .collect()
}

/// Computes the starting value for chunk `chunk_idx` by using the product
/// of `r` and `one_minus_r` vectors and the binary decomposition of `chunk_idx * chunk_size - 1`
#[inline]
fn compute_starting_value<F: RawPrimeField>(
    iter: &EqEvalIter<F>,
    c_start: usize,
    c_end: usize,
) -> F {
    // Compute the location where `c` differs from `r` in the boolean locations;
    // Flipping those bits will give us the first index where the value is non-zero.
    let new_c = c_start | iter.r_only_boolean;
    if !((c_start..c_end).contains(&new_c)) {
        F::zero()
    } else {
        let mut m = F::one();
        for j in 0..iter.r.len() {
            if (new_c >> j) & 1 == 0 {
                m *= iter.one_minus_r[j];
            } else {
                m *= iter.r[j];
            }
        }
        m
    }
}

#[cfg(test)]
mod test {
    use crate::streams::{dense_mle::eq_iter::EqEvalIter, iterator::BatchedIterator, MLE};
    use ark_bls12_381::Fr;
    use ark_std::{test_rng, UniformRand};

    #[test]
    fn eq_iter_test() {
        let rng = &mut test_rng();
        for nv in 9..20 {
            let r = (0..nv).map(|_| Fr::rand(rng)).collect::<Vec<_>>();
            let iter = EqEvalIter::new(r.clone());
            let eq = MLE::eq_x_r(&r);
            let eq_result = eq.evals().iter().to_vec();
            let iter_result = iter.to_vec();
            for (i, (a, b)) in eq_result.iter().zip(&iter_result).enumerate() {
                assert_eq!(a, b, "failed for {nv} at {i}");
            }
        }
    }

    #[test]
    fn eq_iter_with_booleans_test() {
        let rng = &mut ark_std::test_rng();
        for nv in 9..20 {
            let r = (0..nv)
                .map(|_| {
                    // Set some of the r values to be boolean at random.
                    if bool::rand(rng) {
                        Fr::from(bool::rand(rng) as u8)
                    } else {
                        Fr::rand(rng)
                    }
                })
                .collect::<Vec<_>>();
            let iter = EqEvalIter::new(r.clone());
            let eq = MLE::eq_x_r(&r);
            let eq_result = eq.evals().iter().map(|e| e.to_string()).to_vec();
            let iter_result = iter.map(|e| e.to_string()).to_vec();
            assert_eq!(eq_result, iter_result, "failed for {nv} with r = {r:?}");
        }
    }

    #[test]
    fn eq_iter_fix_variables_test() {
        let rng = &mut test_rng();
        for nv in 1..20 {
            let r = (0..nv).map(|_| Fr::rand(rng)).collect::<Vec<_>>();
            let eq = MLE::eq_x_r(&r);
            for fixed_nv in 0..nv {
                let fixed_vars = (0..fixed_nv).map(|_| Fr::rand(rng)).collect::<Vec<_>>();
                let fixed_eq = eq.fix_variables(&fixed_vars);
                let fixed_eq_evals = fixed_eq.evals().iter().to_vec();
                let iter = EqEvalIter::new_with_fixed_vars(r.clone(), fixed_vars);
                let fixed_eq_iter_evals = iter.to_vec();

                assert_eq!(
                    fixed_eq_iter_evals.len(),
                    fixed_eq_evals.len(),
                    "failed for num_vars = {nv} and num_fixed_vars = {fixed_nv}"
                );
                for (i, (a, b)) in fixed_eq_evals.iter().zip(&fixed_eq_iter_evals).enumerate() {
                    assert_eq!(
                        a, b,
                        "failed for num_vars = {nv} at {i} and num_fixed_vars = {fixed_nv}"
                    );
                }
            }
        }
    }
}
