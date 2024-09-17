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
    r: Vec<F>,
    cur_index: usize,
    one_minus_r: Vec<F>,
    one_minus_r_inv: Vec<F>,
    r_inv: Vec<F>,
}

impl<F: RawPrimeField> EqEvalIter<F> {
    pub fn new(r: Vec<F>) -> Self {
        Self::new_with_multiplier(r, F::one())
    }

    pub fn new_with_multiplier(r: Vec<F>, multiplier: F) -> Self {
        let mut r_inv = r.clone();
        ark_ff::batch_inversion(&mut r_inv);

        let one_minus_r = r.iter().map(|r| F::one() - r).collect::<Vec<_>>();
        let mut one_minus_r_inv = one_minus_r.clone();
        ark_ff::batch_inversion(&mut one_minus_r_inv);
        EqEvalIter {
            r,
            cur_index: 0,
            one_minus_r,
            one_minus_r_inv,
            r_inv,
            multiplier,
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
            let num_chunks = if batch_size < CHUNK_SIZE {
                1
            } else {
                batch_size / CHUNK_SIZE
            };
            let chunk_starting_values = (0..num_chunks).into_par_iter().map(|c| {
                compute_starting_value(
                    &self.r,
                    &self.one_minus_r,
                    self.cur_index + c * CHUNK_SIZE,
                    nv,
                ) * self.multiplier
            });
            let result = (0..batch_size)
                .into_par_iter()
                .step_by(CHUNK_SIZE)
                .zip(chunk_starting_values)
                .map(|(c, starting_value)| {
                    p(
                        &self.r,
                        &self.r_inv,
                        &self.one_minus_r,
                        &self.one_minus_r_inv,
                        starting_value,
                        c,
                        c + CHUNK_SIZE,
                    )
                })
                .flat_map(|v| v)
                .collect::<Vec<_>>();
            self.cur_index += batch_size;
            Some(result.into_par_iter().with_min_len(1 << 7))
        }
    }
}

const CHUNK_SIZE: usize = 1 << 14;

fn p<F: RawPrimeField>(
    r: &[F],
    r_inv: &[F],
    one_minus_r: &[F],
    one_minus_r_inv: &[F],
    starting_value: F,
    start: usize,
    end: usize,
) -> Vec<F> {
    let nv = r.len();
    let mut current_m = starting_value;
    (start..end)
        .map(|c| {
            let m = current_m;
            for j in 0..nv {
                if (c >> j) & 1 == 0 {
                    current_m = current_m * r[j] * one_minus_r_inv[j];
                    break;
                } else {
                    current_m = current_m * one_minus_r[j] * r_inv[j];
                }
            }
            m
        })
        .collect()
}

/// Computes the starting value for chunk `chunk_idx` by using the product
/// of `r` and `one_minus_r` vectors and the binary decomposition of `chunk_idx * chunk_size - 1`
fn compute_starting_value<F: RawPrimeField>(
    r: &[F],
    one_minus_r: &[F],
    c: usize,
    num_vars: usize,
) -> F {
    let mut m = F::one();
    for j in 0..num_vars {
        if (c >> j) & 1 == 0 {
            m = m * one_minus_r[j];
        } else {
            m = m * r[j];
        }
    }
    m
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
            let eq = MLE::eq_x_r(&r).unwrap();
            let eq_result = eq.evals().iter().to_vec();
            let iter_result = iter.to_vec();
            for (i, (a, b)) in eq_result.iter().zip(&iter_result).enumerate() {
                assert_eq!(a, b, "failed for {nv} at {i}");
            }
        }
    }

    #[test]
    fn eq_iter_fix_variables_test() {
        let rng = &mut test_rng();
        for nv in 9..20 {
            let r = (0..nv).map(|_| Fr::rand(rng)).collect::<Vec<_>>();
            let eq = MLE::eq_x_r(&r).unwrap();
            for fixed_nv in 0..nv {
                let fixed_vars = (0..fixed_nv).map(|_| Fr::rand(rng)).collect::<Vec<_>>();
                let fixed_eq = eq.fix_variables(&fixed_vars);
                let fixed_eq_evals = fixed_eq.evals().iter().to_vec();
                let iter = EqEvalIter::new_with_fixed_vars(r.clone(), fixed_vars);
                let fixed_eq_iter_evals = iter.to_vec();

                for (i, (a, b)) in fixed_eq_evals.iter().zip(&fixed_eq_iter_evals).enumerate() {
                    assert_eq!(a, b, "failed for {nv} at {i}");
                }
            }
        }
    }
}
