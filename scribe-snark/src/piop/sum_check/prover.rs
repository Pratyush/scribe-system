use std::borrow::BorrowMut;

use super::SumCheckProver;
use crate::piop::{
    errors::PIOPError,
    structs::{IOPProverMessage, IOPProverState},
};
use ark_ff::{PrimeField, batch_inversion};
use ark_std::{end_timer, start_timer, vec::Vec};
use mle::virtual_polynomial::VirtualPolynomial;
use rayon::prelude::*;
use scribe_streams::{
    iterator::{BatchedIterator, zip_many},
    serialize::RawPrimeField,
};

impl<F: RawPrimeField> SumCheckProver<F> for IOPProverState<F> {
    type VirtualPolynomial = VirtualPolynomial<F>;
    type ProverMessage = IOPProverMessage<F>;

    /// Initialize the prover state to argue for the sum of the input polynomial
    /// over {0,1}^`num_vars`.
    fn prover_init(polynomial: &Self::VirtualPolynomial) -> Result<Self, PIOPError> {
        let start = start_timer!(|| "sum check prover init");
        if polynomial.aux_info.num_variables == 0 {
            return Err(PIOPError::InvalidParameters(
                "Attempt to prove a constant.".to_string(),
            ));
        }
        end_timer!(start);

        Ok(Self {
            challenges: Vec::with_capacity(polynomial.aux_info.num_variables),
            round: 0,
            poly: polynomial.clone(),
            extrapolation_aux: (1..polynomial.aux_info.max_degree)
                .map(|degree| {
                    let points = (0..1 + degree as u64).map(F::from).collect::<Vec<_>>();
                    let weights = barycentric_weights(&points);
                    (points, weights)
                })
                .collect(),
        })
    }

    /// Receive message from verifier, generate prover message, and proceed to
    /// next round.
    ///
    /// Main algorithm used is from section 3.2 of [XZZPS19](https://eprint.iacr.org/2019/317.pdf#subsection.3.2).
    fn prove_round_and_update_state(
        &mut self,
        challenge: &Option<F>,
    ) -> Result<Self::ProverMessage, PIOPError> {
        let start =
            start_timer!(|| format!("sum check prove {}-th round and update state", self.round));

        if self.round >= self.poly.aux_info.num_variables {
            return Err(PIOPError::InvalidProver("Prover is not active".to_string()));
        }

        // Step 1:
        // fix argument and evaluate f(x) over x_m = r; where r is the challenge
        // for the current round, and m is the round number, indexed from 1
        //
        // i.e.:
        // at round m <= n, for each mle g(x_1, ... x_n) within the flattened_mle
        // which has already been evaluated to
        //
        //    g(r_1, ..., r_{m-1}, x_m ... x_n)
        //
        // eval g over r_m, and mutate g to g(r_1, ... r_m,, x_{m+1}... x_n)

        if let Some(chal) = challenge {
            // challenge is None for the first round
            if self.round == 0 {
                return Err(PIOPError::InvalidProver(
                    "first round should be prover first.".to_string(),
                ));
            }
            self.challenges.push(*chal);

            let fix_argument = start_timer!(|| "fix argument");

            let r = self.challenges[self.round - 1];
            if self.round == 1 {
                // In the first round, make a deep copy of the original MLEs when fixing
                // the variables.
                // This ensures that the internal `Arc` is changed to point to a fresh file.
                self.poly
                    .mles
                    .par_iter_mut()
                    .for_each(|mle| *mle = mle.fix_variables(&[r]));
            } else {
                self.poly
                    .mles
                    .par_iter_mut()
                    .for_each(|mle| mle.fix_variables_in_place(&[r]));
            }
            end_timer!(fix_argument);
        } else if self.round > 0 {
            return Err(PIOPError::InvalidProver(
                "verifier message is empty".to_string(),
            ));
        }

        let generate_prover_message = start_timer!(|| "generate prover message");
        self.round += 1;

        let mut products_sum = vec![F::zero(); self.poly.aux_info.max_degree + 1];

        // Step 2: generate sum for the partial evaluated polynomial:
        // f(r_1, ... r_m,, x_{m+1}... x_n)
        let sums = self
            .poly
            .products
            .par_iter()
            .map(|(coefficient, products)| {
                let mut buffers: Vec<Vec<F>> = vec![vec![]; products.len()];
                let mut polys_in_product = products
                    .iter()
                    .zip(&mut buffers)
                    .map(|(&f, b)| self.poly.mles[f].evals_with_buf(b).array_chunks::<2>())
                    .collect::<Vec<_>>();
                let mut sum = match polys_in_product.len() {
                    1 => {
                        let a = polys_in_product.pop().unwrap();
                        summation_helper(a.map(|x| [x]), 1)
                    },
                    2 => {
                        let a = polys_in_product.pop().unwrap();
                        let b = polys_in_product.pop().unwrap();
                        summation_helper(a.zip(b).map(|(x, y)| [x, y]), 2)
                    },
                    3 => {
                        let a = polys_in_product.pop().unwrap();
                        let b = polys_in_product.pop().unwrap();
                        let c = polys_in_product.pop().unwrap();
                        summation_helper(a.zip(b).zip(c).map(|((x, y), z)| [x, y, z]), 3)
                    },
                    4 => {
                        let a = polys_in_product.pop().unwrap();
                        let b = polys_in_product.pop().unwrap();
                        let c = polys_in_product.pop().unwrap();
                        let d = polys_in_product.pop().unwrap();
                        summation_helper(
                            a.zip(b).zip(c).zip(d).map(|(((x, y), z), w)| [x, y, z, w]),
                            4,
                        )
                    },
                    5 => {
                        let a = polys_in_product.pop().unwrap();
                        let b = polys_in_product.pop().unwrap();
                        let c = polys_in_product.pop().unwrap();
                        let d = polys_in_product.pop().unwrap();
                        let e = polys_in_product.pop().unwrap();
                        summation_helper(
                            a.zip(b)
                                .zip(c)
                                .zip(d)
                                .zip(e)
                                .map(|((((x, y), z), w), v)| [x, y, z, w, v]),
                            5,
                        )
                    },
                    n => summation_helper(zip_many(polys_in_product), n),
                };

                sum.iter_mut().for_each(|sum| *sum *= *coefficient);
                let extrapolation = (0..self.poly.aux_info.max_degree - products.len())
                    .into_par_iter()
                    .map(|i| {
                        let (points, weights) = &self.extrapolation_aux[products.len() - 1];
                        let at = F::from((products.len() + 1 + i) as u64);
                        extrapolate(points, weights, &sum, &at)
                    })
                    .collect::<Vec<_>>();
                sum.into_iter().chain(extrapolation).collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        for sum in sums {
            products_sum
                .iter_mut()
                .zip(sum)
                .for_each(|(acc, value)| *acc += value);
        }

        end_timer!(generate_prover_message);
        end_timer!(start);

        Ok(IOPProverMessage {
            evaluations: products_sum,
        })
    }
}

fn summation_helper<F: PrimeField, T: BorrowMut<[[F; 2]]>>(
    zipped: impl BatchedIterator<Item = T>,
    len: usize,
) -> Vec<F> {
    zipped.fold(
        || vec![F::zero(); len + 1],
        |mut acc, mut products| {
            let products = products.borrow_mut();
            products.iter_mut().for_each(|[even, odd]| {
                *odd -= *even;
            });
            acc[0] += products.iter().map(|[e, _]| *e).product::<F>();
            acc[1..].iter_mut().for_each(|acc| {
                products.iter_mut().for_each(|[eval, step]| *eval += step);
                *acc += products.iter().map(|[e, _]| e).product::<F>();
            });
            acc // by the bit
        },
        |mut sum, partial| {
            sum.iter_mut()
                .zip(partial)
                .for_each(|(sum, partial)| *sum += partial);
            sum // sum for half of the bits
        },
    )
}

fn barycentric_weights<F: PrimeField>(points: &[F]) -> Vec<F> {
    let mut weights = points
        .iter()
        .enumerate()
        .map(|(j, point_j)| {
            points
                .iter()
                .enumerate()
                .filter(|&(i, _)| i != j)
                .map(|(_, point_i)| *point_j - point_i)
                .reduce(|acc, value| acc * value)
                .unwrap_or_else(F::one)
        })
        .collect::<Vec<_>>();
    batch_inversion(&mut weights);
    weights
}

fn extrapolate<F: PrimeField>(points: &[F], weights: &[F], evals: &[F], at: &F) -> F {
    let (coeffs, sum_inv) = {
        let mut coeffs = points
            .par_iter()
            .map(|point| *at - point)
            .collect::<Vec<_>>();
        batch_inversion(&mut coeffs);
        coeffs
            .par_iter_mut()
            .zip(weights)
            .for_each(|(coeff, weight)| *coeff *= weight);
        let sum_inv = coeffs.par_iter().sum::<F>().inverse().unwrap_or_default();
        (coeffs, sum_inv)
    };
    coeffs
        .par_iter()
        .zip(evals)
        .map(|(coeff, eval)| *coeff * eval)
        .sum::<F>()
        * sum_inv
}
