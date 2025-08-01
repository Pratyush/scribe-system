use std::{borrow::BorrowMut, collections::HashSet};

use super::SumCheckProver;
use crate::piop::{
    errors::PIOPError,
    structs::{IOPProverMessage, IOPProverState},
};
use ark_ff::{PrimeField, batch_inversion};
use ark_std::{end_timer, start_timer, vec::Vec};
use itertools::Itertools;
use mle::virtual_polynomial::VirtualPolynomial;
use rayon::prelude::*;
use scribe_streams::{iterator::BatchedIterator, serialize::RawPrimeField};

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
        let degrees = polynomial
            .products
            .iter()
            .map(|(_, products)| products.len())
            .collect::<HashSet<_>>();
        let max_degree = polynomial.aux_info.max_degree;
        let extrapolation_aux = (1..max_degree)
            .into_par_iter()
            .map(|degree| match degrees.contains(&degree) {
                true => {
                    let points = (0..1 + degree as u64).map(F::from).collect::<Vec<_>>();
                    let weights = barycentric_weights(&points);
                    // Compute lagrange coefficients for extrapolation.
                    let points = (0..(max_degree - degree))
                        .into_par_iter()
                        .map(|j| {
                            let at = F::from((degree + 1 + j) as u64);
                            let mut v = points.par_iter().map(|p| at - *p).collect::<Vec<_>>();
                            batch_inversion(&mut v);
                            let inv = v
                                .par_iter_mut()
                                .zip(&weights)
                                .map(|(a, b)| {
                                    *a *= *b;
                                    *a
                                })
                                .sum::<F>()
                                .inverse()
                                .unwrap();
                            (v, inv)
                        })
                        .collect();
                    Some(points)
                },
                false => None,
            })
            .collect::<Vec<_>>();
        Ok(Self {
            challenges: Vec::with_capacity(polynomial.aux_info.num_variables),
            round: 0,
            poly: polynomial.clone(),
            extrapolation_aux,
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
                    .for_each(|m| *m = m.fix_variables(&[r]));
            } else {
                self.poly
                    .mles
                    .par_iter_mut()
                    .for_each(|m| m.fix_variables_in_place(&[r]));
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
        let mut iter_bufs = vec![vec![]; self.poly.mles.len()];
        let mut mle_iters = self
            .poly
            .mles
            .iter()
            .zip(&mut iter_bufs)
            .map(|(m, b)| m.evals_with_buf(b).array_chunks::<2>())
            .collect::<Vec<_>>();
        let mut buffers = vec![vec![]; self.poly.mles.len()];
        let mut running_sums = None;

        while next_mle_batch(&mut mle_iters, &mut buffers).is_some() {
            let sums = self
                .poly
                .products
                .par_iter()
                .map(|(coefficient, products)| {
                    let polys_in_product = products
                        .iter()
                        .map(|&i| buffers[i].par_iter().copied())
                        .collect();
                    let sums_of_evals_of_products =
                        compute_sums_of_evals_of_products(polys_in_product);
                    (coefficient, sums_of_evals_of_products, products.len())
                })
                .collect::<Vec<_>>();
            match running_sums.as_mut() {
                None => running_sums = Some(sums),
                Some(r) => r
                    .iter_mut()
                    .zip(sums)
                    .for_each(|((_, running, _), (_, cur, _))| {
                        running.iter_mut().zip(cur).for_each(|(a, v)| *a += v);
                    }),
            }
        }
        let sums = running_sums.expect("at least one batch should be processed");

        // Step 2: generate sum for the partial evaluated polynomial:
        // f(r_1, ... r_m,, x_{m+1}... x_n)

        let sums = sums
            .into_par_iter()
            .map(|(coefficient, mut sum, degree)| {
                sum.iter_mut().for_each(|sum| *sum *= *coefficient);
                // We already have evaluations at `product_size + 1` points, we need to
                // extrapolate to `max_degree + 1` points.
                // i.e. we need to extrapolate to `max_degree - product_size` points
                // at points `product_size + 1, product_size + 2, ..., max_degree`
                // using barycentric interpolation.
                let extrapolation = (0..self.poly.aux_info.max_degree - degree)
                    .into_par_iter()
                    .map(|i| {
                        let points = &self.extrapolation_aux[degree - 1].as_ref().unwrap();
                        let (points, inv) = &points[i];
                        extrapolate(points, *inv, &sum)
                    })
                    .collect::<Vec<_>>();
                sum.par_extend(extrapolation);
                sum
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

fn next_mle_batch<F: PrimeField, I: BatchedIterator<Item = [F; 2]> + Sync + Send>(
    mle_iters: &mut [I],
    buffers: &mut [Vec<[F; 2]>],
) -> Option<()>
where
    for<'a> I::Batch<'a>: rayon::iter::IndexedParallelIterator<Item = [F; 2]>,
{
    mle_iters
        .par_iter_mut()
        .zip(buffers)
        .map(|(iter, buf)| {
            buf.clear();
            if let Some(b) = iter.next_batch() {
                b.collect_into_vec(buf);
                Some(())
            } else {
                None
            }
        })
        .collect()
}
type T1<T> = (T,);
type T2<T> = (T, T);
type T3<T> = (T, T, T);
type T4<T> = (T, T, T, T);
type T5<T> = (T, T, T, T, T);
type T6<T> = (T, T, T, T, T, T);
type T7<T> = (T, T, T, T, T, T, T);
type T8<T> = (T, T, T, T, T, T, T, T);
type T9<T> = (T, T, T, T, T, T, T, T, T);
type T10<T> = (T, T, T, T, T, T, T, T, T, T);
type T11<T> = (T, T, T, T, T, T, T, T, T, T, T);
type T12<T> = (T, T, T, T, T, T, T, T, T, T, T, T);

fn compute_sums_of_evals_of_products<F: PrimeField>(
    mut polys_in_product: Vec<impl IndexedParallelIterator<Item = [F; 2]> + Send + Sync>,
) -> Vec<F> {
    let len = polys_in_product.len();
    match polys_in_product.len() {
        1 => {
            let x: T1<_> = polys_in_product.drain(..).collect_tuple().unwrap();
            summation_helper(x.into_par_iter().map(<[_; 1]>::from), len)
        },
        2 => {
            let x: T2<_> = polys_in_product.drain(..).collect_tuple().unwrap();
            summation_helper(x.into_par_iter().map(<[_; 2]>::from), len)
        },
        3 => {
            let x: T3<_> = polys_in_product.drain(..).collect_tuple().unwrap();
            summation_helper(x.into_par_iter().map(<[_; 3]>::from), len)
        },
        4 => {
            let x: T4<_> = polys_in_product.drain(..).collect_tuple().unwrap();
            summation_helper(x.into_par_iter().map(<[_; 4]>::from), len)
        },
        5 => {
            let x: T5<_> = polys_in_product.drain(..).collect_tuple().unwrap();
            summation_helper(x.into_par_iter().map(<[_; 5]>::from), len)
        },
        6 => {
            let x: T6<_> = polys_in_product.drain(..).collect_tuple().unwrap();
            summation_helper(x.into_par_iter().map(<[_; 6]>::from), len)
        },

        7 => {
            let x: T7<_> = polys_in_product.drain(..).collect_tuple().unwrap();
            summation_helper(x.into_par_iter().map(<[_; 7]>::from), len)
        },

        8 => {
            let x: T8<_> = polys_in_product.drain(..).collect_tuple().unwrap();
            summation_helper(x.into_par_iter().map(<[_; 8]>::from), len)
        },
        9 => {
            let x: T9<_> = polys_in_product.drain(..).collect_tuple().unwrap();
            summation_helper(x.into_par_iter().map(<[_; 9]>::from), len)
        },
        10 => {
            let x: T10<_> = polys_in_product.drain(..).collect_tuple().unwrap();
            summation_helper(x.into_par_iter().map(<[_; 10]>::from), len)
        },
        11 => {
            let x: T11<_> = polys_in_product.drain(..).collect_tuple().unwrap();
            summation_helper(x.into_par_iter().map(<[_; 11]>::from), len)
        },
        12 => {
            let x: T12<_> = polys_in_product.drain(..).collect_tuple().unwrap();
            summation_helper(x.into_par_iter().map(<[_; 12]>::from), len)
        },
        _ => unimplemented!("products with more than 12 polynomials are not supported yet"),
    }
}

fn summation_helper<F: PrimeField, T: BorrowMut<[[F; 2]]>>(
    zipped: impl IndexedParallelIterator<Item = T>,
    len: usize,
) -> Vec<F> {
    let zero_vec = || vec![F::zero(); len + 1];
    zipped
        .map(|mut products| {
            let mut evals_of_product = zero_vec();
            // each entry in products is the evaluation of the following affine polynomial
            // g(X) = \sum_b p(r, X, b),
            // at the pair of points (r, r + 1) in [0, 2^n].
            //
            // Since g(X) is affine, we can write it as g(X) = a * X + b.
            // Furthermore, we have that g(r + 1) - g(r) = a * (r + 1 - r) + b - b = a.
            let products = products.borrow_mut();
            // Now, products[i] = [g_i(r), a_i]
            evals_of_product[0] += products
                .iter_mut()
                .map(|[even, odd]| {
                    *odd -= *even;
                    *even
                })
                .product::<F>();

            // We are computing the evaluations of the product polynomial at the point `r`
            // This loop computes the rest of the evaluations at points r + 1, r + 2, ..., r + len
            // The idea is as follows: given the evaluation at r + j, we can compute the evaluation at r + (j + 1) as g_i(r + j + 1) = g_i(r + j) + a_i.
            // Inside the loop, we perform exactly this calculation; step denotes the `a` values.
            evals_of_product[1..].iter_mut().for_each(|eval| {
                *eval += products
                    .iter_mut()
                    .map(|[g_r_j, a]| {
                        let g_r_j_plus_1 = *g_r_j + a;
                        *g_r_j = g_r_j_plus_1;
                        *g_r_j
                    })
                    .product::<F>();
            });
            evals_of_product
        })
        .reduce(zero_vec, |mut sum, partial| {
            sum.iter_mut()
                .zip(partial)
                .for_each(|(sum, partial)| *sum += partial);
            sum
        })
}

fn barycentric_weights<F: PrimeField>(points: &[F]) -> Vec<F> {
    let mut weights = points
        .par_iter()
        .enumerate()
        .map(|(j, point_j)| {
            points
                .par_iter()
                .enumerate()
                .filter(|&(i, _)| i != j)
                .map(|(_, point_i)| *point_j - point_i)
                .reduce(|| F::one(), |acc, value| acc * value)
        })
        .collect::<Vec<_>>();
    batch_inversion(&mut weights);
    weights
}

fn extrapolate<F: PrimeField>(points: &[F], denom: F, evals: &[F]) -> F {
    let num = points
        .par_iter()
        .zip(evals)
        .map(|(coeff, e)| *coeff * e)
        .sum::<F>();
    num * denom
}
