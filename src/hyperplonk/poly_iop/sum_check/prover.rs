// Copyright (c) 2023 Espresso Systems (espressosys.com)
// This file is part of the HyperPlonk library.

// You should have received a copy of the MIT License
// along with the HyperPlonk library. If not, see <https://mit-license.org/>.

//! Prover subroutines for a SumCheck protocol.

use super::SumCheckProver;
use crate::hyperplonk::arithmetic::virtual_polynomial::VirtualPolynomial;
use crate::read_write::DenseMLPolyStream;
use crate::{
    hyperplonk::poly_iop::{
        errors::PolyIOPErrors,
        structs::{IOPProverMessage, IOPProverState},
    },
    read_write::ReadWriteStream,
};
use ark_ff::{batch_inversion, PrimeField};
// use ark_poly::DenseMultilinearExtension;
use ark_std::{cfg_into_iter, end_timer, start_timer, vec::Vec};
use rayon::prelude::{IntoParallelIterator, IntoParallelRefIterator};
use std::io::Seek;
use std::sync::Arc;

#[cfg(feature = "parallel")]
use rayon::iter::{IntoParallelRefMutIterator, ParallelIterator};

impl<F: PrimeField> SumCheckProver<F> for IOPProverState<F> {
    type VirtualPolynomial = VirtualPolynomial<F>;
    type ProverMessage = IOPProverMessage<F>;

    /// Initialize the prover state to argue for the sum of the input polynomial
    /// over {0,1}^`num_vars`.
    fn prover_init(polynomial: &Self::VirtualPolynomial) -> Result<Self, PolyIOPErrors> {
        let start = start_timer!(|| "sum check prover init");
        if polynomial.aux_info.num_variables == 0 {
            return Err(PolyIOPErrors::InvalidParameters(
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
    ) -> Result<Self::ProverMessage, PolyIOPErrors> {
        // let start =
        //     start_timer!(|| format!("sum check prove {}-th round and update state",
        // self.round));

        if self.round >= self.poly.aux_info.num_variables {
            return Err(PolyIOPErrors::InvalidProver(
                "Prover is not active".to_string(),
            ));
        }

        // let fix_argument = start_timer!(|| "fix argument");

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
        // let mut flattened_ml_extensions: Vec<&DenseMLPolyStream<F>> = self
        //     .poly
        //     .flattened_ml_extensions
        //     .par_iter()
        //     .map(|x| x.as_ref().clone())
        //     .collect();

        if let Some(chal) = challenge {
            // println!("ROUND CHALLENGE: {:?}", chal);
            // challenge is None for the first round
            if self.round == 0 {
                return Err(PolyIOPErrors::InvalidProver(
                    "first round should be prover first.".to_string(),
                ));
            }
            self.challenges.push(*chal);

            let r = self.challenges[self.round - 1];
            println!("prover challenge: {}", r);
            #[cfg(feature = "parallel")]
            self.poly
                .flattened_ml_extensions
                .par_iter_mut()
                .for_each(|mle| {
                    let mut mle = mle.lock().expect("Failed to lock mutex");
                    dbg!(mle.read_pointer.stream_position().unwrap());
                    mle
                        .fix_variables(&[r])
                });
            #[cfg(not(feature = "parallel"))]
            self.poly
                .flattened_ml_extensions
                .iter_mut()
                .for_each(|mle| mle.fix_variables(&[r]));
        } else if self.round > 0 {
            return Err(PolyIOPErrors::InvalidProver(
                "verifier message is empty".to_string(),
            ));
        }
        // end_timer!(fix_argument);

        self.round += 1;

        let products_list = self.poly.products.clone();
        let mut products_sum = vec![F::zero(); self.poly.aux_info.max_degree + 1];

        // Step 2: generate sum for the partial evaluated polynomial:
        // f(r_1, ... r_m,, x_{m+1}... x_n)

        for (coefficient, products) in &products_list {
            let mut sum = vec![F::zero(); products.len() + 1];

            for b in 0..1 << (self.poly.aux_info.num_variables - self.round) {
                let mut buf = vec![(F::zero(), F::zero()); products.len()];

                // Updating buf
                for ((eval, step), f) in buf.iter_mut().zip(products.iter()) {
                    // let mut stream = self.poly.flattened_ml_extensions[*f];
                    // *eval = stream.read_next().unwrap();
                    // *step = stream.read_next().unwrap() - *eval;

                    *eval = self.poly.flattened_ml_extensions[*f]
                        .lock()
                        .expect("Failed to lock mutex")
                        .read_next()
                        .unwrap(); // aL
                    println!("eval: {}", eval);
                    *step = self.poly.flattened_ml_extensions[*f]
                        .lock()
                        .expect("Failed to lock mutex")
                        .read_next()
                        .unwrap()
                        - *eval; // aR - aL
                    println!("step: {}", step);
                }

                // Updating sum
                println!("buf length: {}", buf.len());
                println!("first eval: {}", buf[0].0);
                sum[0] += buf.iter().map(|(eval, _)| *eval).product::<F>();
                for acc in sum.iter_mut().skip(1) {
                    for (eval, step) in buf.iter_mut() {
                        *eval += *step; // aL; aR; 2aR - aL; 3aR - 2aL; ...
                    }
                    println!("subsequent eval: {}", buf[0].0);
                    *acc += buf.iter().map(|(eval, _)| *eval).product::<F>();
                }
            }

            // Multiplying sum by coefficient
            for s in &mut sum {
                *s *= *coefficient;
                println!(" sum: {}", s)
            }

            // Extrapolation
            let mut extrapolation = Vec::new();
            for i in 0..self.poly.aux_info.max_degree - products.len() {
                let (points, weights) = &self.extrapolation_aux[products.len() - 1];
                let at = F::from((products.len() + 1 + i) as u64);
                extrapolation.push(extrapolate(points, weights, &sum, &at));
            }

            // Updating products_sum
            for (products_sum, s) in products_sum
                .iter_mut()
                .zip(sum.iter().chain(extrapolation.iter()))
            {
                *products_sum += *s;
            }
        }

        // restart all streams
        self.poly.flattened_ml_extensions.iter_mut().for_each(|stream| {
            stream
                .lock()
                .expect("Failed to lock mutex")
                .read_restart();
        });

        // update prover's state to the partial evaluated polynomial
        // self.poly.flattened_ml_extensions = flattened_ml_extensions
        //     .par_iter()
        //     .map(|x| Arc::new(x.clone()))
        //     .collect();

        println!("prover message 0: {}", products_sum[0]);
        println!("prover message 1: {}", products_sum[1]);

        Ok(IOPProverMessage {
            evaluations: products_sum,
        })
    }
}

fn barycentric_weights<F: PrimeField>(points: &[F]) -> Vec<F> {
    let mut weights = points
        .iter()
        .enumerate()
        .map(|(j, point_j)| {
            points
                .iter()
                .enumerate()
                .filter_map(|(i, point_i)| (i != j).then(|| *point_j - point_i))
                .reduce(|acc, value| acc * value)
                .unwrap_or_else(F::one)
        })
        .collect::<Vec<_>>();
    batch_inversion(&mut weights);
    weights
}

fn extrapolate<F: PrimeField>(points: &[F], weights: &[F], evals: &[F], at: &F) -> F {
    let (coeffs, sum_inv) = {
        let mut coeffs = points.iter().map(|point| *at - point).collect::<Vec<_>>();
        batch_inversion(&mut coeffs);
        coeffs.iter_mut().zip(weights).for_each(|(coeff, weight)| {
            *coeff *= weight;
        });
        let sum_inv = coeffs.iter().sum::<F>().inverse().unwrap_or_default();
        (coeffs, sum_inv)
    };
    coeffs
        .iter()
        .zip(evals)
        .map(|(coeff, eval)| *coeff * eval)
        .sum::<F>()
        * sum_inv
}
