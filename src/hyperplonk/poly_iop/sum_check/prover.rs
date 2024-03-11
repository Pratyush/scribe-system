use super::SumCheckProver;
use crate::hyperplonk::arithmetic::virtual_polynomial::VirtualPolynomial;
use crate::read_write::{batch_inversion_from_to, prod_multi_from_to, DenseMLPolyStream};
use crate::{
    hyperplonk::poly_iop::{
        errors::PolyIOPErrors,
        structs::{IOPProverMessage, IOPProverState},
    },
    read_write::ReadWriteStream,
};
use ark_ff::{batch_inversion, PrimeField};
use ark_std::{end_timer, start_timer, vec::Vec};
use std::collections::HashSet;
use std::io::Seek;
use std::sync::{Arc, Mutex};

#[cfg(feature = "parallel")]
use rayon::iter::{IndexedParallelIterator, IntoParallelRefMutIterator, ParallelIterator};

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
        let start =
            start_timer!(|| format!("sum check prove {}-th round and update state", self.round));

        if self.round >= self.poly.aux_info.num_variables {
            return Err(PolyIOPErrors::InvalidProver(
                "Prover is not active".to_string(),
            ));
        }

        let fix_argument = start_timer!(|| "fix argument");

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
            #[cfg(debug_assertions)]
            println!("sum check ROUND CHALLENGE: {}", chal);
            // challenge is None for the first round
            if self.round == 0 {
                return Err(PolyIOPErrors::InvalidProver(
                    "first round should be prover first.".to_string(),
                ));
            }
            self.challenges.push(*chal);

            let r = self.challenges[self.round - 1];
            #[cfg(debug_assertions)]
            println!("sum check prover challenge: {}", r);

            // get stream indices that are not perm_inv_streams or perm_prod_streams for folding
            let mut do_not_fold_streams: Vec<usize> = self.poly.perm_inv_streams.0.clone();
            do_not_fold_streams.extend(self.poly.perm_inv_streams.1.clone());
            if let (Some(prod_0), Some(prod_1)) = (self.poly.perm_prod_streams.0, self.poly.perm_prod_streams.1) {
                do_not_fold_streams.push(prod_0);
                do_not_fold_streams.push(prod_1);
            }

            #[cfg(feature = "parallel")]
            self.poly
                .flattened_ml_extensions
                .par_iter_mut()
                .enumerate()
                .for_each(|(idx, mle)| {
                    if !do_not_fold_streams.contains(&idx) {
                        let mut mle = mle.lock().expect("Failed to lock mutex");
                        dbg!(mle.read_pointer.stream_position().unwrap());
                        mle.fix_variables(&[r]);
                    }
                });
            #[cfg(not(feature = "parallel"))]
            self.poly
                .flattened_ml_extensions
                .iter_mut()
                .enumerate()
                .for_each(|(idx, mle)| {
                    if !do_not_fold_streams.contains(&idx) {
                        let mut mle = mle.lock().expect("Failed to lock mutex");
                        dbg!(mle.read_pointer.stream_position().unwrap());
                        mle.fix_variables(&[r]);
                    }
                });
        } else if self.round > 0 {
            return Err(PolyIOPErrors::InvalidProver(
                "verifier message is empty".to_string(),
            ));
        }

        // create perm_inv_streams from perm_streams
        if !self.poly.perm_streams.0.is_empty() && !self.poly.perm_inv_streams.0.is_empty() {
            self.poly
                .perm_streams
                .0
                .iter()
                .chain(self.poly.perm_streams.1.iter())
                .zip(
                    self.poly
                        .perm_inv_streams
                        .0
                        .iter()
                        .chain(self.poly.perm_inv_streams.1.iter()),
                )
                .for_each(|(perm_idx, perm_inv_idx)| {
                    let mut stream = self.poly.flattened_ml_extensions[*perm_idx].clone();
                    let mut inv_stream = self.poly.flattened_ml_extensions[*perm_inv_idx].clone();
                    batch_inversion_from_to(&mut inv_stream, &mut stream, 1 << 20);
                });
        }

        // create perm_prod_streams from perm_streams
        if !self.poly.perm_streams.0.is_empty() && self.poly.perm_prod_streams.0.is_some() {
            let from = self
                .poly
                .perm_streams
                .0
                .iter()
                .map(|perm_idx| self.poly.flattened_ml_extensions[*perm_idx].clone())
                .collect::<Vec<Arc<Mutex<DenseMLPolyStream<F>>>>>();
            prod_multi_from_to(
                &from,
                &self.poly.flattened_ml_extensions[self.poly.perm_prod_streams.0.unwrap()],
            );

            let from = self
                .poly
                .perm_streams
                .1
                .iter()
                .map(|perm_idx| self.poly.flattened_ml_extensions[*perm_idx].clone())
                .collect::<Vec<Arc<Mutex<DenseMLPolyStream<F>>>>>();
            prod_multi_from_to(
                &from,
                &self.poly.flattened_ml_extensions[self.poly.perm_prod_streams.1.unwrap()],
            );
        }

        end_timer!(fix_argument);

        let generate_prover_message = start_timer!(|| "generate prover message");
        self.round += 1;

        #[cfg(debug_assertions)]
        println!("sum check products_list: {:?}", self.poly.products);

        let products_list = self.poly.products.clone();
        let mut products_sum = vec![F::zero(); self.poly.aux_info.max_degree + 1];

        // Step 2: generate sum for the partial evaluated polynomial:
        // f(r_1, ... r_m,, x_{m+1}... x_n)

        // let mut total_read_time = std::time::Duration::new(0, 0);

        let mut polynomials = self
            .poly
            .flattened_ml_extensions
            .iter()
            .map(|x| x.lock().unwrap())
            .collect::<Vec<_>>();

        let mut stream_values: std::collections::HashMap<usize, (F, F)> =
            std::collections::HashMap::new();

        for (coefficient, products) in &products_list {
            #[cfg(debug_assertions)]
            {
                println!("sum check product coefficient: {}", coefficient);
                println!("sum check product products: {:?}", products);
                println!("sum check product round: {}", self.round);
            }

            let mut sum = vec![F::zero(); products.len() + 1];

            let unique_products: HashSet<usize> = products.iter().cloned().collect();

            for b in 0..1 << (self.poly.aux_info.num_variables - self.round) {
                #[cfg(debug_assertions)]
                {
                    println!("sum check product b: {}", b);
                    println!("sum check product round: {}", self.round);
                    println!(
                        "sum check product num_variables: {}",
                        self.poly.aux_info.num_variables
                    );
                }

                stream_values.clear();

                // Read and store values only for unique streams
                for &f in unique_products.iter() {
                    #[cfg(debug_assertions)]
                    println!("sum check product: {}", f);

                    let stream = &mut polynomials[f];

                    let eval = stream.read_next().unwrap(); // Read once for eval
                    let step = stream.read_next().unwrap() - eval; // Read once for step

                    stream_values.insert(f, (eval, step));
                }

                let mut buf = vec![(F::zero(), F::zero()); products.len()];

                for (buf_item, &f) in buf.iter_mut().zip(products.iter()) {
                    if let Some(&(eval, step)) = stream_values.get(&f) {
                        *buf_item = (eval, step);
                    }
                }

                // Updating sum
                #[cfg(debug_assertions)]
                {
                    println!("sum check product buf length: {}", buf.len());
                    println!("sum check product first eval: {}", buf[0].0);
                }
                sum[0] += buf.iter().map(|(eval, _)| *eval).product::<F>();
                for acc in sum.iter_mut().skip(1) {
                    for (eval, step) in buf.iter_mut() {
                        *eval += *step; // aL; aR; 2aR - aL; 3aR - 2aL; ...
                    }
                    #[cfg(debug_assertions)]
                    println!("subsequent eval: {}", buf[0].0);
                    *acc += buf.iter().map(|(eval, _)| *eval).product::<F>();
                }
            }

            // restart all streams
            polynomials
                .iter_mut()
                .for_each(|stream| stream.read_restart());

            // Multiplying sum by coefficient
            for s in &mut sum {
                *s *= *coefficient;

                #[cfg(debug_assertions)]
                {
                    println!("sum chesck product sum: {}", s)
                }
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

        end_timer!(generate_prover_message);

        #[cfg(debug_assertions)]
        {
            println!("sum check prover message 0: {}", products_sum[0]);
            println!("sum check prover message 1: {}", products_sum[1]);
        }

        end_timer!(start);

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
