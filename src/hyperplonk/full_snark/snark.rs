// use crate::hyperplonk::arithmetic::virtual_polynomial::{eq_eval, VPAuxInfo};
// use crate::hyperplonk::full_snark::utils::PcsAccumulator;
// use crate::hyperplonk::pcs::multilinear_kzg::batching::{BatchProofSinglePoint, BatchProofSinglePointAggr};
// use crate::hyperplonk::pcs::prelude::Commitment;
// use crate::hyperplonk::pcs::PolynomialCommitmentScheme;
// use crate::hyperplonk::poly_iop::perm_check::util::compute_frac_poly_plonk;
// use crate::hyperplonk::poly_iop::perm_check_original::PermutationCheck;
// use crate::hyperplonk::poly_iop::prelude::{SumCheck, ZeroCheck};
// use crate::hyperplonk::poly_iop::PolyIOP;
// use crate::hyperplonk::transcript::IOPTranscript;
// use crate::read_write::copy_mle;
// use crate::{
//     hyperplonk::full_snark::{
//         errors::HyperPlonkErrors,
//         structs::{HyperPlonkIndex, HyperPlonkProof, HyperPlonkProvingKey, HyperPlonkVerifyingKey},
//         utils::{build_f, eval_f, prover_sanity_check},
//         HyperPlonkSNARK,
//     },
//     read_write::DenseMLPolyStream,
// };
// use ark_ec::pairing::Pairing;
// use ark_ec::CurveGroup;
// use ark_ff::Field;
// use ark_std::{end_timer, log2, start_timer, Zero, One};
// use rayon::iter::IntoParallelRefIterator;
// #[cfg(feature = "parallel")]
// use rayon::iter::ParallelIterator;
// use std::cmp::max;
// use std::{
//     marker::PhantomData,
//     sync::{Arc, Mutex},
// };

// impl<E, PCS> HyperPlonkSNARK<E, PCS> for PolyIOP<E::ScalarField>
// where
//     E: Pairing,
//     PCS: PolynomialCommitmentScheme<
//         E,
//         Polynomial = Arc<Mutex<DenseMLPolyStream<E::ScalarField>>>,
//         Point = Vec<E::ScalarField>,
//         Evaluation = E::ScalarField,
//         Commitment = Commitment<E>,
//     >,
// {
//     type Index = HyperPlonkIndex<E::ScalarField>;
//     type ProvingKey = HyperPlonkProvingKey<E, PCS>;
//     type VerifyingKey = HyperPlonkVerifyingKey<E, PCS>;
//     type Proof = HyperPlonkProof<E, Self, PCS>;

//     fn preprocess(
//         index: &Self::Index,
//         pcs_srs: &PCS::SRS,
//     ) -> Result<(Self::ProvingKey, Self::VerifyingKey), HyperPlonkErrors> {
//         let num_vars = index.num_variables();
//         let supported_ml_degree = num_vars;

//         let start = start_timer!(|| format!("hyperplonk preprocessing nv = {}", num_vars));

//         // extract PCS prover and verifier keys from SRS
//         let (pcs_prover_param, pcs_verifier_param) =
//             PCS::trim(pcs_srs, None, Some(supported_ml_degree))?;

//         // build permutation oracles
//         let mut permutation_oracles = index.permutation.clone();
//         let mut permutation_commitments = permutation_oracles.iter().map(|perm_oracle| {
//             PCS::commit(&pcs_prover_param, perm_oracle)
//         }).collect::<Result<Vec<_>, _>>()?;

//         // commit selector oracles
//         let selector_oracles = index.selectors.clone();

//         let selector_commitments = selector_oracles
//             .par_iter()
//             .map(|poly| PCS::commit(&pcs_prover_param, poly))
//             .collect::<Result<Vec<_>, _>>()?;

//         end_timer!(start);

//         Ok((
//             Self::ProvingKey {
//                 params: index.params.clone(),
//                 permutation_oracles,
//                 selector_oracles,
//                 selector_commitments: selector_commitments.clone(),
//                 permutation_commitments: permutation_commitments.clone(),
//                 pcs_param: pcs_prover_param,
//             },
//             Self::VerifyingKey {
//                 params: index.params.clone(),
//                 pcs_param: pcs_verifier_param,
//                 selector_commitments,
//                 perm_commitments: permutation_commitments,
//             },
//         ))
//     }

//     /// Generate HyperPlonk SNARK proof.
//     ///
//     /// Inputs:
//     /// - `pk`: circuit proving key
//     /// - `pub_input`: online public input of length 2^\ell
//     /// - `witness`: witness assignment of length 2^n
//     /// Outputs:
//     /// - The HyperPlonk SNARK proof.
//     ///
//     /// Steps:
//     ///
//     /// 1. Commit Witness polynomials `w_i(x)` and append commitment to
//     /// transcript
//     ///
//     /// 2. Run ZeroCheck on
//     ///
//     ///     `f(q_0(x),...q_l(x), w_0(x),...w_d(x))`  
//     ///
//     /// where `f` is the constraint polynomial i.e.,
//     /// ```ignore
//     ///     f(q_l, q_r, q_m, q_o, w_a, w_b, w_c)
//     ///     = q_l w_a(x) + q_r w_b(x) + q_m w_a(x)w_b(x) - q_o w_c(x)
//     /// ```
//     /// in vanilla plonk, and obtain a ZeroCheckSubClaim
//     ///
//     /// 3. Run permutation check on `\{w_i(x)\}` and `permutation_oracle`, and
//     /// obtain a PermCheckSubClaim.
//     ///
//     /// 4. Generate evaluations and corresponding proofs
//     /// - 4.1. (deferred) batch opening prod(x) at
//     ///   - [0, perm_check_point]
//     ///   - [1, perm_check_point]
//     ///   - [perm_check_point, 0]
//     ///   - [perm_check_point, 1]
//     ///   - [1,...1, 0]
//     ///
//     /// - 4.2. permutation check evaluations and proofs
//     ///   - 4.2.1. (deferred) wi_poly(perm_check_point)
//     ///
//     /// - 4.3. zero check evaluations and proofs
//     ///   - 4.3.1. (deferred) wi_poly(zero_check_point)
//     ///   - 4.3.2. (deferred) selector_poly(zero_check_point)
//     ///
//     /// - 4.4. public input consistency checks
//     ///   - pi_poly(r_pi) where r_pi is sampled from transcript
//     ///
//     /// - 5. deferred batch opening
//     fn prove(
//         pk: &Self::ProvingKey,
//         pub_input: &[E::ScalarField],
//         witnesses: Vec<Arc<Mutex<DenseMLPolyStream<E::ScalarField>>>>,
//     ) -> Result<Self::Proof, HyperPlonkErrors> {
//         // copy inputs for opening, should not be a part of proving time (i put it here as i don't want to change the ProvingKey to store the copies as well)
//         let witnesses_copy = witnesses
//             .iter()
//             .map(|x| copy_mle(x, None, None))
//             .collect::<Vec<Arc<Mutex<DenseMLPolyStream<E::ScalarField>>>>>();
//         let selector_oracles_copy = pk
//             .selector_oracles
//             .iter()
//             .map(|x| copy_mle(x, None, None))
//             .collect::<Vec<Arc<Mutex<DenseMLPolyStream<E::ScalarField>>>>>();
//         let perm_oracles_copy = pk
//             .permutation_oracles
//             .iter()
//             .map(|x| copy_mle(x, None, None))
//             .collect::<Vec<Arc<Mutex<DenseMLPolyStream<E::ScalarField>>>>>();

//         // copy witnesses again for permutation check
//         // TODO: update permutation check helper function so that no duplicate copy is needed
//         let witnesses_fx_copy = witnesses
//             .iter()
//             .map(|x| copy_mle(x, None, None))
//             .collect::<Vec<Arc<Mutex<DenseMLPolyStream<E::ScalarField>>>>>();
//         let witnesses_gx_copy = witnesses
//             .iter()
//             .map(|x| copy_mle(x, None, None))
//             .collect::<Vec<Arc<Mutex<DenseMLPolyStream<E::ScalarField>>>>>();
        
//         let start =
//             start_timer!(|| format!("hyperplonk proving nv = {}", pk.params.num_variables()));
//         let mut transcript = IOPTranscript::<E::ScalarField>::new(b"hyperplonk");

//         prover_sanity_check(&pk.params, pub_input, witnesses.clone())?;

//         // witness assignment of length 2^n
//         let num_vars = pk.params.num_variables();

//         // online public input of length 2^\ell
//         let ell = log2(pk.params.num_pub_input) as usize;

//         // We use accumulators to store the polynomials and their eval points.
//         // They are batch opened at a later stage.
//         let mut pcs_acc_perm = PcsAccumulator::<E, PCS>::new(num_vars);
//         let mut pcs_acc_perm_0 = PcsAccumulator::<E, PCS>::new(num_vars);
//         let mut pcs_acc_perm_1 = PcsAccumulator::<E, PCS>::new(num_vars);
//         let mut pcs_acc_zero = PcsAccumulator::<E, PCS>::new(num_vars);
//         let mut pcs_acc_prod = PcsAccumulator::<E, PCS>::new(num_vars);

//         // =======================================================================
//         // 1. Commit Witness polynomials `w_i(x)` and append commitment to
//         // transcript
//         // =======================================================================
//         let step = start_timer!(|| "commit witnesses");

//         let witness_commits = witnesses
//             .par_iter()
//             .map(|x| PCS::commit(&pk.pcs_param, x).unwrap())
//             .collect::<Vec<_>>();
//         for w_com in witness_commits.iter() {
//             transcript.append_serializable_element(b"w", w_com)?;
//         }

//         end_timer!(step);

//         // =======================================================================
//         // 2 Run ZeroCheck on
//         //
//         //     `f(q_0(x),...q_l(x), w_0(x),...w_d(x))`
//         //
//         // where `f` is the constraint polynomial i.e.,
//         //
//         //     f(q_l, q_r, q_m, q_o, w_a, w_b, w_c)
//         //     = q_l w_a(x) + q_r w_b(x) + q_m w_a(x)w_b(x) - q_o w_c(x)
//         //
//         // in vanilla plonk, and obtain a ZeroCheckSubClaim
//         // =======================================================================
//         let step = start_timer!(|| "ZeroCheck on f");

//         let fx = build_f(
//             &pk.params.gate_func,
//             pk.params.num_variables(),
//             &pk.selector_oracles,
//             &witnesses,
//         )?;

//         let zero_check_proof = <Self as ZeroCheck<E::ScalarField>>::prove(&fx, &mut transcript)?;
//         end_timer!(step);
        
//         // =======================================================================
//         // 3. Run permutation check on `\{w_i(x)\}` and `permutation_oracle`, and
//         // obtain a PermCheckSubClaim.
//         // =======================================================================
//         let step = start_timer!(|| "Permutation check on w_i(x)");

//         let (perm_check_proof, prod_x_copy, frac_poly_copy) = <Self as PermutationCheck<E, PCS>>::prove(
//             &pk.pcs_param,
//             witnesses_fx_copy,
//             witnesses_gx_copy,
//             pk.permutation_oracles,
//             &mut transcript,
//         )?;
//         let perm_check_point = &perm_check_proof.zero_check_proof.point;

//         end_timer!(step);

//         // =======================================================================
//         // 4. Generate evaluations and corresponding proofs
//         // - permcheck
//         //  1. (deferred) batch opening prod(x) at
//         //   - [perm_check_point]
//         //   - [perm_check_point[2..n], 0]
//         //   - [perm_check_point[2..n], 1]
//         //   - [1,...1, 0]
//         //  2. (deferred) batch opening frac(x) at
//         //   - [perm_check_point]
//         //   - [perm_check_point[2..n], 0]
//         //   - [perm_check_point[2..n], 1]
//         //  3. (deferred) batch opening s_id(x) at
//         //   - [perm_check_point]
//         //  4. (deferred) batch opening perms(x) at
//         //   - [perm_check_point]
//         //  5. (deferred) batch opening witness_i(x) at
//         //   - [perm_check_point]
//         //
//         // - zero check evaluations and proofs
//         //   - 4.3.1. (deferred) wi_poly(zero_check_point)
//         //   - 4.3.2. (deferred) selector_poly(zero_check_point)
//         //
//         // - 4.4. (deferred) public input consistency checks
//         //   - pi_poly(r_pi) where r_pi is sampled from transcript
//         // =======================================================================

//         let step = start_timer!(|| "opening and evaluations");

//         // (perm_check_point[2..n], 0)
//         let perm_check_point_0 = [
//             &[E::ScalarField::zero()],
//             &perm_check_point[0..num_vars - 1],
//         ]
//         .concat();
//         // (perm_check_point[2..n], 1)
//         let perm_check_point_1 =
//             [&[E::ScalarField::one()], &perm_check_point[0..num_vars - 1]].concat();
//         // (1, ..., 1, 0)
//         let prod_final_query_point = [
//             vec![E::ScalarField::zero()],
//             vec![E::ScalarField::one(); num_vars - 1],
//         ]
//         .concat();

//         // prod(x)'s points
//         pcs_acc_perm.insert_poly_and_points(&prod_x_copy, &perm_check_proof.prod_x_comm, perm_check_point);
//         pcs_acc_perm_0.insert_poly_and_points(&prod_x_copy, &perm_check_proof.prod_x_comm, &perm_check_point_0);
//         pcs_acc_perm_1.insert_poly_and_points(&prod_x_copy, &perm_check_proof.prod_x_comm, &perm_check_point_1);
//         pcs_acc_prod.insert_poly_and_points(
//             &prod_x_copy,
//             &perm_check_proof.prod_x_comm,
//             &prod_final_query_point,
//         );

//         // frac(x)'s points
//         pcs_acc_perm.insert_poly_and_points(&frac_poly_copy, &perm_check_proof.frac_comm, perm_check_point);
//         pcs_acc_perm_0.insert_poly_and_points(
//             &frac_poly_copy,
//             &perm_check_proof.frac_comm,
//             &perm_check_point_0,
//         );
//         pcs_acc_perm_1.insert_poly_and_points(
//             &frac_poly_copy,
//             &perm_check_proof.frac_comm,
//             &perm_check_point_1,
//         );

//         // perms(x)'s points
//         for (perm, pcom) in perm_oracles_copy
//             .iter()
//             .zip(pk.permutation_commitments.iter())
//         {
//             pcs_acc_perm.insert_poly_and_points(perm, pcom, perm_check_point);
//         }

//         // witnesses' points
//         // TODO: refactor so it remains correct even if the order changed
//         for (wpoly, wcom) in witnesses_copy.iter().zip(witness_commits.iter()) {
//             pcs_acc_perm.insert_poly_and_points(wpoly, wcom, perm_check_point);
//         }
//         for (wpoly, wcom) in witnesses_copy.iter().zip(witness_commits.iter()) {
//             pcs_acc_zero.insert_poly_and_points(wpoly, wcom, &zero_check_proof.point);
//         }

//         //   - 4.3.2. (deferred) selector_poly(zero_check_point)
//         selector_oracles_copy
//             .iter()
//             .zip(pk.selector_commitments.iter())
//             .for_each(|(poly, com)| {
//                 pcs_acc_zero.insert_poly_and_points(poly, com, &zero_check_proof.point)
//             });

//         // // - 4.4. public input consistency checks
//         // //   - pi_poly(r_pi) where r_pi is sampled from transcript
//         // let r_pi = transcript.get_and_append_challenge_vectors(b"r_pi", ell)?;
//         // // padded with zeros
//         // let r_pi_padded = [r_pi, vec![E::ScalarField::zero(); num_vars - ell]].concat();
//         // // Evaluate witness_poly[0] at r_pi||0s which is equal to public_input evaluated
//         // // at r_pi. Assumes that public_input is a power of 2
//         // pcs_acc.insert_poly_and_points(&witness_polys[0], &witness_commits[0], &r_pi_padded);
//         end_timer!(step);

//         let step = start_timer!(|| "deferred batch openings");

//         // note that these opening create a rlc of the polynomials in the accumulator
//         // so the original polynomials (copies) aren't folded
//         // that's why we use for example witnesses rather than witnesses_copy for calculating evaluations
//         let (proof_perm, rlc_eval_perm) =
//             pcs_acc_perm.multi_open_single_point(&pk.pcs_param, &mut transcript)?;
//         let (proof_perm_0, rlc_eval_perm_0) =
//             pcs_acc_perm_0.multi_open_single_point(&pk.pcs_param, &mut transcript)?;
//         let (proof_perm_1, rlc_eval_perm_1) =
//             pcs_acc_perm_1.multi_open_single_point(&pk.pcs_param, &mut transcript)?;
//         let (proof_prod, rlc_eval_prod) =
//             pcs_acc_prod.multi_open_single_point(&pk.pcs_param, &mut transcript)?;
//         let (proof_zero, rlc_eval_zero) =
//             pcs_acc_zero.multi_open_single_point(&pk.pcs_param, &mut transcript)?;

//         // get evaluation of all relevant polynomials
//         let perm_evals = pk
//             .permutation_oracles
//             .iter()
//             .map(|poly| {
//                 poly.lock()
//                     .unwrap()
//                     .evaluate(std::slice::from_ref(&sum_check_proof.point[num_vars - 1]))
//                     .unwrap()
//             })
//             .collect::<Vec<E::ScalarField>>();
//         let perm_index_evals = pk
//             .permutation_oracles
//             .1
//             .iter()
//             .map(|poly| {
//                 poly.lock()
//                     .unwrap()
//                     .evaluate(std::slice::from_ref(&sum_check_proof.point[num_vars - 1]))
//                     .unwrap()
//             })
//             .collect::<Vec<E::ScalarField>>();
//         let selector_evals = pk
//             .selector_oracles
//             .iter()
//             .map(|poly| {
//                 poly.lock()
//                     .unwrap()
//                     .evaluate(std::slice::from_ref(&sum_check_proof.point[num_vars - 1]))
//                     .unwrap()
//             })
//             .collect::<Vec<E::ScalarField>>();
//         let witness_evals = witnesses
//             .iter()
//             .map(|poly| {
//                 poly.lock()
//                     .unwrap()
//                     .evaluate(std::slice::from_ref(&sum_check_proof.point[num_vars - 1]))
//                     .unwrap()
//             })
//             .collect::<Vec<E::ScalarField>>();

//         #[cfg(debug_assertions)]
//         {
//             // print all evaluations
//             perm_evals
//                 .iter()
//                 .for_each(|eval| println!("perm eval: {}", eval));
//             perm_index_evals
//                 .iter()
//                 .for_each(|eval| println!("perm index eval: {}", eval));
//             selector_evals
//                 .iter()
//                 .for_each(|eval| println!("selector eval: {}", eval));
//             witness_evals
//                 .iter()
//                 .for_each(|eval| println!("witness eval: {}", eval));
//         }

//         let opening = BatchProofSinglePointAggr {
//             rlc_eval_prod,
//             proof_prod,
//             rlc_eval_perm,
//             proof_perm,
//             rlc_eval_perm_0,
//             proof_perm_0,
//             rlc_eval_perm_1,
//             proof_perm_1,
//             rlc_eval_zero,
//             proof_zero,

//             perm_evals,
//             perm_index_evals,
//             selector_evals,
//             witness_evals,
//             hp_evals,
//             hq_evals,
//         };

//         end_timer!(step);

//         end_timer!(start);

//         Ok(HyperPlonkProof {
//             witness_commits,
//             opening, // opening and evaluations
//             sum_check_proof,
//             h_comm: h_p_comm,
//             h_prime_comm: h_q_comm,
//         })
//     }

//     fn verify(
//         vk: &Self::VerifyingKey,
//         pub_input: &[E::ScalarField],
//         proof: &Self::Proof,
//     ) -> Result<bool, HyperPlonkErrors> {
//         let start =
//             start_timer!(|| format!("hyperplonk verification nv = {}", vk.params.num_variables()));

//         let mut transcript = IOPTranscript::<E::ScalarField>::new(b"hyperplonk");

//         let num_vars = vk.params.num_variables();

//         //  online public input of length 2^\ell
//         let ell = log2(vk.params.num_pub_input) as usize;

//         // public input length
//         if pub_input.len() != vk.params.num_pub_input {
//             return Err(HyperPlonkErrors::InvalidProver(format!(
//                 "Public input length is not correct: got {}, expect {}",
//                 pub_input.len(),
//                 1 << ell
//             )));
//         }

//         // =======================================================================
//         // 1. Verify sum check proof
//         // =======================================================================
//         let step = start_timer!(|| "verify sum check ");
//         // auxinfo for sum check
//         let sum_check_aux_info = VPAuxInfo::<E::ScalarField> {
//             max_degree: max(vk.params.gate_func.degree() + 1, 3), // max of gate identity zero check or permutation check (degree 2 + 1)
//             num_variables: num_vars,
//             phantom: PhantomData::default(),
//         };

//         // push witness to transcript
//         for w_com in proof.witness_commits.iter() {
//             transcript.append_serializable_element(b"w", w_com)?;
//         }

//         // get randomnesses for building evaluation
//         let alpha = transcript.get_and_append_challenge(b"alpha")?;
//         #[cfg(debug_assertions)]
//         println!("verifier alpha: {}", alpha);

//         let gamma = transcript.get_and_append_challenge(b"gamma")?;
//         let batch_factor = transcript.get_and_append_challenge(b"batch_zero_check_factor")?;
//         #[cfg(debug_assertions)]
//         println!("verifier batch_zero_check_factor: {}", batch_factor);

//         let r = transcript.get_and_append_challenge_vectors(b"0check r", num_vars)?;
//         let batch_sum_check_factor =
//             transcript.get_and_append_challenge(b"batch_sum_check_factor")?;
//         #[cfg(debug_assertions)]
//         println!(
//             "verifier batch_sum_check_factor: {}",
//             batch_sum_check_factor
//         );

//         // verify sum check
//         let sum_check_sub_claim = <Self as SumCheck<E::ScalarField>>::verify(
//             E::ScalarField::ZERO,
//             &proof.sum_check_proof,
//             &sum_check_aux_info,
//             &mut transcript,
//         )?;

//         // print all sum check sub claim points
//         #[cfg(debug_assertions)]
//         sum_check_sub_claim
//             .point
//             .iter()
//             .for_each(|point| println!("sum check sub claim point: {}", point));

//         // check batch sum check subclaim
//         // gate identity zero check
//         let mut f_eval = eval_f(
//             &vk.params.gate_func,
//             &proof.opening.selector_evals,
//             &proof.opening.witness_evals,
//         )?;
//         // print f_eval
//         #[cfg(debug_assertions)]
//         println!("gate identity eval: {}", f_eval);

//         // add permu zero checks
//         // get constant poly evaluation for permu zero check
//         let mut constant = -batch_factor;
//         let mut batch_factor_power = -batch_factor * batch_factor;
//         for _ in 0..(proof.opening.hp_evals.len() * 2 - 1) {
//             constant += batch_factor_power;
//             batch_factor_power *= batch_factor;
//         }
//         // print constant_eval which is the same as constant mathematically
//         #[cfg(debug_assertions)]
//         println!("constant eval: {}", constant);
//         f_eval += constant;

//         let mut batch_factor_lower_power = batch_factor;
//         let mut batch_factor_higher_power = batch_factor * batch_factor;

//         let hp_evals = proof.opening.hp_evals.clone();
//         let hq_evals = proof.opening.hq_evals.clone();

//         for i in 0..hp_evals.len() {
//             f_eval += hp_evals[i] * proof.opening.witness_evals[i] * batch_factor_lower_power;
//             f_eval += hp_evals[i] * proof.opening.perm_evals[i] * batch_factor_lower_power * alpha;
//             f_eval += hq_evals[i] * proof.opening.witness_evals[i] * batch_factor_higher_power;
//             f_eval +=
//                 hq_evals[i] * proof.opening.perm_index_evals[i] * batch_factor_higher_power * alpha;
//             f_eval += hp_evals[i] * batch_factor_lower_power * gamma;
//             f_eval += hq_evals[i] * batch_factor_higher_power * gamma;

//             batch_factor_lower_power = batch_factor_lower_power * batch_factor * batch_factor;
//             batch_factor_higher_power = batch_factor_higher_power * batch_factor * batch_factor;
//         }

//         // print f_eval
//         #[cfg(debug_assertions)]
//         println!("eval after permu zero check: {}", f_eval);

//         // multiply by eq_x_r to obtain sum check 1
//         let eq_x_r_eval = eq_eval(&sum_check_sub_claim.point, &r).unwrap();
//         f_eval *= eq_x_r_eval;

//         // print f_eval
//         #[cfg(debug_assertions)]
//         println!("eval after multiplying by eq_x_r: {}", f_eval);

//         // add permu sum check as sum check 2
//         hp_evals
//             .iter()
//             .for_each(|hp_eval| f_eval = f_eval + *hp_eval * batch_sum_check_factor);
//         // println!("eval after adding batch sum check: {}", f_eval);
//         hq_evals
//             .iter()
//             .for_each(|hq_eval| f_eval = f_eval - *hq_eval * batch_sum_check_factor);
//         #[cfg(debug_assertions)]
//         println!("eval after adding batch sum check: {}", f_eval);

//         if f_eval != sum_check_sub_claim.expected_evaluation {
//             return Err(HyperPlonkErrors::InvalidProof(format!(
//                 "sum check evaluation failed, verifier calculated eval: {}, expected: {}",
//                 f_eval, sum_check_sub_claim.expected_evaluation
//             )));
//         }

//         end_timer!(step);

//         // =======================================================================
//         // 2. Verify the opening against the commitment
//         // =======================================================================
//         let step = start_timer!(|| "verify opening");

//         let alpha = transcript.get_and_append_challenge(b"opening rlc").unwrap();
//         // create rlc of evaluations
//         let mut evaluations: Vec<E::ScalarField> = Vec::new();
//         evaluations.extend(proof.opening.perm_evals.iter());
//         evaluations.extend(proof.opening.perm_index_evals.iter());
//         evaluations.extend(proof.opening.selector_evals.iter());
//         evaluations.extend(proof.opening.witness_evals.iter());
//         evaluations.extend(proof.opening.hp_evals.iter());
//         evaluations.extend(proof.opening.hq_evals.iter());
//         let alphas = (0..evaluations.len())
//             .map(|i| alpha.pow(&[i as u64]))
//             .collect::<Vec<E::ScalarField>>();
//         let rlc_eval_calc = evaluations
//             .iter()
//             .zip(alphas.iter())
//             .map(|(eval, alpha)| *eval * *alpha)
//             .fold(E::ScalarField::zero(), |acc, x| acc + x);

//         // assert that calculated rlc_eval matches the one in the proof
//         // just a sanity check, should only use the calculated one in the future
//         if rlc_eval_calc != proof.opening.rlc_eval {
//             return Err(HyperPlonkErrors::InvalidProof(
//                 "opening rlc evaluation failed".to_string(),
//             ));
//         }

//         // get rlc of commitments
//         let mut comms: Vec<PCS::Commitment> = vec![];
//         comms.extend(vk.perm_commitments.0.iter());
//         comms.extend(vk.perm_commitments.1.iter());
//         comms.extend(vk.selector_commitments.iter());
//         comms.extend(proof.witness_commits.iter());
//         comms.extend(proof.h_comm.iter());
//         comms.extend(proof.h_prime_comm.iter());
//         let rlc_comms = comms
//             .iter()
//             .zip(alphas.iter())
//             .map(|(comm, alpha)| comm.0 * *alpha)
//             .fold(E::G1::zero(), |acc, x| acc + x);

//         // verify the opening against the commitment
//         let res = PCS::verify(
//             &vk.pcs_param,
//             &Commitment(rlc_comms.into_affine()),
//             &sum_check_sub_claim.point,
//             &rlc_eval_calc,
//             &proof.opening.proof,
//         )?;

//         end_timer!(step);
//         end_timer!(start);

//         Ok(res)
//     }
// }

// #[cfg(test)]
// mod tests {
//     use super::*;
//     use crate::hyperplonk::full_snark::{custom_gate::CustomizedGates, structs::HyperPlonkParams};
//     use crate::hyperplonk::pcs::multilinear_kzg::MultilinearKzgPCS;
//     use crate::read_write::identity_permutation_mles;
//     use ark_bls12_381::Bls12_381;
//     use ark_std::rand::rngs::StdRng;
//     use ark_std::rand::SeedableRng;
//     use ark_std::One;

//     #[test]
//     fn test_hyperplonk_e2e() -> Result<(), HyperPlonkErrors> {
//         // Example:
//         //     q_L(X) * W_1(X)^5 - W_2(X) = 0
//         // is represented as
//         // vec![
//         //     ( 1,    Some(id_qL),    vec![id_W1, id_W1, id_W1, id_W1, id_W1]),
//         //     (-1,    None,           vec![id_W2])
//         // ]
//         //
//         // 4 public input
//         // 1 selector,
//         // 2 witnesses,
//         // 2 variables for MLE,
//         // 4 wires,
//         let gates = CustomizedGates {
//             gates: vec![(1, Some(0), vec![0, 0, 0, 0, 0]), (-1, None, vec![1])],
//             // gates: vec![(1, Some(0), vec![0]), (-1, None, vec![1])],
//         };
//         test_hyperplonk_helper::<Bls12_381>(gates)
//     }

//     fn test_hyperplonk_helper<E: Pairing>(
//         gate_func: CustomizedGates,
//     ) -> Result<(), HyperPlonkErrors> {
//         {
//             let seed = [
//                 1, 0, 0, 0, 23, 0, 0, 0, 200, 1, 0, 0, 210, 30, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
//                 0, 0, 0, 0, 0, 0,
//             ];
//             let mut rng = StdRng::from_seed(seed);
//             let pcs_srs = MultilinearKzgPCS::<E>::gen_srs_for_testing(&mut rng, 10)?;

//             let num_constraints = 4;
//             let num_pub_input = 4;
//             let nv = log2(num_constraints) as usize;
//             let num_witnesses = 2;

//             // generate index
//             let params = HyperPlonkParams {
//                 num_constraints,
//                 num_pub_input,
//                 gate_func: gate_func.clone(),
//             };
//             // let permutation = identity_permutation_mles(nv, num_witnesses);
//             let permutation = vec![
//                 Arc::new(Mutex::new(DenseMLPolyStream::from_evaluations_vec(
//                     2,
//                     vec![
//                         E::ScalarField::from(1u64),
//                         E::ScalarField::from(0u64),
//                         E::ScalarField::from(2u64),
//                         E::ScalarField::from(3u64),
//                     ],
//                     None,
//                     None,
//                 ))),
//                 Arc::new(Mutex::new(DenseMLPolyStream::from_evaluations_vec(
//                     2,
//                     vec![
//                         E::ScalarField::from(5u64),
//                         E::ScalarField::from(4u64),
//                         E::ScalarField::from(6u64),
//                         E::ScalarField::from(7u64),
//                     ],
//                     None,
//                     None,
//                 ))),
//             ];
//             let permutation_index = identity_permutation_mles(nv, num_witnesses);
//             let q1 = Arc::new(Mutex::new(DenseMLPolyStream::from_evaluations_vec(
//                 2,
//                 vec![
//                     E::ScalarField::one(),
//                     E::ScalarField::one(),
//                     E::ScalarField::one(),
//                     E::ScalarField::one(),
//                 ],
//                 None,
//                 None,
//             )));
//             let index = HyperPlonkIndex {
//                 params: params.clone(),
//                 permutation,
//                 permutation_index,
//                 selectors: vec![q1],
//             };

//             // generate pk and vks
//             let (pk, vk) =
//                 <PolyIOP<E::ScalarField> as HyperPlonkSNARK<E, MultilinearKzgPCS<E>>>::preprocess(
//                     &index, &pcs_srs,
//                 )?;

//             // w1 := [1, 1, 2, 3]
//             let w1 = Arc::new(Mutex::new(DenseMLPolyStream::from_evaluations_vec(
//                 2,
//                 vec![
//                     E::ScalarField::one(),
//                     E::ScalarField::one(),
//                     E::ScalarField::from(2u128),
//                     E::ScalarField::from(3u128),
//                 ],
//                 None,
//                 None,
//             )));
//             // // w2 := [1, 1, 2, 3]
//             // let w2 = Arc::new(Mutex::new(DenseMLPolyStream::from_evaluations_vec(
//             //     2,
//             //     vec![E::ScalarField::one(), E::ScalarField::one(), E::ScalarField::from(2u128), E::ScalarField::from(3u128)],
//             //     None,
//             //     None,
//             // )));
//             // w2 := [1^5, 1^5, 2^5, 3^5]
//             let w2 = Arc::new(Mutex::new(DenseMLPolyStream::from_evaluations_vec(
//                 2,
//                 vec![
//                     E::ScalarField::one(),
//                     E::ScalarField::one(),
//                     E::ScalarField::from(32u128),
//                     E::ScalarField::from(243u128),
//                 ],
//                 None,
//                 None,
//             )));
//             // public input = w1
//             let pi = vec![
//                 E::ScalarField::one(),
//                 E::ScalarField::one(),
//                 E::ScalarField::from(2u128),
//                 E::ScalarField::from(3u128),
//             ];

//             // generate a proof and verify
//             let proof =
//                 <PolyIOP<E::ScalarField> as HyperPlonkSNARK<E, MultilinearKzgPCS<E>>>::prove(
//                     &pk,
//                     &pi,
//                     vec![w1.clone(), w2.clone()],
//                 )?;

//             let _verify =
//                 <PolyIOP<E::ScalarField> as HyperPlonkSNARK<E, MultilinearKzgPCS<E>>>::verify(
//                     &vk, &pi, &proof,
//                 )?;

//             assert!(_verify);
//         }

//         {
//             // bad path 1: wrong permutation
//             let seed = [
//                 1, 0, 0, 0, 23, 0, 0, 0, 200, 1, 0, 0, 210, 30, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
//                 0, 0, 0, 0, 0, 0,
//             ];
//             let mut rng = StdRng::from_seed(seed);
//             let pcs_srs = MultilinearKzgPCS::<E>::gen_srs_for_testing(&mut rng, 10)?;

//             let num_constraints = 4;
//             let num_pub_input = 4;
//             let nv = log2(num_constraints) as usize;
//             let num_witnesses = 2;

//             // generate index
//             let params = HyperPlonkParams {
//                 num_constraints,
//                 num_pub_input,
//                 gate_func,
//             };

//             // let permutation = identity_permutation(nv, num_witnesses);
//             let rand_perm = vec![
//                 Arc::new(Mutex::new(DenseMLPolyStream::from_evaluations_vec(
//                     2,
//                     vec![
//                         E::ScalarField::from(1u64),
//                         E::ScalarField::from(3u64),
//                         E::ScalarField::from(6u64),
//                         E::ScalarField::from(7u64),
//                     ],
//                     None,
//                     None,
//                 ))),
//                 Arc::new(Mutex::new(DenseMLPolyStream::from_evaluations_vec(
//                     2,
//                     vec![
//                         E::ScalarField::from(2u64),
//                         E::ScalarField::from(5u64),
//                         E::ScalarField::from(0u64),
//                         E::ScalarField::from(4u64),
//                     ],
//                     None,
//                     None,
//                 ))),
//             ];

//             let permutation_index = identity_permutation_mles(nv, num_witnesses);
//             let q1 = Arc::new(Mutex::new(DenseMLPolyStream::from_evaluations_vec(
//                 2,
//                 vec![
//                     E::ScalarField::one(),
//                     E::ScalarField::one(),
//                     E::ScalarField::one(),
//                     E::ScalarField::one(),
//                 ],
//                 None,
//                 None,
//             )));
//             let bad_index = HyperPlonkIndex {
//                 params,
//                 permutation: rand_perm,
//                 permutation_index,
//                 selectors: vec![q1],
//             };

//             // generate pk and vks
//             let (pk, bad_vk) = <PolyIOP<E::ScalarField> as HyperPlonkSNARK<
//                 E,
//                 MultilinearKzgPCS<E>,
//             >>::preprocess(&bad_index, &pcs_srs)?;

//             // w1 := [1, 1, 2, 3]
//             let w1 = Arc::new(Mutex::new(DenseMLPolyStream::from_evaluations_vec(
//                 2,
//                 vec![
//                     E::ScalarField::one(),
//                     E::ScalarField::one(),
//                     E::ScalarField::from(2u128),
//                     E::ScalarField::from(3u128),
//                 ],
//                 None,
//                 None,
//             )));
//             // w2 := [1^5, 1^5, 2^5, 3^5]
//             let w2 = Arc::new(Mutex::new(DenseMLPolyStream::from_evaluations_vec(
//                 2,
//                 vec![
//                     E::ScalarField::one(),
//                     E::ScalarField::one(),
//                     E::ScalarField::from(32u128),
//                     E::ScalarField::from(243u128),
//                 ],
//                 None,
//                 None,
//             )));
//             // public input = w1
//             let pi = vec![
//                 E::ScalarField::one(),
//                 E::ScalarField::one(),
//                 E::ScalarField::from(2u128),
//                 E::ScalarField::from(3u128),
//             ];

//             // generate a proof and verify
//             let proof =
//                 <PolyIOP<E::ScalarField> as HyperPlonkSNARK<E, MultilinearKzgPCS<E>>>::prove(
//                     &pk,
//                     &pi,
//                     vec![w1.clone(), w2.clone()],
//                 )?;

//             assert!(
//                 <PolyIOP<E::ScalarField> as HyperPlonkSNARK<E, MultilinearKzgPCS<E>>>::verify(
//                     &bad_vk, &pi, &proof,
//                 )
//                 .is_err()
//             );
//         }

//         Ok(())
//     }
// }
