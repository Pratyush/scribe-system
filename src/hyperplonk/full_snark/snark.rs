// Copyright (c) 2023 Espresso Systems (espressosys.com)
// This file is part of the HyperPlonk library.

// You should have received a copy of the MIT License
// along with the HyperPlonk library. If not, see <https://mit-license.org/>.

use crate::hyperplonk::arithmetic::virtual_polynomial::{
    // evaluate_opt, gen_eval_point,
    VPAuxInfo,
};
use crate::read_write::ReadWriteStream;
use crate::{
    hyperplonk::{
        arithmetic::virtual_polynomial::{merge_polynomials, VirtualPolynomial},
        full_snark::{
            errors::HyperPlonkErrors,
            structs::{
                HyperPlonkIndex, HyperPlonkProof, HyperPlonkProvingKey, HyperPlonkVerifyingKey,
            },
            utils::{
                build_f,
                eval_f,
                eval_perm_gate,
                prover_sanity_check,
                // PcsAccumulator
            },
            witness::WitnessColumn,
            HyperPlonkSNARK,
        },
        poly_iop::perm_check::PermutationCheckSubClaim,
    },
    read_write::DenseMLPolyStream,
};
use ark_ff::PrimeField;
// use ark_ec::pairing::Pairing;
use crate::hyperplonk::transcript::IOPTranscript;
use crate::hyperplonk::{
    // pcs::prelude::{Commitment, PolynomialCommitmentScheme},
    poly_iop::{
        prelude::{PermutationCheck, ZeroCheck},
        PolyIOP,
    },
    // BatchProof,
};
use ark_poly::DenseMultilinearExtension;
use ark_std::{end_timer, log2, start_timer, One, Zero};
use rayon::iter::IntoParallelRefIterator;
#[cfg(feature = "parallel")]
use rayon::iter::ParallelIterator;
use std::{
    marker::PhantomData,
    sync::{Arc, Mutex},
};

// impl<E, PCS> HyperPlonkSNARK<E, PCS> for PolyIOP<E::ScalarField>
// where
//     E: Pairing,
//     // Ideally we want to access polynomial as PCS::Polynomial, instead of instantiating it here.
//     // But since PCS::Polynomial can be both univariate or multivariate in our implementation
//     // we cannot bound PCS::Polynomial with a property trait bound.
//     PCS: PolynomialCommitmentScheme<
//         E,
//         Polynomial = Arc<DenseMultilinearExtension<E::ScalarField>>,
//         Point = Vec<E::ScalarField>,
//         Evaluation = E::ScalarField,
//         Commitment = Commitment<E>,
//         BatchProof = BatchProof<E, PCS>,
//     >,
impl<F: PrimeField> HyperPlonkSNARK<F> for PolyIOP<F> {
    type Index = HyperPlonkIndex<F>;
    type ProvingKey = HyperPlonkProvingKey<F>;
    type VerifyingKey = HyperPlonkVerifyingKey<F>;
    type Proof = HyperPlonkProof<Self, F>;

    fn preprocess(
        index: &Self::Index,
        // pcs_srs: &PCS::SRS,
    ) -> Result<(Self::ProvingKey, Self::VerifyingKey), HyperPlonkErrors> {
        let num_vars = index.num_variables();
        let supported_ml_degree = num_vars;

        // extract PCS prover and verifier keys from SRS
        // let (pcs_prover_param, pcs_verifier_param) =
        //     PCS::trim(pcs_srs, None, Some(supported_ml_degree))?;

        // assert that index.permutation and index.permutation_index have the same length
        if index.permutation.len() != index.permutation_index.len() {
            return Err(HyperPlonkErrors::InvalidParameters(
                "permutation and permutation_index have different lengths".to_string(),
            ));
        }

        let perm_oracle = Arc::new(Mutex::new(DenseMLPolyStream::from_evaluations_slice(
            num_vars + log2(index.params.num_witness_columns()) as usize, // returns ceiling of log2 of num_wintess, added to num_vars after the merge
            &index.permutation, // these are merged perm provided by the argument
            None,
            None,
        )));

        // println!("snark prover perm_oracle: {:?}", perm_oracle);

        let perm_index_oracle = Arc::new(Mutex::new(DenseMLPolyStream::from_evaluations_slice(
            num_vars + log2(index.params.num_witness_columns()) as usize, // returns ceiling of log2 of num_wintess, added to num_vars after the merge
            &index.permutation_index, // these are merged index provided by the argument
            None,
            None,
        )));

        // println!("snark prover perm_index_oracle: {:?}", perm_index_oracle);

        // build selector oracles and commit to it
        let selector_oracles: Vec<Arc<Mutex<DenseMLPolyStream<F>>>> = index
            .selectors
            .iter()
            .map(|s| Arc::new(Mutex::new(DenseMLPolyStream::from(s))))
            .collect();

        // let selector_commitments = selector_oracles
        //     .par_iter()
        //     .map(|poly| PCS::commit(&pcs_prover_param, poly))
        //     .collect::<Result<Vec<_>, _>>()?;

        Ok((
            Self::ProvingKey {
                params: index.params.clone(),
                permutation_oracles: (perm_oracle.clone(), perm_index_oracle.clone()),
                selector_oracles: selector_oracles.clone(),
                // selector_commitments: selector_commitments.clone(),
                // permutation_commitments: perm_comms.clone(),
                // pcs_param: pcs_prover_param,
            },
            Self::VerifyingKey {
                params: index.params.clone(),
                // pcs_param: pcs_verifier_param,
                // selector_commitments,
                // perm_commitments: perm_comms,
                selector: selector_oracles,
                perm: (perm_oracle, perm_index_oracle),
            },
        ))
    }

    /// Generate HyperPlonk SNARK proof.
    ///
    /// Inputs:
    /// - `pk`: circuit proving key
    /// - `pub_input`: online public input of length 2^\ell
    /// - `witness`: witness assignment of length 2^n
    /// Outputs:
    /// - The HyperPlonk SNARK proof.
    ///
    /// Steps:
    ///
    /// 1. Commit Witness polynomials `w_i(x)` and append commitment to
    /// transcript
    ///
    /// 2. Run ZeroCheck on
    ///
    ///     `f(q_0(x),...q_l(x), w_0(x),...w_d(x))`  
    ///
    /// where `f` is the constraint polynomial i.e.,
    /// ```ignore
    ///     f(q_l, q_r, q_m, q_o, w_a, w_b, w_c)
    ///     = q_l w_a(x) + q_r w_b(x) + q_m w_a(x)w_b(x) - q_o w_c(x)
    /// ```
    /// in vanilla plonk, and obtain a ZeroCheckSubClaim
    ///
    /// 3. Run permutation check on `\{w_i(x)\}` and `permutation_oracle`, and
    /// obtain a PermCheckSubClaim.
    ///
    /// 4. Generate evaluations and corresponding proofs
    /// - 4.1. (deferred) batch opening prod(x) at
    ///   - [0, perm_check_point]
    ///   - [1, perm_check_point]
    ///   - [perm_check_point, 0]
    ///   - [perm_check_point, 1]
    ///   - [1,...1, 0]
    ///
    /// - 4.2. permutation check evaluations and proofs
    ///   - 4.2.1. (deferred) wi_poly(perm_check_point)
    ///
    /// - 4.3. zero check evaluations and proofs
    ///   - 4.3.1. (deferred) wi_poly(zero_check_point)
    ///   - 4.3.2. (deferred) selector_poly(zero_check_point)
    ///
    /// - 4.4. public input consistency checks
    ///   - pi_poly(r_pi) where r_pi is sampled from transcript
    ///
    /// - 5. deferred batch opening
    fn prove(
        pk: &Self::ProvingKey,
        pub_input: &[F],
        witnesses: &[WitnessColumn<F>],
    ) -> Result<Self::Proof, HyperPlonkErrors> {
        let start = start_timer!(|| "hyperplonk proving");
        let mut transcript = IOPTranscript::<F>::new(b"hyperplonk");

        prover_sanity_check(&pk.params, pub_input, witnesses)?;

        // witness assignment of length 2^n
        let num_vars = pk.params.num_variables();

        // online public input of length 2^\ell
        let ell = log2(pk.params.num_pub_input) as usize;

        // We use accumulators to store the polynomials and their eval points.
        // They are batch opened at a later stage.
        // let mut pcs_acc = PcsAccumulator::<E, PCS>::new(num_vars);

        // =======================================================================
        // 1. Commit Witness polynomials `w_i(x)` and append commitment to
        // transcript
        // =======================================================================
        let step = start_timer!(|| "commit witnesses");

        let witness_polys: Vec<Arc<Mutex<DenseMLPolyStream<F>>>> = witnesses
            .iter()
            .map(|w| Arc::new(Mutex::new(DenseMLPolyStream::from(w))))
            .collect();

        // this should be a part of preprocessing, so not a part of prover time
        // it gets into this prove function as preprocessing probably can't take witnesses as they are private
        let witness_polys_merge = merge_polynomials(witnesses, num_vars).unwrap();

        // feeding to the transcript is needed to get it started.
        // the witness commitment should be feeded. however, we don't have that component yet
        // this part should be updated once we have the PCS.
        let _ = transcript.append_serializable_element(b"transcript start", &F::one());

        // let witness_commits = witness_polys
        //     .par_iter()
        //     .map(|x| PCS::commit(&pk.pcs_param, x).unwrap())
        //     .collect::<Vec<_>>();
        // for w_com in witness_commits.iter() {
        //     transcript.append_serializable_element(b"w", w_com)?;
        // }

        end_timer!(step);
        // =======================================================================
        // 2 Run ZeroCheck on
        //
        //     `f(q_0(x),...q_l(x), w_0(x),...w_d(x))`
        //
        // where `f` is the constraint polynomial i.e.,
        //
        //     f(q_l, q_r, q_m, q_o, w_a, w_b, w_c)
        //     = q_l w_a(x) + q_r w_b(x) + q_m w_a(x)w_b(x) - q_o w_c(x)
        //
        // in vanilla plonk, and obtain a ZeroCheckSubClaim
        // =======================================================================
        let step = start_timer!(|| "ZeroCheck on f");

        let fx = build_f(
            &pk.params.gate_func,
            pk.params.num_variables(),
            &pk.selector_oracles,
            &witness_polys,
        )?;

        let zero_check_proof = <Self as ZeroCheck<F>>::prove(&fx, &mut transcript)?;
        end_timer!(step);
        // =======================================================================
        // 3. Run permutation check on `\{w_i(x)\}` and `permutation_oracle`, and
        // obtain a PermCheckSubClaim.
        // =======================================================================
        let step = start_timer!(|| "Permutation check on w_i(x)");

        // // print all entries of pk.permutation_oracles.0
        // // lock, read_next, and print in a loop
        // let mut pi_locked = pk.permutation_oracles.0.lock().unwrap();
        // while let Some(pi_val) = pi_locked.read_next() {
        //     println!("snark prover pi_val: {}", pi_val);
        // }
        // pi_locked.read_restart();
        // drop(pi_locked);
        // // print all entries of pk.permutation_oracles.1
        // // lock, read_next, and print in a loop
        // let mut index_locked = pk.permutation_oracles.1.lock().unwrap();
        // while let Some(index_val) = index_locked.read_next() {
        //     println!("snark prover index_val: {}", index_val);
        // }
        // index_locked.read_restart();
        // drop(index_locked);

        let (perm_check_proof, hp, hq, eq_x_r) = <Self as PermutationCheck<F>>::prove_plonk(
            witness_polys_merge.clone(),
            pk.permutation_oracles.0.clone(),
            pk.permutation_oracles.1.clone(),
            &mut transcript,
        )?;
        let perm_check_point = &perm_check_proof.point;

        end_timer!(step);
        // // =======================================================================
        // // 4. Generate evaluations and corresponding proofs
        // // - permcheck
        // //  1. (deferred) batch opening prod(x) at
        // //   - [perm_check_point]
        // //   - [perm_check_point[2..n], 0]
        // //   - [perm_check_point[2..n], 1]
        // //   - [1,...1, 0]
        // //  2. (deferred) batch opening frac(x) at
        // //   - [perm_check_point]
        // //   - [perm_check_point[2..n], 0]
        // //   - [perm_check_point[2..n], 1]
        // //  3. (deferred) batch opening s_id(x) at
        // //   - [perm_check_point]
        // //  4. (deferred) batch opening perms(x) at
        // //   - [perm_check_point]
        // //  5. (deferred) batch opening witness_i(x) at
        // //   - [perm_check_point]
        // //
        // // - zero check evaluations and proofs
        // //   - 4.3.1. (deferred) wi_poly(zero_check_point)
        // //   - 4.3.2. (deferred) selector_poly(zero_check_point)
        // //
        // // - 4.4. (deferred) public input consistency checks
        // //   - pi_poly(r_pi) where r_pi is sampled from transcript
        // // =======================================================================
        // let step = start_timer!(|| "opening and evaluations");

        // // (perm_check_point[2..n], 0)
        // let perm_check_point_0 = [
        //     &[E::ScalarField::zero()],
        //     &perm_check_point[0..num_vars - 1],
        // ]
        // .concat();
        // // (perm_check_point[2..n], 1)
        // let perm_check_point_1 =
        //     [&[E::ScalarField::one()], &perm_check_point[0..num_vars - 1]].concat();
        // // (1, ..., 1, 0)
        // let prod_final_query_point = [
        //     vec![E::ScalarField::zero()],
        //     vec![E::ScalarField::one(); num_vars - 1],
        // ]
        // .concat();

        // // prod(x)'s points
        // pcs_acc.insert_poly_and_points(&prod_x, &perm_check_proof.prod_x_comm, perm_check_point);
        // pcs_acc.insert_poly_and_points(&prod_x, &perm_check_proof.prod_x_comm, &perm_check_point_0);
        // pcs_acc.insert_poly_and_points(&prod_x, &perm_check_proof.prod_x_comm, &perm_check_point_1);
        // pcs_acc.insert_poly_and_points(
        //     &prod_x,
        //     &perm_check_proof.prod_x_comm,
        //     &prod_final_query_point,
        // );

        // // frac(x)'s points
        // pcs_acc.insert_poly_and_points(&frac_poly, &perm_check_proof.frac_comm, perm_check_point);
        // pcs_acc.insert_poly_and_points(
        //     &frac_poly,
        //     &perm_check_proof.frac_comm,
        //     &perm_check_point_0,
        // );
        // pcs_acc.insert_poly_and_points(
        //     &frac_poly,
        //     &perm_check_proof.frac_comm,
        //     &perm_check_point_1,
        // );

        // // perms(x)'s points
        // for (perm, pcom) in pk
        //     .permutation_oracles
        //     .iter()
        //     .zip(pk.permutation_commitments.iter())
        // {
        //     pcs_acc.insert_poly_and_points(perm, pcom, perm_check_point);
        // }

        // // witnesses' points
        // // TODO: refactor so it remains correct even if the order changed
        // for (wpoly, wcom) in witness_polys.iter().zip(witness_commits.iter()) {
        //     pcs_acc.insert_poly_and_points(wpoly, wcom, perm_check_point);
        // }
        // for (wpoly, wcom) in witness_polys.iter().zip(witness_commits.iter()) {
        //     pcs_acc.insert_poly_and_points(wpoly, wcom, &zero_check_proof.point);
        // }

        // //   - 4.3.2. (deferred) selector_poly(zero_check_point)
        // pk.selector_oracles
        //     .iter()
        //     .zip(pk.selector_commitments.iter())
        //     .for_each(|(poly, com)| {
        //         pcs_acc.insert_poly_and_points(poly, com, &zero_check_proof.point)
        //     });

        // // - 4.4. public input consistency checks
        // //   - pi_poly(r_pi) where r_pi is sampled from transcript
        // let r_pi = transcript.get_and_append_challenge_vectors(b"r_pi", ell)?;
        // // padded with zeros
        // let r_pi_padded = [r_pi, vec![E::ScalarField::zero(); num_vars - ell]].concat();
        // // Evaluate witness_poly[0] at r_pi||0s which is equal to public_input evaluated
        // // at r_pi. Assumes that public_input is a power of 2
        // pcs_acc.insert_poly_and_points(&witness_polys[0], &witness_commits[0], &r_pi_padded);
        // end_timer!(step);

        // // =======================================================================
        // // 5. deferred batch opening
        // // =======================================================================
        // let step = start_timer!(|| "deferred batch openings prod(x)");
        // let batch_openings = pcs_acc.multi_open(&pk.pcs_param, &mut transcript)?;
        // end_timer!(step);

        end_timer!(start);

        Ok(HyperPlonkProof {
            // PCS commit for witnesses
            // witness_commits,
            // batch_openings,
            // batch_openings,
            // =======================================================================
            // IOP proofs
            // =======================================================================
            // the custom gate zerocheck proof
            zero_check_proof,
            // the permutation check proof for copy constraints
            perm_check_proof,
            // shouldn't return any of the following fields if it's zk but just doing benchmarking now
            zero_check_virtual_poly: fx,
            hp,
            hq,
            eq_x_r,
            witness_polys_merge,
        })
    }

    /// Verify the HyperPlonk proof.
    ///
    /// Inputs:
    /// - `vk`: verification key
    /// - `pub_input`: online public input
    /// - `proof`: HyperPlonk SNARK proof
    /// Outputs:
    /// - Return a boolean on whether the verification is successful
    ///
    /// 1. Verify zero_check_proof on
    ///
    ///     `f(q_0(x),...q_l(x), w_0(x),...w_d(x))`
    ///
    /// where `f` is the constraint polynomial i.e.,
    /// ```ignore
    ///     f(q_l, q_r, q_m, q_o, w_a, w_b, w_c)
    ///     = q_l w_a(x) + q_r w_b(x) + q_m w_a(x)w_b(x) - q_o w_c(x)
    /// ```
    /// in vanilla plonk, and obtain a ZeroCheckSubClaim
    ///
    /// 2. Verify perm_check_proof on `\{w_i(x)\}` and `permutation_oracles`
    ///
    /// 3. check subclaim validity
    ///
    /// 4. Verify the opening against the commitment:
    /// - check permutation check evaluations
    /// - check zero check evaluations
    /// - public input consistency checks
    fn verify(
        vk: &Self::VerifyingKey,
        pub_input: &[F],
        proof: &Self::Proof,
    ) -> Result<bool, HyperPlonkErrors> {
        let start = start_timer!(|| "hyperplonk verification");

        let mut transcript = IOPTranscript::<F>::new(b"hyperplonk");

        // feeding to the transcript is needed to get it started.
        // the witness commitment should be feeded. however, we don't have that component yet
        // this part should be updated once we have the PCS.
        let _ = transcript.append_serializable_element(b"transcript start", &F::one());

        let num_selectors = vk.params.num_selector_columns();
        let num_witnesses = vk.params.num_witness_columns();
        let num_vars = vk.params.num_variables();

        //  online public input of length 2^\ell
        let ell = log2(vk.params.num_pub_input) as usize;

        // decompose proof
        let HyperPlonkProof {
            zero_check_proof,
            perm_check_proof,
            zero_check_virtual_poly,
            hp,
            hq,
            eq_x_r,
            witness_polys_merge,
        } = proof;

        // =======================================================================
        // 0. sanity checks
        // =======================================================================
        // public input length
        if pub_input.len() != vk.params.num_pub_input {
            return Err(HyperPlonkErrors::InvalidProver(format!(
                "Public input length is not correct: got {}, expect {}",
                pub_input.len(),
                1 << ell
            )));
        }

        // // Extract evaluations from openings
        // let prod_evals = &proof.batch_openings.f_i_eval_at_point_i[0..4];
        // let frac_evals = &proof.batch_openings.f_i_eval_at_point_i[4..7];
        // let perm_evals = &proof.batch_openings.f_i_eval_at_point_i[7..7 + num_witnesses];
        // let witness_perm_evals =
        //     &proof.batch_openings.f_i_eval_at_point_i[7 + num_witnesses..7 + 2 * num_witnesses];
        // let witness_gate_evals =
        //     &proof.batch_openings.f_i_eval_at_point_i[7 + 2 * num_witnesses..7 + 3 * num_witnesses];
        // let selector_evals = &proof.batch_openings.f_i_eval_at_point_i
        //     [7 + 3 * num_witnesses..7 + 3 * num_witnesses + num_selectors];
        // let pi_eval = proof.batch_openings.f_i_eval_at_point_i.last().unwrap();

        // =======================================================================
        // 1. Verify zero_check_proof on
        //     `f(q_0(x),...q_l(x), w_0(x),...w_d(x))`
        //
        // where `f` is the constraint polynomial i.e.,
        //
        //     f(q_l, q_r, q_m, q_o, w_a, w_b, w_c)
        //     = q_l w_a(x) + q_r w_b(x) + q_m w_a(x)w_b(x) - q_o w_c(x)
        //
        // =======================================================================
        let step = start_timer!(|| "verify zero check");
        // Zero check and perm check have different AuxInfo
        let zero_check_aux_info = VPAuxInfo::<F> {
            max_degree: vk.params.gate_func.degree(),
            num_variables: num_vars,
            phantom: PhantomData::default(),
        };
        // // push witness to transcript
        // for w_com in proof.witness_commits.iter() {
        //     transcript.append_serializable_element(b"w", w_com)?;
        // }

        println!("gate check verify starts");

        let zero_check_sub_claim = <Self as ZeroCheck<F>>::verify(
            zero_check_proof,
            &zero_check_aux_info,
            &mut transcript,
        )?;

        // // check zero check subclaim
        // let f_eval = eval_f(&vk.params.gate_func, selector_evals, witness_gate_evals)?;
        // if f_eval != zero_check_sub_claim.expected_evaluation {
        //     return Err(HyperPlonkErrors::InvalidProof(
        //         "zero check evaluation failed".to_string(),
        //     ));
        // }

        println!("checkpoint 0");

        let evaluated_point = zero_check_virtual_poly
            .evaluate(std::slice::from_ref(
                &zero_check_sub_claim.point.last().unwrap(), // last field element of the point
            ))
            .unwrap();

        println!("checkpoint 1");

        assert!(
            evaluated_point == zero_check_sub_claim.expected_evaluation,
            "wrong subclaim"
        );

        end_timer!(step);
        // =======================================================================
        // 2. Verify perm_check_proof on `\{w_i(x)\}` and `permutation_oracle`
        // =======================================================================
        let step = start_timer!(|| "verify permutation check");

        // Zero check and perm check have different AuxInfo
        let perm_check_aux_info = VPAuxInfo::<F> {
            // Prod(x) has a max degree of witnesses.len() + 1
            max_degree: 2, // max degree is always 2 for the single column perm check (passed into the perm check verify and doesn't account for the eq_x_r, the sum check verify will need an aux_info that adds the eq_x_r degree of 1)
            num_variables: num_vars + log2(vk.params.num_witness_columns()) as usize, // need the num_vars of the merged witness, not the num_vars of the gate identity check, which doesn't merge witness columns
            phantom: PhantomData::default(),
        };

        println!("perm check verify starts");

        let PermutationCheckSubClaim {
            point: perm_check_point,
            expected_evaluation,
            permu_check_challenge,
            batch_sum_check_challenge,
            zero_check_init_challenge,
        } = <PolyIOP<F> as PermutationCheck<F>>::verify(
            perm_check_proof,
            &perm_check_aux_info,
            &mut transcript,
        )?;

        let mut poly = VirtualPolynomial::build_perm_check_poly_plonk(
            hp.clone(),
            hq.clone(),
            witness_polys_merge.clone(),
            vk.perm.0.clone(),
            vk.perm.1.clone(),
            permu_check_challenge,
            batch_sum_check_challenge,
        )
        .unwrap();

        poly.mul_by_mle(eq_x_r.clone(), F::ONE)?;

        // get sumcheck for t_0 = sum over x in {0,1}^n of (h_q(x) - h_q(x)) = 0
        // add term batch_factor^2 * t_0 to f_hat
        // t_0 = h_p - h_q
        let _ = poly.add_mle_list(
            vec![hp.clone()],
            batch_sum_check_challenge * batch_sum_check_challenge,
        );
        let _ = poly.add_mle_list(
            vec![hq.clone()],
            -batch_sum_check_challenge * batch_sum_check_challenge,
        );

        // print all elements of all streams of poly
        // lock, read_next, and print in a loop
        poly.flattened_ml_extensions
            .iter()
            .enumerate()
            .for_each(|(i, stream)| {
                let mut locked = stream.lock().unwrap();
                while let Some(val) = locked.read_next() {
                    println!("snark verifier final stream[{}] val: {}", i, val);
                }
                locked.read_restart();
                drop(locked);
            });
        // print all perm check point elements
        perm_check_point.iter().for_each(|point| {
            println!("snark verifier perm_check_point: {}", point);
        });

        let evaluated_point = poly
            .evaluate(std::slice::from_ref(&perm_check_point.last().unwrap()))
            .unwrap();
        assert!(
            evaluated_point == expected_evaluation,
            "{}",
            format!(
                "wrong subclaim, expected: {}, got: {}",
                expected_evaluation, evaluated_point
            )
        );

        // let alpha = perm_check_sub_claim.product_check_sub_claim.alpha;
        // let (beta, gamma) = perm_check_sub_claim.challenges;

        // let mut id_evals = vec![];
        // for i in 0..num_witnesses {
        //     let ith_point = gen_eval_point(i, log2(num_witnesses) as usize, &perm_check_point[..]);
        //     id_evals.push(vk.params.eval_id_oracle(&ith_point[..])?);
        // }

        // // check evaluation subclaim
        // let perm_gate_eval = eval_perm_gate(
        //     prod_evals,
        //     frac_evals,
        //     witness_perm_evals,
        //     &id_evals[..],
        //     perm_evals,
        //     alpha,
        //     beta,
        //     gamma,
        //     *perm_check_point.last().unwrap(),
        // )?;
        // if perm_gate_eval
        //     != perm_check_sub_claim
        //         .product_check_sub_claim
        //         .zero_check_sub_claim
        //         .expected_evaluation
        // {
        //     return Err(HyperPlonkErrors::InvalidVerifier(
        //         "evaluation failed".to_string(),
        //     ));
        // }

        end_timer!(step);
        // // =======================================================================
        // // 3. Verify the opening against the commitment
        // // =======================================================================
        // let step = start_timer!(|| "assemble commitments");

        // // generate evaluation points and commitments
        // let mut comms = vec![];
        // let mut points = vec![];

        // let perm_check_point_0 = [
        //     &[E::ScalarField::zero()],
        //     &perm_check_point[0..num_vars - 1],
        // ]
        // .concat();
        // let perm_check_point_1 =
        //     [&[E::ScalarField::one()], &perm_check_point[0..num_vars - 1]].concat();
        // let prod_final_query_point = [
        //     vec![E::ScalarField::zero()],
        //     vec![E::ScalarField::one(); num_vars - 1],
        // ]
        // .concat();

        // // prod(x)'s points
        // comms.push(proof.perm_check_proof.prod_x_comm);
        // comms.push(proof.perm_check_proof.prod_x_comm);
        // comms.push(proof.perm_check_proof.prod_x_comm);
        // comms.push(proof.perm_check_proof.prod_x_comm);
        // points.push(perm_check_point.clone());
        // points.push(perm_check_point_0.clone());
        // points.push(perm_check_point_1.clone());
        // points.push(prod_final_query_point);
        // // frac(x)'s points
        // comms.push(proof.perm_check_proof.frac_comm);
        // comms.push(proof.perm_check_proof.frac_comm);
        // comms.push(proof.perm_check_proof.frac_comm);
        // points.push(perm_check_point.clone());
        // points.push(perm_check_point_0);
        // points.push(perm_check_point_1);

        // // perms' points
        // for &pcom in vk.perm_commitments.iter() {
        //     comms.push(pcom);
        //     points.push(perm_check_point.clone());
        // }

        // // witnesses' points
        // // TODO: merge points
        // for &wcom in proof.witness_commits.iter() {
        //     comms.push(wcom);
        //     points.push(perm_check_point.clone());
        // }
        // for &wcom in proof.witness_commits.iter() {
        //     comms.push(wcom);
        //     points.push(zero_check_point.clone());
        // }

        // // selector_poly(zero_check_point)
        // for &com in vk.selector_commitments.iter() {
        //     comms.push(com);
        //     points.push(zero_check_point.clone());
        // }

        // // - 4.4. public input consistency checks
        // //   - pi_poly(r_pi) where r_pi is sampled from transcript
        // let r_pi = transcript.get_and_append_challenge_vectors(b"r_pi", ell)?;

        // // check public evaluation
        // let pi_step = start_timer!(|| "check public evaluation");
        // let pi_poly = DenseMultilinearExtension::from_evaluations_slice(ell, pub_input);
        // let expect_pi_eval = evaluate_opt(&pi_poly, &r_pi[..]);
        // if expect_pi_eval != *pi_eval {
        //     return Err(HyperPlonkErrors::InvalidProver(format!(
        //         "Public input eval mismatch: got {}, expect {}",
        //         pi_eval, expect_pi_eval,
        //     )));
        // }
        // let r_pi_padded = [r_pi, vec![E::ScalarField::zero(); num_vars - ell]].concat();

        // comms.push(proof.witness_commits[0]);
        // points.push(r_pi_padded);
        // assert_eq!(comms.len(), proof.batch_openings.f_i_eval_at_point_i.len());
        // end_timer!(pi_step);

        // end_timer!(step);
        // let step = start_timer!(|| "PCS batch verify");
        // // check proof
        // let res = PCS::batch_verify(
        //     &vk.pcs_param,
        //     &comms,
        //     &points,
        //     &proof.batch_openings,
        //     &mut transcript,
        // )?;

        // end_timer!(step);
        end_timer!(start);
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hyperplonk::arithmetic::virtual_polynomial::identity_permutation;
    use crate::hyperplonk::full_snark::{
        custom_gate::CustomizedGates, selectors::SelectorColumn, structs::HyperPlonkParams,
        witness::WitnessColumn,
    };
    use crate::read_write::random_permutation;
    use ark_std::rand::rngs::StdRng;
    use ark_std::rand::SeedableRng;
    // use ark_bls12_381::Bls12_381;
    use ark_std::test_rng;
    use ark_test_curves::bls12_381::Fr;
    // use subroutines::pcs::prelude::MultilinearKzgPCS;

    #[test]
    fn test_hyperplonk_e2e() -> Result<(), HyperPlonkErrors> {
        // Example:
        //     q_L(X) * W_1(X)^5 - W_2(X) = 0
        // is represented as
        // vec![
        //     ( 1,    Some(id_qL),    vec![id_W1, id_W1, id_W1, id_W1, id_W1]),
        //     (-1,    None,           vec![id_W2])
        // ]
        //
        // 4 public input
        // 1 selector,
        // 2 witnesses,
        // 2 variables for MLE,
        // 4 wires,
        let gates = CustomizedGates {
            gates: vec![(1, Some(0), vec![0, 0, 0, 0, 0]), (-1, None, vec![1])],
        };
        test_hyperplonk_helper::<Fr>(gates)
    }

    fn test_hyperplonk_helper<F: PrimeField>(
        gate_func: CustomizedGates,
    ) -> Result<(), HyperPlonkErrors> {
        {
            let seed = [
                1, 0, 0, 0, 23, 0, 0, 0, 200, 1, 0, 0, 210, 30, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0,
            ];
            let mut rng = StdRng::from_seed(seed);
            // let pcs_srs = MultilinearKzgPCS::<E>::gen_srs_for_testing(&mut rng, 16)?;

            let num_constraints = 4;
            let num_pub_input = 4;
            let nv = log2(num_constraints) as usize;
            let num_witnesses = 2;

            // generate index
            let params = HyperPlonkParams {
                num_constraints,
                num_pub_input,
                gate_func: gate_func.clone(),
            };
            let permutation = identity_permutation(nv, num_witnesses);
            let permutation_index = identity_permutation(nv, num_witnesses);
            let q1 = SelectorColumn(vec![F::one(), F::one(), F::one(), F::one()]);
            let index = HyperPlonkIndex {
                params: params.clone(),
                permutation,
                permutation_index,
                selectors: vec![q1],
            };

            // generate pk and vks
            let (pk, vk) = <PolyIOP<F> as HyperPlonkSNARK<F>>::preprocess(&index)?;

            // w1 := [1, 1, 2, 3]
            let w1 = WitnessColumn(vec![F::one(), F::one(), F::from(2u128), F::from(3u128)]);
            // w2 := [1^5, 1^5, 2^5, 3^5]
            let w2 = WitnessColumn(vec![F::one(), F::one(), F::from(32u128), F::from(243u128)]);
            // public input = w1
            let pi = w1.clone();

            // generate a proof and verify
            let proof =
                <PolyIOP<F> as HyperPlonkSNARK<F>>::prove(&pk, &pi.0, &[w1.clone(), w2.clone()])?;

            let _verify = <PolyIOP<F> as HyperPlonkSNARK<F>>::verify(&vk, &pi.0, &proof)?;
        }

        {
            // bad path 1: wrong permutation
            let seed = [
                1, 0, 0, 0, 23, 0, 0, 0, 200, 1, 0, 0, 210, 30, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0,
            ];
            let mut rng = StdRng::from_seed(seed);
            // let pcs_srs = MultilinearKzgPCS::<E>::gen_srs_for_testing(&mut rng, 16)?;

            let num_constraints = 4;
            let num_pub_input = 4;
            let nv = log2(num_constraints) as usize;
            let num_witnesses = 2;

            // generate index
            let params = HyperPlonkParams {
                num_constraints,
                num_pub_input,
                gate_func,
            };

            // let permutation = identity_permutation(nv, num_witnesses);
            let rand_perm: Vec<F> = random_permutation(nv, num_witnesses, &mut rng);

            let permutation_index = identity_permutation(nv, num_witnesses);
            let q1 = SelectorColumn(vec![F::one(), F::one(), F::one(), F::one()]);
            let bad_index = HyperPlonkIndex {
                params,
                permutation: rand_perm,
                permutation_index,
                selectors: vec![q1],
            };

            // generate pk and vks
            let (pk, bad_vk) = <PolyIOP<F> as HyperPlonkSNARK<F>>::preprocess(&bad_index)?;

            // w1 := [1, 1, 2, 3]
            let w1 = WitnessColumn(vec![F::one(), F::one(), F::from(2u128), F::from(3u128)]);
            // w2 := [1^5, 1^5, 2^5, 3^5]
            let w2 = WitnessColumn(vec![F::one(), F::one(), F::from(32u128), F::from(243u128)]);
            // public input = w1
            let pi = w1.clone();

            // generate a proof and verify
            let proof =
                <PolyIOP<F> as HyperPlonkSNARK<F>>::prove(&pk, &pi.0, &[w1.clone(), w2.clone()])?;

            assert!(<PolyIOP<F> as HyperPlonkSNARK<F>>::verify(&bad_vk, &pi.0, &proof,).is_err());
        }

        Ok(())
    }
}
