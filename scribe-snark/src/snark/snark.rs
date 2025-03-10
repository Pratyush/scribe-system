use crate::pc::pst13::batching::BatchProof;
use crate::pc::structs::Commitment;
use crate::pc::PCScheme;
use crate::snark::utils::PCAccumulator;
use mle::{util::gen_eval_point, virtual_polynomial::VPAuxInfo, MLE};

use crate::piop::perm_check::PermutationCheck;
use crate::piop::prelude::ZeroCheck;
use crate::snark::{
    errors::ScribeErrors,
    structs::{Index, Proof, ProvingKey, VerifyingKey},
    utils::{build_f, eval_f, eval_perm_gate, prover_sanity_check},
    Scribe,
};
use crate::transcript::IOPTranscript;
use ark_ec::pairing::Pairing;
use scribe_streams::serialize::RawPrimeField;

use ark_std::{end_timer, log2, start_timer, One, Zero};
use rayon::iter::IntoParallelRefIterator;
use rayon::iter::ParallelIterator;

use std::marker::PhantomData;

impl<E, PC> Scribe<E, PC>
where
    E: Pairing,
    E::ScalarField: RawPrimeField,
    PC: PCScheme<
        E,
        Polynomial = MLE<E::ScalarField>,
        Point = Vec<E::ScalarField>,
        Evaluation = E::ScalarField,
        Commitment = Commitment<E>,
        BatchProof = BatchProof<E, PC>,
    >,
{
    pub fn preprocess(
        index: &Index<E::ScalarField>,
        pc_srs: &PC::SRS,
    ) -> Result<(ProvingKey<E, PC>, VerifyingKey<E, PC>), ScribeErrors> {
        let num_vars = index.num_variables();
        let start = start_timer!(|| format!("scribe preprocessing nv = {num_vars}"));

        // extract PC prover and verifier keys from SRS
        let trim_time = start_timer!(|| "trimming PC SRS");
        let (pc_ck, pc_vk) = PC::trim(pc_srs, num_vars)?;
        end_timer!(trim_time);

        // build permutation oracles
        let permutation_oracles = index.permutation.clone();
        let permutation_commit_time = start_timer!(|| "commit permutation oracles");
        let permutation_commitments = permutation_oracles
            .par_iter()
            .map(|poly| PC::commit(&pc_ck, poly))
            .collect::<Result<_, _>>()?;
        end_timer!(permutation_commit_time);

        // commit selector oracles
        let selector_oracles = index.selectors.clone();

        let selector_commit_time = start_timer!(|| "commit selector oracles");
        let selector_commitments = selector_oracles
            .par_iter()
            .map(|poly| PC::commit(&pc_ck, poly))
            .collect::<Result<_, _>>()?;
        end_timer!(selector_commit_time);

        end_timer!(start);

        let vk = VerifyingKey {
            config: index.config.clone(),
            pc_vk,
            selector_commitments,
            perm_commitments: permutation_commitments,
        };
        let pk = ProvingKey::new(
            index.config.clone(),
            permutation_oracles,
            selector_oracles,
            vk.clone(),
            pc_ck,
        );
        Ok((pk, vk))
    }

    /// Generate Scribe SNARK proof.
    ///
    /// Inputs:
    /// - `pk`: circuit proving key
    /// - `pub_input`: online public input of length 2^\ell
    /// - `witness`: witness assignment of length 2^n
    ///
    /// Outputs:
    /// - The Scribe SNARK proof.
    ///
    /// Steps:
    ///
    /// 1. Commit Witness polynomials `w_i(x)` and append commitment to
    ///    transcript
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
    ///    obtain a PermCheckSubClaim.
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
    pub fn prove(
        pk: &ProvingKey<E, PC>,
        pub_input: &[E::ScalarField],
        witnesses: &[MLE<E::ScalarField>],
    ) -> Result<Proof<E, PC>, ScribeErrors> {
        let start = start_timer!(|| format!("scribe proving nv = {}", pk.config().num_variables()));
        let mut transcript = IOPTranscript::<E::ScalarField>::new(b"scribe");

        #[cfg(debug_assertions)]
        prover_sanity_check(&pk.config(), pub_input, witnesses.to_vec())?;

        // witness assignment of length 2^n
        let num_vars = pk.config().num_variables();

        // online public input of length 2^\ell
        let ell = log2(pk.config().num_pub_input) as usize;

        // We use accumulators to store the polynomials and their eval points.
        // They are batch opened at a later stage.
        let mut pcs_acc = PCAccumulator::<E, PC>::new(num_vars);

        // =======================================================================
        // 1. Commit Witness polynomials `w_i(x)` and append commitment to
        // transcript
        // =======================================================================
        let step = start_timer!(|| "commit witnesses");

        #[cfg(target_os = "linux")]
        let witness_commits = witnesses
            .iter()
            .map(|x| PC::commit(&pk.pc_ck, x).unwrap())
            .collect::<Vec<_>>();
        #[cfg(not(target_os = "linux"))]
        let witness_commits = witnesses
            .par_iter()
            .map(|x| PC::commit(&pk.pc_ck, x).unwrap())
            .collect::<Vec<_>>();
        for w_com in witness_commits.iter() {
            transcript.append_serializable_element(b"w", w_com)?;
        }

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
            &pk.config().gate_func,
            pk.config().num_variables(),
            &pk.selector_oracles(),
            witnesses,
        )?;

        let zero_check_proof = <ZeroCheck<E::ScalarField>>::prove(&fx, &mut transcript)?;
        end_timer!(step);

        // =======================================================================
        // 3. Run permutation check on `\{w_i(x)\}` and `permutation_oracle`, and
        // obtain a PermCheckSubClaim.
        // =======================================================================
        let step = start_timer!(|| "Permutation check on w_i(x)");

        let (perm_check_proof, prod_x, frac_poly) = <PermutationCheck<E, PC>>::prove(
            &pk.pc_ck,
            witnesses,
            witnesses,
            &pk.permutation_oracles(),
            &mut transcript,
        )?;
        let perm_check_point = &perm_check_proof.zero_check_proof.point;

        end_timer!(step);

        // =======================================================================
        // 4. Generate evaluations and corresponding proofs
        // - permcheck
        //  1. (deferred) batch opening prod(x) at
        //   - [perm_check_point]
        //   - [perm_check_point[2..n], 0]
        //   - [perm_check_point[2..n], 1]
        //   - [1,...1, 0]
        //  2. (deferred) batch opening frac(x) at
        //   - [perm_check_point]
        //   - [perm_check_point[2..n], 0]
        //   - [perm_check_point[2..n], 1]
        //  3. (deferred) batch opening s_id(x) at
        //   - [perm_check_point]
        //  4. (deferred) batch opening perms(x) at
        //   - [perm_check_point]
        //  5. (deferred) batch opening witness_i(x) at
        //   - [perm_check_point]
        //
        // - zero check evaluations and proofs
        //   - 4.3.1. (deferred) wi_poly(zero_check_point)
        //   - 4.3.2. (deferred) selector_poly(zero_check_point)
        //
        // - 4.4. (deferred) public input consistency checks
        //   - pi_poly(r_pi) where r_pi is sampled from transcript
        // =======================================================================

        let step = start_timer!(|| "opening and evaluations");

        // (perm_check_point[2..n], 0)
        let perm_check_point_0 = [
            &[E::ScalarField::zero()],
            &perm_check_point[0..num_vars - 1],
        ]
        .concat();
        // (perm_check_point[2..n], 1)
        let perm_check_point_1 =
            [&[E::ScalarField::one()], &perm_check_point[0..num_vars - 1]].concat();
        // (1, ..., 1, 0)
        let prod_final_query_point = [
            vec![E::ScalarField::zero()],
            vec![E::ScalarField::one(); num_vars - 1],
        ]
        .concat();

        // prod(x)'s points
        // note that the polynomial inputs aren't dified or consumed by pc accumulator
        // copies are used because their originals are already folded in sum checks
        pcs_acc.insert_poly_and_points(&prod_x, &perm_check_proof.prod_x_comm, perm_check_point);
        pcs_acc.insert_poly_and_points(&prod_x, &perm_check_proof.prod_x_comm, &perm_check_point_0);
        pcs_acc.insert_poly_and_points(&prod_x, &perm_check_proof.prod_x_comm, &perm_check_point_1);
        pcs_acc.insert_poly_and_points(
            &prod_x,
            &perm_check_proof.prod_x_comm,
            &prod_final_query_point,
        );

        // frac(x)'s points
        pcs_acc.insert_poly_and_points(&frac_poly, &perm_check_proof.frac_comm, perm_check_point);
        pcs_acc.insert_poly_and_points(
            &frac_poly,
            &perm_check_proof.frac_comm,
            &perm_check_point_0,
        );
        pcs_acc.insert_poly_and_points(
            &frac_poly,
            &perm_check_proof.frac_comm,
            &perm_check_point_1,
        );

        // perms(x)'s points
        for (perm, pcom) in pk
            .permutation_oracles()
            .iter()
            .zip(&pk.vk().perm_commitments)
        {
            pcs_acc.insert_poly_and_points(perm, pcom, perm_check_point);
        }

        // witnesses' points
        // TODO: refactor so it remains correct even if the order changed
        for (wpoly, wcom) in witnesses.iter().zip(witness_commits.iter()) {
            pcs_acc.insert_poly_and_points(wpoly, wcom, perm_check_point);
        }
        for (wpoly, wcom) in witnesses.iter().zip(witness_commits.iter()) {
            pcs_acc.insert_poly_and_points(wpoly, wcom, &zero_check_proof.point);
        }

        //   - 4.3.2. (deferred) selector_poly(zero_check_point)
        pk.selector_oracles()
            .iter()
            .zip(&pk.vk().selector_commitments)
            .for_each(|(poly, com)| {
                pcs_acc.insert_poly_and_points(poly, com, &zero_check_proof.point)
            });

        // - 4.4. public input consistency checks
        //   - pi_poly(r_pi) where r_pi is sampled from transcript
        let r_pi = transcript.get_and_append_challenge_vectors(b"r_pi", ell)?;
        // padded with zeros
        let r_pi_padded = [r_pi, vec![E::ScalarField::zero(); num_vars - ell]].concat();
        // Evaluate witness_poly[0] at r_pi||0s which is equal to public_input evaluated
        // at r_pi. Assumes that public_input is a power of 2
        pcs_acc.insert_poly_and_points(&witnesses[0], &witness_commits[0], &r_pi_padded);
        end_timer!(step);

        // =======================================================================
        // 5. deferred batch opening
        // =======================================================================

        let step = start_timer!(|| "deferred batch openings");

        // note that these opening create a rlc of the polynomials in the accumulator
        // so the original polynomials (copies) aren't folded
        // that's why we use for example witnesses rather than witnesses_copy for calculating evaluations
        let batch_openings = pcs_acc.multi_open(&pk.pc_ck, &mut transcript)?;
        end_timer!(step);

        end_timer!(start);

        Ok(Proof {
            // PC commit for witnesses
            witness_commits,
            // batch_openings,
            batch_openings,
            // =======================================================================
            // IOP proofs
            // =======================================================================
            // the custom gate zerocheck proof
            zero_check_proof,
            // the permutation check proof for copy constraints
            perm_check_proof,
        })
    }

    /// Verify the Scribe proof.
    ///
    /// Inputs:
    /// - `vk`: verification key
    /// - `pub_input`: online public input
    /// - `proof`: Scribe SNARK proof
    ///
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
    pub fn verify(
        vk: &VerifyingKey<E, PC>,
        pub_input: &[E::ScalarField],
        proof: &Proof<E, PC>,
    ) -> Result<bool, ScribeErrors> {
        let start = start_timer!(|| "scribe verification");

        let mut transcript = IOPTranscript::<E::ScalarField>::new(b"scribe");

        let num_selectors = vk.config.num_selector_columns();
        let num_witnesses = vk.config.num_witness_columns();
        let num_vars = vk.config.num_variables();

        //  online public input of length 2^\ell
        let ell = log2(vk.config.num_pub_input) as usize;

        // =======================================================================
        // 0. sanity checks
        // =======================================================================
        // public input length
        if pub_input.len() != vk.config.num_pub_input {
            return Err(ScribeErrors::InvalidProver(format!(
                "Public input length is not correct: got {}, expect {}",
                pub_input.len(),
                1 << ell
            )));
        }

        // Extract evaluations from openings
        let prod_evals = &proof.batch_openings.f_i_eval_at_point_i[0..4];
        let frac_evals = &proof.batch_openings.f_i_eval_at_point_i[4..7];
        let perm_evals = &proof.batch_openings.f_i_eval_at_point_i[7..7 + num_witnesses];
        let witness_perm_evals =
            &proof.batch_openings.f_i_eval_at_point_i[7 + num_witnesses..7 + 2 * num_witnesses];
        let witness_gate_evals =
            &proof.batch_openings.f_i_eval_at_point_i[7 + 2 * num_witnesses..7 + 3 * num_witnesses];
        let selector_evals = &proof.batch_openings.f_i_eval_at_point_i
            [7 + 3 * num_witnesses..7 + 3 * num_witnesses + num_selectors];
        let pi_eval = proof.batch_openings.f_i_eval_at_point_i.last().unwrap();

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
        let zero_check_aux_info = VPAuxInfo::<E::ScalarField> {
            max_degree: vk.config.gate_func.degree(),
            num_variables: num_vars,
            phantom: PhantomData::default(),
        };
        // push witness to transcript
        for w_com in proof.witness_commits.iter() {
            transcript.append_serializable_element(b"w", w_com)?;
        }

        let zero_check_sub_claim = <ZeroCheck<E::ScalarField>>::verify(
            &proof.zero_check_proof,
            &zero_check_aux_info,
            &mut transcript,
        )?;

        let zero_check_point = zero_check_sub_claim.point;

        // check zero check subclaim
        let f_eval = eval_f(&vk.config.gate_func, selector_evals, witness_gate_evals)?;
        if f_eval != zero_check_sub_claim.expected_evaluation {
            return Err(ScribeErrors::InvalidProof(
                "zero check evaluation failed".to_string(),
            ));
        }

        end_timer!(step);
        // =======================================================================
        // 2. Verify perm_check_proof on `\{w_i(x)\}` and `permutation_oracle`
        // =======================================================================
        let step = start_timer!(|| "verify permutation check");

        // Zero check and perm check have different AuxInfo
        let perm_check_aux_info = VPAuxInfo::<E::ScalarField> {
            // Prod(x) has a max degree of witnesses.len() + 1
            max_degree: proof.witness_commits.len() + 1,
            num_variables: num_vars,
            phantom: PhantomData,
        };
        let perm_check_sub_claim = <PermutationCheck<E, PC>>::verify(
            &proof.perm_check_proof,
            &perm_check_aux_info,
            &mut transcript,
        )?;

        let perm_check_point = perm_check_sub_claim
            .product_check_sub_claim
            .zero_check_sub_claim
            .point;

        let alpha = perm_check_sub_claim.product_check_sub_claim.alpha;
        let (beta, gamma) = perm_check_sub_claim.challenges;

        let mut id_evals = vec![];
        for i in 0..num_witnesses {
            let ith_point = gen_eval_point(i, log2(num_witnesses) as usize, &perm_check_point[..]);
            id_evals.push(vk.config.eval_id_oracle(&ith_point[..])?);
        }

        // check evaluation subclaim
        let perm_gate_eval = eval_perm_gate(
            prod_evals,
            frac_evals,
            witness_perm_evals,
            &id_evals[..],
            perm_evals,
            alpha,
            beta,
            gamma,
            *perm_check_point.last().unwrap(),
        )?;
        if perm_gate_eval
            != perm_check_sub_claim
                .product_check_sub_claim
                .zero_check_sub_claim
                .expected_evaluation
        {
            return Err(ScribeErrors::InvalidVerifier(
                "evaluation failed".to_string(),
            ));
        }

        end_timer!(step);
        // =======================================================================
        // 3. Verify the opening against the commitment
        // =======================================================================
        let step = start_timer!(|| "assemble commitments");

        // generate evaluation points and commitments
        let mut comms = vec![];
        let mut points = vec![];

        let perm_check_point_0 = [
            &[E::ScalarField::zero()],
            &perm_check_point[0..num_vars - 1],
        ]
        .concat();
        let perm_check_point_1 =
            [&[E::ScalarField::one()], &perm_check_point[0..num_vars - 1]].concat();
        let prod_final_query_point = [
            vec![E::ScalarField::zero()],
            vec![E::ScalarField::one(); num_vars - 1],
        ]
        .concat();

        // prod(x)'s points
        comms.push(proof.perm_check_proof.prod_x_comm);
        comms.push(proof.perm_check_proof.prod_x_comm);
        comms.push(proof.perm_check_proof.prod_x_comm);
        comms.push(proof.perm_check_proof.prod_x_comm);
        points.push(perm_check_point.clone());
        points.push(perm_check_point_0.clone());
        points.push(perm_check_point_1.clone());
        points.push(prod_final_query_point);
        // frac(x)'s points
        comms.push(proof.perm_check_proof.frac_comm);
        comms.push(proof.perm_check_proof.frac_comm);
        comms.push(proof.perm_check_proof.frac_comm);
        points.push(perm_check_point.clone());
        points.push(perm_check_point_0);
        points.push(perm_check_point_1);

        // perms' points
        for &pcom in vk.perm_commitments.iter() {
            comms.push(pcom);
            points.push(perm_check_point.clone());
        }

        // witnesses' points
        // TODO: merge points
        for &wcom in proof.witness_commits.iter() {
            comms.push(wcom);
            points.push(perm_check_point.clone());
        }
        for &wcom in proof.witness_commits.iter() {
            comms.push(wcom);
            points.push(zero_check_point.clone());
        }

        // selector_poly(zero_check_point)
        for &com in vk.selector_commitments.iter() {
            comms.push(com);
            points.push(zero_check_point.clone());
        }

        // - 4.4. public input consistency checks
        //   - pi_poly(r_pi) where r_pi is sampled from transcript
        let r_pi = transcript.get_and_append_challenge_vectors(b"r_pi", ell)?;

        // check public evaluation
        let pi_step = start_timer!(|| "check public evaluation");
        let pi_poly = MLE::from_evals_vec(pub_input.to_vec(), ell);
        let expect_pi_eval = pi_poly.evaluate(&r_pi[..]).unwrap();
        if expect_pi_eval != *pi_eval {
            return Err(ScribeErrors::InvalidProver(format!(
                "Public input eval mismatch: got {}, expect {}",
                pi_eval, expect_pi_eval,
            )));
        }
        let r_pi_padded = [r_pi, vec![E::ScalarField::zero(); num_vars - ell]].concat();

        comms.push(proof.witness_commits[0]);
        points.push(r_pi_padded);
        assert_eq!(comms.len(), proof.batch_openings.f_i_eval_at_point_i.len());
        end_timer!(pi_step);

        end_timer!(step);
        let step = start_timer!(|| "PC batch verify");
        // check proof
        let res = PC::batch_verify(
            &vk.pc_vk,
            &comms,
            &points,
            &proof.batch_openings,
            &mut transcript,
        )?;

        end_timer!(step);
        end_timer!(start);
        Ok(res)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pc::pst13::PST13;

    use crate::snark::{custom_gate::CustomizedGates, structs::ScribeConfig};
    use scribe_streams::serialize::RawAffine;

    use ark_bls12_381::Bls12_381;
    use ark_std::rand::rngs::StdRng;
    use ark_std::rand::SeedableRng;
    use ark_std::One;

    #[test]
    fn test_scribe_e2e() -> Result<(), ScribeErrors> {
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
            gates: vec![
                (1.into(), Some(0), vec![0, 0, 0, 0, 0]),
                ((-1).into(), None, vec![1]),
            ],
            // gates: vec![(1, Some(0), vec![0]), (-1, None, vec![1])],
        };
        test_scribe_helper::<Bls12_381>(gates)
    }

    fn test_scribe_helper<E: Pairing>(gate_func: CustomizedGates) -> Result<(), ScribeErrors>
    where
        E::ScalarField: RawPrimeField,
        E::G1Affine: RawAffine,
    {
        {
            let seed = [
                1, 0, 0, 0, 23, 0, 0, 0, 200, 1, 0, 0, 210, 30, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0,
            ];
            let mut rng = StdRng::from_seed(seed);
            let pcs_srs = PST13::<E>::gen_srs_for_testing(&mut rng, 10)?;
            println!("Generated Test SRS");

            let num_constraints = 4;
            let num_pub_input = 4;
            let _nv = log2(num_constraints) as usize;
            let _num_witnesses = 2;

            // generate index
            let params = ScribeConfig {
                num_constraints,
                num_pub_input,
                gate_func: gate_func.clone(),
            };
            // let permutation = identity_permutation_mles(nv, num_witnesses);
            let permutation = vec![
                MLE::from_evals_vec(
                    vec![
                        E::ScalarField::from(1u64),
                        E::ScalarField::from(0u64),
                        E::ScalarField::from(2u64),
                        E::ScalarField::from(3u64),
                    ],
                    2,
                ),
                MLE::from_evals_vec(
                    vec![
                        E::ScalarField::from(5u64),
                        E::ScalarField::from(4u64),
                        E::ScalarField::from(6u64),
                        E::ScalarField::from(7u64),
                    ],
                    2,
                ),
            ];
            println!("Generated Permutation MLEs");
            let q1 = MLE::from_evals_vec(
                vec![
                    E::ScalarField::one(),
                    E::ScalarField::one(),
                    E::ScalarField::one(),
                    E::ScalarField::one(),
                ],
                2,
            );
            println!("Generated Selectors");
            let index = Index {
                config: params.clone(),
                permutation,
                selectors: vec![q1],
            };

            // generate pk and vks
            let (pk, vk) = <Scribe<E, PST13<E>>>::preprocess(&index, &pcs_srs)?;
            println!("Finished preprocessing");

            // w1 := [1, 1, 2, 3]
            let w1 = MLE::from_evals_vec(
                vec![
                    E::ScalarField::one(),
                    E::ScalarField::one(),
                    E::ScalarField::from(2u128),
                    E::ScalarField::from(3u128),
                ],
                2,
            );
            // // w2 := [1, 1, 2, 3]
            // let w2 = Arc::new(Mutex::new(DenseMLPolyStream::from_evaluations_vec(
            //     2,
            //     vec![E::ScalarField::one(), E::ScalarField::one(), E::ScalarField::from(2u128), E::ScalarField::from(3u128)],
            //     None,
            //     None,
            // )));
            // w2 := [1^5, 1^5, 2^5, 3^5]
            let w2 = MLE::from_evals_vec(
                vec![
                    E::ScalarField::one(),
                    E::ScalarField::one(),
                    E::ScalarField::from(32u128),
                    E::ScalarField::from(243u128),
                ],
                2,
            );
            // public input = w1
            let pi = vec![
                E::ScalarField::one(),
                E::ScalarField::one(),
                E::ScalarField::from(2u128),
                E::ScalarField::from(3u128),
            ];

            // generate a proof and verify
            let proof = <Scribe<E, PST13<E>>>::prove(&pk, &pi, &[w1, w2])?;

            let _verify = <Scribe<E, PST13<E>>>::verify(&vk, &pi, &proof)?;
            println!("Scribe proof verified: {_verify}");

            assert!(_verify);
        }

        {
            // bad path 1: wrong permutation
            let seed = [
                1, 0, 0, 0, 23, 0, 0, 0, 200, 1, 0, 0, 210, 30, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0,
            ];
            let mut rng = StdRng::from_seed(seed);
            let pcs_srs = PST13::<E>::gen_srs_for_testing(&mut rng, 10)?;

            let num_constraints = 4;
            let num_pub_input = 4;
            let _nv = log2(num_constraints) as usize;
            let _num_witnesses = 2;

            // generate index
            let params = ScribeConfig {
                num_constraints,
                num_pub_input,
                gate_func,
            };

            // let permutation = identity_permutation(nv, num_witnesses);
            let rand_perm = vec![
                MLE::from_evals_vec(
                    vec![
                        E::ScalarField::from(1u64),
                        E::ScalarField::from(3u64),
                        E::ScalarField::from(6u64),
                        E::ScalarField::from(7u64),
                    ],
                    2,
                ),
                MLE::from_evals_vec(
                    vec![
                        E::ScalarField::from(2u64),
                        E::ScalarField::from(5u64),
                        E::ScalarField::from(0u64),
                        E::ScalarField::from(4u64),
                    ],
                    2,
                ),
            ];

            let q1 = MLE::from_evals_vec(
                vec![
                    E::ScalarField::one(),
                    E::ScalarField::one(),
                    E::ScalarField::one(),
                    E::ScalarField::one(),
                ],
                2,
            );
            let bad_index = Index {
                config: params,
                permutation: rand_perm,
                selectors: vec![q1],
            };

            // generate pk and vks
            let (pk, bad_vk) = <Scribe<E, PST13<E>>>::preprocess(&bad_index, &pcs_srs)?;

            // w1 := [1, 1, 2, 3]
            let w1 = MLE::from_evals_vec(
                vec![
                    E::ScalarField::one(),
                    E::ScalarField::one(),
                    E::ScalarField::from(2u128),
                    E::ScalarField::from(3u128),
                ],
                2,
            );
            // w2 := [1^5, 1^5, 2^5, 3^5]
            let w2 = MLE::from_evals_vec(
                vec![
                    E::ScalarField::one(),
                    E::ScalarField::one(),
                    E::ScalarField::from(32u128),
                    E::ScalarField::from(243u128),
                ],
                2,
            );
            // public input = w1
            let pi = vec![
                E::ScalarField::one(),
                E::ScalarField::one(),
                E::ScalarField::from(2u128),
                E::ScalarField::from(3u128),
            ];

            // generate a proof and verify
            let proof = <Scribe<E, PST13<E>>>::prove(&pk, &pi, &[w1, w2])?;

            assert!(<Scribe<E, PST13<E>>>::verify(&bad_vk, &pi, &proof,).is_err());
        }

        Ok(())
    }
}
