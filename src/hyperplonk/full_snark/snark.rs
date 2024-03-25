use crate::hyperplonk::arithmetic::virtual_polynomial::{eq_eval, VPAuxInfo};
use crate::hyperplonk::full_snark::utils::PcsAccumulator;
use crate::hyperplonk::pcs::multilinear_kzg::batching::BatchProofSinglePoint;
use crate::hyperplonk::pcs::prelude::Commitment;
use crate::hyperplonk::pcs::PolynomialCommitmentScheme;
use crate::hyperplonk::poly_iop::perm_check::util::compute_frac_poly_plonk;
use crate::hyperplonk::poly_iop::prelude::SumCheck;
use crate::hyperplonk::poly_iop::PolyIOP;
use crate::hyperplonk::transcript::IOPTranscript;
use crate::read_write::copy_mle;
use crate::{
    hyperplonk::full_snark::{
        errors::HyperPlonkErrors,
        structs::{HyperPlonkIndex, HyperPlonkProof, HyperPlonkProvingKey, HyperPlonkVerifyingKey},
        utils::{build_f, eval_f, prover_sanity_check},
        HyperPlonkSNARK,
    },
    read_write::DenseMLPolyStream,
};
use ark_ec::pairing::Pairing;
use ark_ec::CurveGroup;
use ark_ff::Field;
use ark_std::{end_timer, log2, start_timer, Zero};
use rayon::iter::IntoParallelRefIterator;
#[cfg(feature = "parallel")]
use rayon::iter::ParallelIterator;
use std::cmp::max;
use std::{
    marker::PhantomData,
    sync::{Arc, Mutex},
};

impl<E, PCS> HyperPlonkSNARK<E, PCS> for PolyIOP<E::ScalarField>
where
    E: Pairing,
    PCS: PolynomialCommitmentScheme<
        E,
        Polynomial = Arc<Mutex<DenseMLPolyStream<E::ScalarField>>>,
        Point = Vec<E::ScalarField>,
        Evaluation = E::ScalarField,
        Commitment = Commitment<E>,
    >,
{
    type Index = HyperPlonkIndex<E::ScalarField>;
    type ProvingKey = HyperPlonkProvingKey<E, PCS>;
    type VerifyingKey = HyperPlonkVerifyingKey<E, PCS>;
    type Proof = HyperPlonkProof<E, Self, PCS>;

    fn preprocess(
        index: &Self::Index,
        pcs_srs: &PCS::SRS,
    ) -> Result<(Self::ProvingKey, Self::VerifyingKey), HyperPlonkErrors> {
        let num_vars = index.num_variables();
        let supported_ml_degree = num_vars;

        let start = start_timer!(|| format!("hyperplonk preprocessing nv = {}", num_vars));

        // extract PCS prover and verifier keys from SRS
        let (pcs_prover_param, pcs_verifier_param) =
            PCS::trim(pcs_srs, None, Some(supported_ml_degree))?;

        // assert that index.permutation and index.permutation_index have the same length
        // TODO: loop over all index.permutation and index.permutation_index and check that they have the same length
        if index.permutation[0].lock().unwrap().num_vars
            != index.permutation_index[0].lock().unwrap().num_vars
        {
            return Err(HyperPlonkErrors::InvalidParameters(
                "permutation and permutation_index have different lengths".to_string(),
            ));
        }

        // commit permutation and permutation index oracles
        let permutation_oracles = (index.permutation.clone(), index.permutation_index.clone());
        let permutation_commitments = (
            permutation_oracles
                .0
                .par_iter()
                .map(|poly| PCS::commit(&pcs_prover_param, poly))
                .collect::<Result<Vec<_>, _>>()?,
            permutation_oracles
                .1
                .par_iter()
                .map(|poly| PCS::commit(&pcs_prover_param, poly))
                .collect::<Result<Vec<_>, _>>()?,
        );

        // commit selector oracles
        let selector_oracles = index.selectors.clone();

        let selector_commitments = selector_oracles
            .par_iter()
            .map(|poly| PCS::commit(&pcs_prover_param, poly))
            .collect::<Result<Vec<_>, _>>()?;

        end_timer!(start);

        Ok((
            Self::ProvingKey {
                params: index.params.clone(),
                permutation_oracles,
                permutation_commitments: permutation_commitments.clone(),
                selector_oracles,
                selector_commitments: selector_commitments.clone(),
                pcs_param: pcs_prover_param,
            },
            Self::VerifyingKey {
                params: index.params.clone(),
                pcs_param: pcs_verifier_param,
                selector_commitments,
                perm_commitments: permutation_commitments,
            },
        ))
    }

    fn prove(
        pk: &Self::ProvingKey,
        pub_input: &[E::ScalarField],
        witnesses: Vec<Arc<Mutex<DenseMLPolyStream<E::ScalarField>>>>,
    ) -> Result<Self::Proof, HyperPlonkErrors> {
        // copy inputs for opening, should not be a part of proving time (i put it here as i don't want to change the ProvingKey to store the copies as well)
        let witnesses_copy = witnesses
            .iter()
            .map(|x| copy_mle(x, None, None))
            .collect::<Vec<Arc<Mutex<DenseMLPolyStream<E::ScalarField>>>>>();
        let selector_oracles_copy = pk
            .selector_oracles
            .iter()
            .map(|x| copy_mle(x, None, None))
            .collect::<Vec<Arc<Mutex<DenseMLPolyStream<E::ScalarField>>>>>();
        let perm_oracles_copy = pk
            .permutation_oracles
            .0
            .iter()
            .map(|x| copy_mle(x, None, None))
            .collect::<Vec<Arc<Mutex<DenseMLPolyStream<E::ScalarField>>>>>();
        let perm_index_oracles_copy = pk
            .permutation_oracles
            .1
            .iter()
            .map(|x| copy_mle(x, None, None))
            .collect::<Vec<Arc<Mutex<DenseMLPolyStream<E::ScalarField>>>>>();

        let start =
            start_timer!(|| format!("hyperplonk proving nv = {}", pk.params.num_variables()));
        let mut transcript = IOPTranscript::<E::ScalarField>::new(b"hyperplonk");

        prover_sanity_check(&pk.params, pub_input, witnesses.clone())?;

        // witness assignment of length 2^n
        let num_vars = pk.params.num_variables();

        // online public input of length 2^\ell
        let ell = log2(pk.params.num_pub_input) as usize;

        // We use accumulators to store the polynomials and their eval points.
        // They are batch opened at a later stage.
        let mut pcs_acc = PcsAccumulator::<E, PCS>::new(num_vars);

        // =======================================================================
        // 1. Commit Witness polynomials `w_i(x)` and append commitment to
        // transcript
        // =======================================================================
        let step = start_timer!(|| "commit witnesses");

        let witness_commits = witnesses
            .par_iter()
            .map(|x| PCS::commit(&pk.pcs_param, x).unwrap())
            .collect::<Vec<_>>();
        for w_com in witness_commits.iter() {
            transcript.append_serializable_element(b"w", w_com)?;
        }

        end_timer!(step);
        // =======================================================================
        // 2 Run batched sum check on:
        // gate identity zero check
        // permutation zero checks
        // permutation sum check
        // =======================================================================
        let step = start_timer!(|| "Batch sum check");

        // gate identity zero check but without multiplying eq_x_r yet
        let mut batch_sum_check = build_f(
            &pk.params.gate_func,
            pk.params.num_variables(),
            &pk.selector_oracles,
            &witnesses,
        )
        .unwrap();

        let perm_identity_alpha = transcript.get_and_append_challenge(b"alpha")?;
        #[cfg(debug_assertions)]
        println!("prover alpha: {}", perm_identity_alpha);

        let perm_identity_gamma = transcript.get_and_append_challenge(b"gamma")?;
        #[cfg(debug_assertions)]
        println!("prover gamma: {}", perm_identity_gamma);

        let (h_ps, h_qs) = compute_frac_poly_plonk(
            witnesses.clone(),
            pk.permutation_oracles.0.clone(),
            pk.permutation_oracles.1.clone(),
            perm_identity_alpha,
            perm_identity_gamma,
        )
        .unwrap();

        // copy inputs for opening (i put it here as i don't want to change the ProvingKey to store the copies as well)
        let h_ps_copy = h_ps
            .iter()
            .map(|x| copy_mle(x, None, None))
            .collect::<Vec<Arc<Mutex<DenseMLPolyStream<E::ScalarField>>>>>();
        let h_qs_copy = h_qs
            .iter()
            .map(|x| copy_mle(x, None, None))
            .collect::<Vec<Arc<Mutex<DenseMLPolyStream<E::ScalarField>>>>>();

        // commit hp's and hq's in loops
        let h_p_comm = h_ps
            .iter()
            .map(|hp| PCS::commit(&pk.pcs_param, hp))
            .collect::<Result<Vec<_>, _>>()?;
        let h_q_comm = h_qs
            .iter()
            .map(|hq| PCS::commit(&pk.pcs_param, hq))
            .collect::<Result<Vec<_>, _>>()?;

        let batch_zero_check_factor =
            transcript.get_and_append_challenge(b"batch_zero_check_factor")?;
        #[cfg(debug_assertions)]
        println!(
            "prover batch_zero_check_factor: {}",
            batch_zero_check_factor
        );

        // add perm check's batch zero checks but without multiplying eq_x_r yet
        batch_sum_check
            .add_build_perm_check_poly_plonk(
                h_ps.clone(),
                h_qs.clone(),
                witnesses.clone(),
                pk.permutation_oracles.0.clone(),
                pk.permutation_oracles.1.clone(),
                perm_identity_alpha,
                batch_zero_check_factor,
                perm_identity_gamma,
            )
            .unwrap();

        let r = transcript.get_and_append_challenge_vectors(b"0check r", num_vars)?;

        // multiply by eq_x_r for the final batch zero check, which contains gate identity zero check (coeff = 1) and perm check's batch zero checks (coeff = powers of batch_zero_check_factor)
        #[cfg(debug_assertions)]
        println!(
            "max degree before build_f_hat: {}",
            batch_sum_check.aux_info.max_degree
        );

        batch_sum_check = batch_sum_check.build_f_hat(r.as_ref()).unwrap();

        #[cfg(debug_assertions)]
        println!(
            "max degree after build_f_hat: {}",
            batch_sum_check.aux_info.max_degree
        );
        let batch_sum_check_factor =
            transcript.get_and_append_challenge(b"batch_sum_check_factor")?;

        #[cfg(debug_assertions)]
        println!("prover batch_sum_check_factor: {}", batch_sum_check_factor);

        // add perm check's sum check (coeff = batch_sum_check_factor)
        for i in 0..h_ps.len() {
            batch_sum_check
                .add_mle_list([h_ps[i].clone()], batch_sum_check_factor)
                .unwrap();
            batch_sum_check
                .add_mle_list([h_qs[i].clone()], -batch_sum_check_factor)
                .unwrap();
        }

        let sum_check_proof =
            <Self as SumCheck<E::ScalarField>>::prove(&batch_sum_check, &mut transcript)?;

        end_timer!(step);

        let step = start_timer!(|| "opening and evaluations");

        // permutation oracles
        for (perm, pcom) in perm_oracles_copy
            .iter()
            .zip(pk.permutation_commitments.0.iter())
        {
            pcs_acc.insert_poly_and_points(perm, pcom, &sum_check_proof.point);
        }

        // permutation index oracles
        for (perm, pcom) in perm_index_oracles_copy
            .iter()
            .zip(pk.permutation_commitments.1.iter())
        {
            pcs_acc.insert_poly_and_points(perm, pcom, &sum_check_proof.point);
        }

        // selector oracles
        for (sel, scom) in selector_oracles_copy
            .iter()
            .zip(pk.selector_commitments.iter())
        {
            pcs_acc.insert_poly_and_points(sel, scom, &sum_check_proof.point);
        }

        // witness oracles
        for (witness, wcom) in witnesses_copy.iter().zip(witness_commits.iter()) {
            pcs_acc.insert_poly_and_points(witness, wcom, &sum_check_proof.point);
        }

        // h_ps and h_qs
        for (hp, hcom) in h_ps_copy.iter().zip(h_p_comm.iter()) {
            pcs_acc.insert_poly_and_points(hp, hcom, &sum_check_proof.point);
        }

        for (hq, hcom) in h_qs_copy.iter().zip(h_q_comm.iter()) {
            pcs_acc.insert_poly_and_points(hq, hcom, &sum_check_proof.point);
        }

        end_timer!(step);

        let step = start_timer!(|| "deferred batch openings");
        let (opening_proof, opening_rlc_eval) =
            pcs_acc.multi_open_single_point(&pk.pcs_param, &mut transcript)?;

        // get evaluation of all relevant polynomials
        let perm_evals = pk
            .permutation_oracles
            .0
            .iter()
            .map(|poly| {
                poly.lock()
                    .unwrap()
                    .evaluate(std::slice::from_ref(&sum_check_proof.point[num_vars - 1]))
                    .unwrap()
            })
            .collect::<Vec<E::ScalarField>>();
        let perm_index_evals = pk
            .permutation_oracles
            .1
            .iter()
            .map(|poly| {
                poly.lock()
                    .unwrap()
                    .evaluate(std::slice::from_ref(&sum_check_proof.point[num_vars - 1]))
                    .unwrap()
            })
            .collect::<Vec<E::ScalarField>>();
        let selector_evals = pk
            .selector_oracles
            .iter()
            .map(|poly| {
                poly.lock()
                    .unwrap()
                    .evaluate(std::slice::from_ref(&sum_check_proof.point[num_vars - 1]))
                    .unwrap()
            })
            .collect::<Vec<E::ScalarField>>();
        let witness_evals = witnesses
            .iter()
            .map(|poly| {
                poly.lock()
                    .unwrap()
                    .evaluate(std::slice::from_ref(&sum_check_proof.point[num_vars - 1]))
                    .unwrap()
            })
            .collect::<Vec<E::ScalarField>>();
        let hp_evals = h_ps
            .iter()
            .map(|poly| {
                poly.lock()
                    .unwrap()
                    .evaluate(std::slice::from_ref(&sum_check_proof.point[num_vars - 1]))
                    .unwrap()
            })
            .collect::<Vec<E::ScalarField>>();
        let hq_evals = h_qs
            .iter()
            .map(|poly| {
                poly.lock()
                    .unwrap()
                    .evaluate(std::slice::from_ref(&sum_check_proof.point[num_vars - 1]))
                    .unwrap()
            })
            .collect::<Vec<E::ScalarField>>();

        #[cfg(debug_assertions)]
        {
            // print all evaluations
            perm_evals
                .iter()
                .for_each(|eval| println!("perm eval: {}", eval));
            perm_index_evals
                .iter()
                .for_each(|eval| println!("perm index eval: {}", eval));
            selector_evals
                .iter()
                .for_each(|eval| println!("selector eval: {}", eval));
            witness_evals
                .iter()
                .for_each(|eval| println!("witness eval: {}", eval));
            hp_evals
                .iter()
                .for_each(|eval| println!("hp eval: {}", eval));
            hq_evals
                .iter()
                .for_each(|eval| println!("hq eval: {}", eval));
        }

        let opening = BatchProofSinglePoint {
            rlc_eval: opening_rlc_eval,
            proof: opening_proof,
            perm_evals,
            perm_index_evals,
            selector_evals,
            witness_evals,
            hp_evals,
            hq_evals,
        };

        end_timer!(step);

        end_timer!(start);

        Ok(HyperPlonkProof {
            witness_commits,
            opening, // opening and evaluations
            sum_check_proof,
            h_comm: h_p_comm,
            h_prime_comm: h_q_comm,
        })
    }

    fn verify(
        vk: &Self::VerifyingKey,
        pub_input: &[E::ScalarField],
        proof: &Self::Proof,
    ) -> Result<bool, HyperPlonkErrors> {
        let start =
            start_timer!(|| format!("hyperplonk verification nv = {}", vk.params.num_variables()));

        let mut transcript = IOPTranscript::<E::ScalarField>::new(b"hyperplonk");

        let num_vars = vk.params.num_variables();

        //  online public input of length 2^\ell
        let ell = log2(vk.params.num_pub_input) as usize;

        // public input length
        if pub_input.len() != vk.params.num_pub_input {
            return Err(HyperPlonkErrors::InvalidProver(format!(
                "Public input length is not correct: got {}, expect {}",
                pub_input.len(),
                1 << ell
            )));
        }

        // =======================================================================
        // 1. Verify sum check proof
        // =======================================================================
        let step = start_timer!(|| "verify sum check ");
        // auxinfo for sum check
        let sum_check_aux_info = VPAuxInfo::<E::ScalarField> {
            max_degree: max(vk.params.gate_func.degree() + 1, 3), // max of gate identity zero check or permutation check (degree 2 + 1)
            num_variables: num_vars,
            phantom: PhantomData::default(),
        };

        // push witness to transcript
        for w_com in proof.witness_commits.iter() {
            transcript.append_serializable_element(b"w", w_com)?;
        }

        // get randomnesses for building evaluation
        let alpha = transcript.get_and_append_challenge(b"alpha")?;
        #[cfg(debug_assertions)]
        println!("verifier alpha: {}", alpha);

        let gamma = transcript.get_and_append_challenge(b"gamma")?;
        let batch_factor = transcript.get_and_append_challenge(b"batch_zero_check_factor")?;
        #[cfg(debug_assertions)]
        println!("verifier batch_zero_check_factor: {}", batch_factor);

        let r = transcript.get_and_append_challenge_vectors(b"0check r", num_vars)?;
        let batch_sum_check_factor =
            transcript.get_and_append_challenge(b"batch_sum_check_factor")?;
        #[cfg(debug_assertions)]
        println!(
            "verifier batch_sum_check_factor: {}",
            batch_sum_check_factor
        );

        // verify sum check
        let sum_check_sub_claim = <Self as SumCheck<E::ScalarField>>::verify(
            E::ScalarField::ZERO,
            &proof.sum_check_proof,
            &sum_check_aux_info,
            &mut transcript,
        )?;

        // print all sum check sub claim points
        #[cfg(debug_assertions)]
        sum_check_sub_claim
            .point
            .iter()
            .for_each(|point| println!("sum check sub claim point: {}", point));

        // check batch sum check subclaim
        // gate identity zero check
        let mut f_eval = eval_f(
            &vk.params.gate_func,
            &proof.opening.selector_evals,
            &proof.opening.witness_evals,
        )?;
        // print f_eval
        #[cfg(debug_assertions)]
        println!("gate identity eval: {}", f_eval);

        // add permu zero checks
        // get constant poly evaluation for permu zero check
        let mut constant = -batch_factor;
        let mut batch_factor_power = -batch_factor * batch_factor;
        for _ in 0..(proof.opening.hp_evals.len() * 2 - 1) {
            constant += batch_factor_power;
            batch_factor_power *= batch_factor;
        }
        // print constant_eval which is the same as constant mathematically
        #[cfg(debug_assertions)]
        println!("constant eval: {}", constant);
        f_eval += constant;

        let mut batch_factor_lower_power = batch_factor;
        let mut batch_factor_higher_power = batch_factor * batch_factor;

        let hp_evals = proof.opening.hp_evals.clone();
        let hq_evals = proof.opening.hq_evals.clone();

        for i in 0..hp_evals.len() {
            f_eval += hp_evals[i] * proof.opening.witness_evals[i] * batch_factor_lower_power;
            f_eval += hp_evals[i] * proof.opening.perm_evals[i] * batch_factor_lower_power * alpha;
            f_eval += hq_evals[i] * proof.opening.witness_evals[i] * batch_factor_higher_power;
            f_eval +=
                hq_evals[i] * proof.opening.perm_index_evals[i] * batch_factor_higher_power * alpha;
            f_eval += hp_evals[i] * batch_factor_lower_power * gamma;
            f_eval += hq_evals[i] * batch_factor_higher_power * gamma;

            batch_factor_lower_power = batch_factor_lower_power * batch_factor * batch_factor;
            batch_factor_higher_power = batch_factor_higher_power * batch_factor * batch_factor;
        }

        // print f_eval
        #[cfg(debug_assertions)]
        println!("eval after permu zero check: {}", f_eval);

        // multiply by eq_x_r to obtain sum check 1
        let eq_x_r_eval = eq_eval(&sum_check_sub_claim.point, &r).unwrap();
        f_eval *= eq_x_r_eval;

        // print f_eval
        #[cfg(debug_assertions)]
        println!("eval after multiplying by eq_x_r: {}", f_eval);

        // add permu sum check as sum check 2
        hp_evals
            .iter()
            .for_each(|hp_eval| f_eval = f_eval + *hp_eval * batch_sum_check_factor);
        // println!("eval after adding batch sum check: {}", f_eval);
        hq_evals
            .iter()
            .for_each(|hq_eval| f_eval = f_eval - *hq_eval * batch_sum_check_factor);
        #[cfg(debug_assertions)]
        println!("eval after adding batch sum check: {}", f_eval);

        if f_eval != sum_check_sub_claim.expected_evaluation {
            return Err(HyperPlonkErrors::InvalidProof(format!(
                "sum check evaluation failed, verifier calculated eval: {}, expected: {}",
                f_eval, sum_check_sub_claim.expected_evaluation
            )));
        }

        end_timer!(step);

        // =======================================================================
        // 2. Verify the opening against the commitment
        // =======================================================================
        let step = start_timer!(|| "verify opening");

        let alpha = transcript.get_and_append_challenge(b"opening rlc").unwrap();
        // create rlc of evaluations
        let mut evaluations: Vec<E::ScalarField> = Vec::new();
        evaluations.extend(proof.opening.perm_evals.iter());
        evaluations.extend(proof.opening.perm_index_evals.iter());
        evaluations.extend(proof.opening.selector_evals.iter());
        evaluations.extend(proof.opening.witness_evals.iter());
        evaluations.extend(proof.opening.hp_evals.iter());
        evaluations.extend(proof.opening.hq_evals.iter());
        let alphas = (0..evaluations.len())
            .map(|i| alpha.pow(&[i as u64]))
            .collect::<Vec<E::ScalarField>>();
        let rlc_eval_calc = evaluations
            .iter()
            .zip(alphas.iter())
            .map(|(eval, alpha)| *eval * *alpha)
            .fold(E::ScalarField::zero(), |acc, x| acc + x);

        // assert that calculated rlc_eval matches the one in the proof
        // just a sanity check, should only use the calculated one in the future
        if rlc_eval_calc != proof.opening.rlc_eval {
            return Err(HyperPlonkErrors::InvalidProof(
                "opening rlc evaluation failed".to_string(),
            ));
        }

        // get rlc of commitments
        let mut comms: Vec<PCS::Commitment> = vec![];
        comms.extend(vk.perm_commitments.0.iter());
        comms.extend(vk.perm_commitments.1.iter());
        comms.extend(vk.selector_commitments.iter());
        comms.extend(proof.witness_commits.iter());
        comms.extend(proof.h_comm.iter());
        comms.extend(proof.h_prime_comm.iter());
        let rlc_comms = comms
            .iter()
            .zip(alphas.iter())
            .map(|(comm, alpha)| comm.0 * *alpha)
            .fold(E::G1::zero(), |acc, x| acc + x);

        // verify the opening against the commitment
        let res = PCS::verify(
            &vk.pcs_param,
            &Commitment(rlc_comms.into_affine()),
            &sum_check_sub_claim.point,
            &rlc_eval_calc,
            &proof.opening.proof,
        )?;

        end_timer!(step);
        end_timer!(start);

        Ok(res)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hyperplonk::full_snark::{custom_gate::CustomizedGates, structs::HyperPlonkParams};
    use crate::hyperplonk::pcs::multilinear_kzg::MultilinearKzgPCS;
    use crate::read_write::identity_permutation_mles;
    use ark_bls12_381::Bls12_381;
    use ark_std::rand::rngs::StdRng;
    use ark_std::rand::SeedableRng;
    use ark_std::One;

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
            // gates: vec![(1, Some(0), vec![0]), (-1, None, vec![1])],
        };
        test_hyperplonk_helper::<Bls12_381>(gates)
    }

    fn test_hyperplonk_helper<E: Pairing>(
        gate_func: CustomizedGates,
    ) -> Result<(), HyperPlonkErrors> {
        {
            let seed = [
                1, 0, 0, 0, 23, 0, 0, 0, 200, 1, 0, 0, 210, 30, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0,
            ];
            let mut rng = StdRng::from_seed(seed);
            let pcs_srs = MultilinearKzgPCS::<E>::gen_srs_for_testing(&mut rng, 10)?;

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
            // let permutation = identity_permutation_mles(nv, num_witnesses);
            let permutation = vec![
                Arc::new(Mutex::new(DenseMLPolyStream::from_evaluations_vec(
                    2,
                    vec![
                        E::ScalarField::from(1u64),
                        E::ScalarField::from(0u64),
                        E::ScalarField::from(2u64),
                        E::ScalarField::from(3u64),
                    ],
                    None,
                    None,
                ))),
                Arc::new(Mutex::new(DenseMLPolyStream::from_evaluations_vec(
                    2,
                    vec![
                        E::ScalarField::from(5u64),
                        E::ScalarField::from(4u64),
                        E::ScalarField::from(6u64),
                        E::ScalarField::from(7u64),
                    ],
                    None,
                    None,
                ))),
            ];
            let permutation_index = identity_permutation_mles(nv, num_witnesses);
            let q1 = Arc::new(Mutex::new(DenseMLPolyStream::from_evaluations_vec(
                2,
                vec![
                    E::ScalarField::one(),
                    E::ScalarField::one(),
                    E::ScalarField::one(),
                    E::ScalarField::one(),
                ],
                None,
                None,
            )));
            let index = HyperPlonkIndex {
                params: params.clone(),
                permutation,
                permutation_index,
                selectors: vec![q1],
            };

            // generate pk and vks
            let (pk, vk) =
                <PolyIOP<E::ScalarField> as HyperPlonkSNARK<E, MultilinearKzgPCS<E>>>::preprocess(
                    &index, &pcs_srs,
                )?;

            // w1 := [1, 1, 2, 3]
            let w1 = Arc::new(Mutex::new(DenseMLPolyStream::from_evaluations_vec(
                2,
                vec![
                    E::ScalarField::one(),
                    E::ScalarField::one(),
                    E::ScalarField::from(2u128),
                    E::ScalarField::from(3u128),
                ],
                None,
                None,
            )));
            // // w2 := [1, 1, 2, 3]
            // let w2 = Arc::new(Mutex::new(DenseMLPolyStream::from_evaluations_vec(
            //     2,
            //     vec![E::ScalarField::one(), E::ScalarField::one(), E::ScalarField::from(2u128), E::ScalarField::from(3u128)],
            //     None,
            //     None,
            // )));
            // w2 := [1^5, 1^5, 2^5, 3^5]
            let w2 = Arc::new(Mutex::new(DenseMLPolyStream::from_evaluations_vec(
                2,
                vec![
                    E::ScalarField::one(),
                    E::ScalarField::one(),
                    E::ScalarField::from(32u128),
                    E::ScalarField::from(243u128),
                ],
                None,
                None,
            )));
            // public input = w1
            let pi = vec![
                E::ScalarField::one(),
                E::ScalarField::one(),
                E::ScalarField::from(2u128),
                E::ScalarField::from(3u128),
            ];

            // generate a proof and verify
            let proof =
                <PolyIOP<E::ScalarField> as HyperPlonkSNARK<E, MultilinearKzgPCS<E>>>::prove(
                    &pk,
                    &pi,
                    vec![w1.clone(), w2.clone()],
                )?;

            let _verify =
                <PolyIOP<E::ScalarField> as HyperPlonkSNARK<E, MultilinearKzgPCS<E>>>::verify(
                    &vk, &pi, &proof,
                )?;

            assert!(_verify);
        }

        {
            // bad path 1: wrong permutation
            let seed = [
                1, 0, 0, 0, 23, 0, 0, 0, 200, 1, 0, 0, 210, 30, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0,
            ];
            let mut rng = StdRng::from_seed(seed);
            let pcs_srs = MultilinearKzgPCS::<E>::gen_srs_for_testing(&mut rng, 10)?;

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
            let rand_perm = vec![
                Arc::new(Mutex::new(DenseMLPolyStream::from_evaluations_vec(
                    2,
                    vec![
                        E::ScalarField::from(1u64),
                        E::ScalarField::from(3u64),
                        E::ScalarField::from(6u64),
                        E::ScalarField::from(7u64),
                    ],
                    None,
                    None,
                ))),
                Arc::new(Mutex::new(DenseMLPolyStream::from_evaluations_vec(
                    2,
                    vec![
                        E::ScalarField::from(2u64),
                        E::ScalarField::from(5u64),
                        E::ScalarField::from(0u64),
                        E::ScalarField::from(4u64),
                    ],
                    None,
                    None,
                ))),
            ];

            let permutation_index = identity_permutation_mles(nv, num_witnesses);
            let q1 = Arc::new(Mutex::new(DenseMLPolyStream::from_evaluations_vec(
                2,
                vec![
                    E::ScalarField::one(),
                    E::ScalarField::one(),
                    E::ScalarField::one(),
                    E::ScalarField::one(),
                ],
                None,
                None,
            )));
            let bad_index = HyperPlonkIndex {
                params,
                permutation: rand_perm,
                permutation_index,
                selectors: vec![q1],
            };

            // generate pk and vks
            let (pk, bad_vk) = <PolyIOP<E::ScalarField> as HyperPlonkSNARK<
                E,
                MultilinearKzgPCS<E>,
            >>::preprocess(&bad_index, &pcs_srs)?;

            // w1 := [1, 1, 2, 3]
            let w1 = Arc::new(Mutex::new(DenseMLPolyStream::from_evaluations_vec(
                2,
                vec![
                    E::ScalarField::one(),
                    E::ScalarField::one(),
                    E::ScalarField::from(2u128),
                    E::ScalarField::from(3u128),
                ],
                None,
                None,
            )));
            // w2 := [1^5, 1^5, 2^5, 3^5]
            let w2 = Arc::new(Mutex::new(DenseMLPolyStream::from_evaluations_vec(
                2,
                vec![
                    E::ScalarField::one(),
                    E::ScalarField::one(),
                    E::ScalarField::from(32u128),
                    E::ScalarField::from(243u128),
                ],
                None,
                None,
            )));
            // public input = w1
            let pi = vec![
                E::ScalarField::one(),
                E::ScalarField::one(),
                E::ScalarField::from(2u128),
                E::ScalarField::from(3u128),
            ];

            // generate a proof and verify
            let proof =
                <PolyIOP<E::ScalarField> as HyperPlonkSNARK<E, MultilinearKzgPCS<E>>>::prove(
                    &pk,
                    &pi,
                    vec![w1.clone(), w2.clone()],
                )?;

            assert!(
                <PolyIOP<E::ScalarField> as HyperPlonkSNARK<E, MultilinearKzgPCS<E>>>::verify(
                    &bad_vk, &pi, &proof,
                )
                .is_err()
            );
        }

        Ok(())
    }
}
