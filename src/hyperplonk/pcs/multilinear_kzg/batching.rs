use crate::hyperplonk::arithmetic::virtual_polynomial::{
    build_eq_x_r_vec, VPAuxInfo, VirtualPolynomial,
};
use crate::hyperplonk::poly_iop::{prelude::SumCheck, structs::IOPProof, PolyIOP};
use crate::read_write::{DenseMLPoly, DenseMLPolyStream, ReadWriteStream};
use crate::{
    hyperplonk::{
        arithmetic::virtual_polynomial::build_eq_x_r,
        pcs::{
            multilinear_kzg::util::eq_eval,
            prelude::{Commitment, PCSError},
            PolynomialCommitmentScheme,
        },
    },
    read_write::{add_assign, copy_mle},
};
use ark_ec::pairing::Pairing;
use ark_ec::{scalar_mul::variable_base::VariableBaseMSM, CurveGroup};

use crate::hyperplonk::transcript::IOPTranscript;
use ark_std::{end_timer, log2, start_timer, One, Zero};
use std::{
    collections::BTreeMap,
    iter,
    marker::PhantomData,
    ops::Deref,
    sync::{Arc, Mutex},
};

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BatchProof<E, PCS>
where
    E: Pairing,
    PCS: PolynomialCommitmentScheme<E>,
{
    /// A sum check proof proving tilde g's sum
    pub(crate) sum_check_proof: IOPProof<E::ScalarField>,
    /// f_i(point_i)
    pub f_i_eval_at_point_i: Vec<E::ScalarField>,
    /// proof for g'(a_2)
    pub(crate) g_prime_proof: PCS::Proof,
}

/// Steps:
/// 1. get challenge point t from transcript
/// 2. build eq(t,i) for i in [0..k]
/// 3. build \tilde g_i(b) = eq(t, i) * f_i(b)
/// 4. compute \tilde eq_i(b) = eq(b, point_i)
/// 5. run sumcheck on \sum_i=1..k \tilde eq_i * \tilde g_i
/// 6. build g'(X) = \sum_i=1..k \tilde eq_i(a2) * \tilde g_i(X) where (a2) is
/// the sumcheck's point 7. open g'(X) at point (a2)
pub(crate) fn multi_open_internal<E, PCS>(
    prover_param: &PCS::ProverParam,
    polynomials: &[PCS::Polynomial],
    // polynomials: Vec<Arc<Mutex<DenseMLPolyStream<E::ScalarField>>>>,
    points: &[PCS::Point],
    evals: &[PCS::Evaluation],
    transcript: &mut IOPTranscript<E::ScalarField>,
) -> Result<BatchProof<E, PCS>, PCSError>
where
    E: Pairing,
    PCS: PolynomialCommitmentScheme<
        E,
        Polynomial = Arc<Mutex<DenseMLPolyStream<E::ScalarField>>>,
        Point = Vec<E::ScalarField>,
        Evaluation = E::ScalarField,
    >,
{
    let open_timer = start_timer!(|| format!("multi open {} points", points.len()));

    // TODO: sanity checks
    let num_var = polynomials[0].lock().unwrap().num_vars;
    let k = polynomials.len();
    let ell = log2(k) as usize;

    // challenge point t
    let t = transcript.get_and_append_challenge_vectors("t".as_ref(), ell)?;

    // eq(t, i) for i in [0..k]
    let eq_t_i_list = build_eq_x_r_vec(t.as_ref())?;

    // \tilde g_i(b) = eq(t, i) * f_i(b)
    let timer = start_timer!(|| format!("compute tilde g for {} points", points.len()));
    // combine the polynomials that have same opening point first to reduce the
    // cost of sum check later.
    let point_indices = points
        .iter()
        .fold(BTreeMap::<_, _>::new(), |mut indices, point| {
            let idx = indices.len();
            indices.entry(point).or_insert(idx);
            indices
        });
    let deduped_points =
        BTreeMap::from_iter(point_indices.iter().map(|(point, idx)| (*idx, *point)))
            .into_values()
            .collect::<Vec<_>>();
    let merged_tilde_gs = polynomials
        .iter()
        .zip(points.iter())
        .zip(eq_t_i_list.iter())
        .fold(
            iter::repeat_with(|| {
                DenseMLPolyStream::const_mle(E::ScalarField::zero(), num_var, None, None)
            })
            .take(point_indices.len())
            .collect::<Vec<Arc<Mutex<DenseMLPolyStream<E::ScalarField>>>>>(),
            |merged_tilde_gs, ((poly, point), coeff)| {
                add_assign(
                    merged_tilde_gs[point_indices[point]].clone(),
                    *coeff,
                    poly.clone(),
                );
                // merged_tilde_gs is a new stream created so that the source streams (poly) aren't modified at all in foldings later
                merged_tilde_gs
            },
        );
    end_timer!(timer);

    let timer = start_timer!(|| format!("compute tilde eq for {} points", points.len()));
    let tilde_eqs: Vec<Arc<Mutex<DenseMLPolyStream<E::ScalarField>>>> = deduped_points
        .iter()
        .map(|point| {
            build_eq_x_r(point.as_ref()).unwrap()
            // let eq_b_zi = build_eq_x_r_vec(point).unwrap();
            // Arc::new(DenseMultilinearExtension::from_evaluations_vec(
            //     num_var, eq_b_zi,
            // ))
        })
        .collect();
    end_timer!(timer);

    // copy merged_tilde_gs for opening (original copy used for sum check and another copy for opening)
    start_timer!(|| "copy merged_tilde_gs for opening");
    let merged_tilde_gs_copy = merged_tilde_gs
        .iter()
        .map(|x| copy_mle(x, None, None))
        .collect::<Vec<Arc<Mutex<DenseMLPolyStream<E::ScalarField>>>>>();
    end_timer!(timer);

    // built the virtual polynomial for SumCheck
    let timer = start_timer!(|| format!("sum check prove of {} variables", num_var));

    let step = start_timer!(|| "add mle");
    let mut sum_check_vp = VirtualPolynomial::new(num_var);
    for (merged_tilde_g, tilde_eq) in merged_tilde_gs.iter().zip(tilde_eqs.into_iter()) {
        sum_check_vp.add_mle_list(
            [merged_tilde_g.clone(), tilde_eq.clone()],
            E::ScalarField::one(),
        )?;
    }
    end_timer!(step);

    let proof = match <PolyIOP<E::ScalarField> as SumCheck<E::ScalarField>>::prove(
        &sum_check_vp,
        transcript,
    ) {
        Ok(p) => p,
        Err(_e) => {
            // cannot wrap IOPError with PCSError due to cyclic dependency
            return Err(PCSError::InvalidProver(
                "Sumcheck in batch proving Failed".to_string(),
            ));
        }
    };

    end_timer!(timer);

    // a2 := sumcheck's point
    let a2 = &proof.point[..num_var];

    // build g'(X) = \sum_i=1..k \tilde eq_i(a2) * \tilde g_i(X) where (a2) is the
    // sumcheck's point \tilde eq_i(a2) = eq(a2, point_i)
    let step = start_timer!(|| "evaluate at a2");
    let g_prime = DenseMLPolyStream::const_mle(E::ScalarField::zero(), num_var, None, None);
    for (merged_tilde_g, point) in merged_tilde_gs_copy.iter().zip(deduped_points.iter()) {
        let eq_i_a2 = eq_eval(a2, point)?;
        add_assign(g_prime.clone(), eq_i_a2, merged_tilde_g.clone());
        // drop(g_prime_stream); // No longer needed
    }
    end_timer!(step);

    let step = start_timer!(|| "pcs open");
    let (g_prime_proof, _g_prime_eval) = PCS::open(prover_param, &g_prime, a2.to_vec().as_ref())?;
    // assert_eq!(g_prime_eval, tilde_g_eval);
    end_timer!(step);

    let step = start_timer!(|| "evaluate fi(pi)");
    end_timer!(step);
    end_timer!(open_timer);

    Ok(BatchProof {
        sum_check_proof: proof,
        f_i_eval_at_point_i: evals.to_vec(),
        g_prime_proof,
    })
}

/// Steps:
/// 1. get challenge point t from transcript
/// 2. build g' commitment
/// 3. ensure \sum_i eq(a2, point_i) * eq(t, <i>) * f_i_evals matches the sum
/// via SumCheck verification 4. verify commitment
pub(crate) fn batch_verify_internal<E, PCS>(
    verifier_param: &PCS::VerifierParam,
    f_i_commitments: &[Commitment<E>],
    points: &[PCS::Point],
    proof: &BatchProof<E, PCS>,
    transcript: &mut IOPTranscript<E::ScalarField>,
) -> Result<bool, PCSError>
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
    let open_timer = start_timer!(|| "batch verification");

    // TODO: sanity checks

    let k = f_i_commitments.len();
    let ell = log2(k) as usize;
    let num_var = proof.sum_check_proof.point.len();

    // challenge point t
    let t = transcript.get_and_append_challenge_vectors("t".as_ref(), ell)?;

    // sum check point (a2)
    let a2 = &proof.sum_check_proof.point[..num_var];

    // build g' commitment
    let step = start_timer!(|| "build homomorphic commitment");
    let eq_t_list = build_eq_x_r_vec(t.as_ref())?;

    let mut scalars = vec![];
    let mut bases = vec![];

    for (i, point) in points.iter().enumerate() {
        let eq_i_a2 = eq_eval(a2, point)?;
        scalars.push(eq_i_a2 * eq_t_list[i]);
        bases.push(f_i_commitments[i].0);
    }
    let g_prime_commit = E::G1::msm_unchecked(&bases, &scalars);
    end_timer!(step);

    // ensure \sum_i eq(t, <i>) * f_i_evals matches the sum via SumCheck
    let mut sum = E::ScalarField::zero();
    for (i, &e) in eq_t_list.iter().enumerate().take(k) {
        sum += e * proof.f_i_eval_at_point_i[i];
    }
    let aux_info = VPAuxInfo {
        max_degree: 2,
        num_variables: num_var,
        phantom: PhantomData,
    };
    let subclaim = match <PolyIOP<E::ScalarField> as SumCheck<E::ScalarField>>::verify(
        sum,
        &proof.sum_check_proof,
        &aux_info,
        transcript,
    ) {
        Ok(p) => p,
        Err(_e) => {
            // cannot wrap IOPError with PCSError due to cyclic dependency
            return Err(PCSError::InvalidProver(
                "Sumcheck in batch verification failed".to_string(),
            ));
        }
    };
    let tilde_g_eval = subclaim.expected_evaluation;

    // verify commitment
    let res = PCS::verify(
        verifier_param,
        &Commitment(g_prime_commit.into_affine()),
        a2.to_vec().as_ref(),
        &tilde_g_eval,
        &proof.g_prime_proof,
    )?;

    end_timer!(open_timer);
    Ok(res)
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BatchProofSinglePoint<E, PCS>
where
    E: Pairing,
    PCS: PolynomialCommitmentScheme<E>,
{
    pub rlc_eval: E::ScalarField, // rlc of f_i(point_i)
    pub(crate) proof: PCS::Proof, // proof for rlc of polynomials
    pub perm_evals: Vec<E::ScalarField>,
    pub perm_index_evals: Vec<E::ScalarField>,
    pub selector_evals: Vec<E::ScalarField>,
    pub witness_evals: Vec<E::ScalarField>,
    pub hp_evals: Vec<E::ScalarField>,
    pub hq_evals: Vec<E::ScalarField>,
}

// still uses batch proof single point method, but use it multiple times on different points
// so we get multiple proofs of rlcs of polynomials opened at a single point
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BatchProofSinglePointAggr<E, PCS>
where
    E: Pairing,
    PCS: PolynomialCommitmentScheme<E>,
{
    // product final query [1, 1, ..., 1, 0]
    pub rlc_eval_prod: E::ScalarField, // rlc of f_i(point_i)
    pub proof_prod: PCS::Proof,        // proof for rlc of polynomials
    // perm query
    pub rlc_eval_perm: E::ScalarField, // rlc of f_i(point_i)
    pub proof_perm: PCS::Proof,        // proof for rlc of polynomials
    // perm 0 query
    pub rlc_eval_perm_0: E::ScalarField, // rlc of f_i(point_i)
    pub proof_perm_0: PCS::Proof,        // proof for rlc of polynomials
    // perm 1 query
    pub rlc_eval_perm_1: E::ScalarField, // rlc of f_i(point_i)
    pub proof_perm_1: PCS::Proof,        // proof for rlc of polynomials
    // zero check query
    pub rlc_eval_zero: E::ScalarField, // rlc of f_i(point_i)
    pub proof_zero: PCS::Proof,        // proof for rlc of polynomials

    // evaluations: these are needed to ensure that the rlc's are correct
    pub perm_evals: Vec<E::ScalarField>,
    pub selector_evals: Vec<E::ScalarField>,
    pub witness_evals: Vec<E::ScalarField>,
    pub prod_evals: Vec<E::ScalarField>,
    pub frac_evals: Vec<E::ScalarField>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hyperplonk::arithmetic::util::get_batched_nv;
    use crate::hyperplonk::pcs::{
        prelude::{MultilinearKzgPCS, MultilinearUniversalParams},
        StructuredReferenceString,
    };
    use ark_bls12_381::Bls12_381 as E;
    use ark_ec::pairing::Pairing;
    use ark_poly::{DenseMultilinearExtension, MultilinearExtension};
    use ark_std::{rand::Rng, test_rng, vec::Vec, UniformRand};

    type Fr = <E as Pairing>::ScalarField;

    fn test_multi_open_helper<R: Rng>(
        ml_params: &MultilinearUniversalParams<E>,
        polys: Vec<Arc<Mutex<DenseMLPolyStream<Fr>>>>,
        rng: &mut R,
    ) -> Result<(), PCSError> {
        let merged_nv = get_batched_nv(polys[0].lock().unwrap().num_vars(), polys.len());
        let (ml_ck, ml_vk) = ml_params.trim(merged_nv)?;

        let mut points = Vec::new();
        for poly in polys.iter() {
            let point = (0..poly.lock().unwrap().num_vars())
                .map(|_| Fr::rand(rng))
                .collect::<Vec<Fr>>();
            points.push(point);
        }

        // create poly copies for evaluation, which changes the stream
        let mut polys_copy = polys
            .iter()
            .map(|x| copy_mle(x, None, None))
            .collect::<Vec<_>>();

        let evals = polys_copy
            .iter()
            .zip(points.iter())
            .map(|(f, p)| f.lock().unwrap().evaluate(p).unwrap())
            .collect::<Vec<_>>();

        let commitments = polys
            .iter()
            .map(|poly| MultilinearKzgPCS::commit(&ml_ck.clone(), poly).unwrap())
            .collect::<Vec<_>>();

        let mut transcript = IOPTranscript::new("test transcript".as_ref());
        transcript.append_field_element("init".as_ref(), &Fr::zero())?;

        let batch_proof = multi_open_internal::<E, MultilinearKzgPCS<E>>(
            &ml_ck,
            &polys,
            &points,
            &evals,
            &mut transcript,
        )?;

        // good path
        let mut transcript = IOPTranscript::new("test transcript".as_ref());
        transcript.append_field_element("init".as_ref(), &Fr::zero())?;
        assert!(batch_verify_internal::<E, MultilinearKzgPCS<E>>(
            &ml_vk,
            &commitments,
            &points,
            &batch_proof,
            &mut transcript
        )?);

        Ok(())
    }

    #[test]
    fn test_multi_open_internal() -> Result<(), PCSError> {
        let mut rng = test_rng();

        let ml_params = MultilinearUniversalParams::<E>::gen_srs_for_testing(&mut rng, 15)?;
        for num_poly in 5..6 {
            for nv in 8..9 {
                let polys1: Vec<_> = (0..num_poly)
                    .map(|_| Arc::new(Mutex::new(DenseMLPolyStream::rand(nv, &mut rng))))
                    .collect();
                test_multi_open_helper(&ml_params, polys1, &mut rng)?;
            }
        }

        Ok(())
    }
}
