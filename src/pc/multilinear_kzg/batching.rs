use crate::pc::errors::PCSError;
use crate::pc::structs::Commitment;
use crate::pc::{multilinear_kzg::util::eq_eval, PolynomialCommitmentScheme};
use crate::piop::{prelude::SumCheck, structs::IOPProof};
use crate::{
    arithmetic::virtual_polynomial::{build_eq_x_r_vec, VPAuxInfo, VirtualPolynomial},
    streams::serialize::RawPrimeField,
};

use crate::streams::MLE;
use ark_ec::pairing::Pairing;
use ark_ec::{scalar_mul::variable_base::VariableBaseMSM, CurveGroup};

use crate::transcript::IOPTranscript;
use ark_std::{collections::BTreeMap, marker::PhantomData};
use ark_std::{end_timer, log2, start_timer, One, Zero};

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BatchProof<E, PC>
where
    E: Pairing,
    PC: PolynomialCommitmentScheme<E>,
{
    /// A sum check proof proving tilde g's sum
    pub(crate) sum_check_proof: IOPProof<E::ScalarField>,
    /// f_i(point_i)
    pub f_i_eval_at_point_i: Vec<E::ScalarField>,
    /// proof for g'(a_2)
    pub(crate) g_prime_proof: PC::Proof,
}

/// Steps:
/// 1. get challenge point t from transcript
/// 2. build eq(t,i) for i in [0..k]
/// 3. build \tilde g_i(b) = eq(t, i) * f_i(b)
/// 4. compute \tilde eq_i(b) = eq(b, point_i)
/// 5. run sumcheck on \sum_i=1..k \tilde eq_i * \tilde g_i
/// 6. build g'(X) = \sum_i=1..k \tilde eq_i(a2) * \tilde g_i(X) where (a2) is
///    the sumcheck's point 7. open g'(X) at point (a2)
pub(crate) fn multi_open_internal<E, PC>(
    prover_param: &PC::ProverParam,
    polynomials: &[PC::Polynomial],
    points: &[PC::Point],
    evals: &[PC::Evaluation],
    transcript: &mut IOPTranscript<E::ScalarField>,
) -> Result<BatchProof<E, PC>, PCSError>
where
    E: Pairing,
    E::ScalarField: RawPrimeField,
    PC: PolynomialCommitmentScheme<
        E,
        Polynomial = MLE<E::ScalarField>,
        Point = Vec<E::ScalarField>,
        Evaluation = E::ScalarField,
    >,
{
    let open_timer = start_timer!(|| format!("multi open {} points", points.len()));

    // TODO: sanity checks
    let num_var = polynomials[0].num_vars();
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
    let merged_tilde_gs: Vec<MLE<_>> = polynomials
        .iter()
        .zip(points.iter())
        .zip(eq_t_i_list.iter())
        .fold(
            vec![None; point_indices.len()],
            |mut merged_tilde_gs, ((poly, point), coeff)| {
                let e = &mut merged_tilde_gs[point_indices[point]];
                match e {
                    Some(e) => *e += (*coeff, poly),
                    None => *e = Some(poly * *coeff),
                }
                merged_tilde_gs
            },
        )
        .into_iter()
        .map(|merged_tilde_g| merged_tilde_g.unwrap())
        .collect();
    end_timer!(timer);

    let timer = start_timer!(|| format!("compute tilde eq for {} points", points.len()));
    let tilde_eqs: Vec<MLE<E::ScalarField>> = deduped_points
        .iter()
        .map(|point| MLE::eq_x_r(point).unwrap())
        .collect();
    end_timer!(timer);

    // built the virtual polynomial for SumCheck
    let timer = start_timer!(|| format!("sum check prove of {} variables", num_var));

    let step = start_timer!(|| "add mle");
    let mut sum_check_vp = VirtualPolynomial::new(num_var);
    for (merged_tilde_g, tilde_eq) in merged_tilde_gs.iter().zip(tilde_eqs.into_iter()) {
        sum_check_vp.add_mles([merged_tilde_g.clone(), tilde_eq], E::ScalarField::one())?;
    }
    end_timer!(step);

    let proof = match <SumCheck<E::ScalarField>>::prove(&sum_check_vp, transcript) {
        Ok(p) => p,
        Err(_e) => {
            // cannot wrap IOPError with PCSError due to cyclic dependency
            return Err(PCSError::InvalidProver(
                "Sumcheck in batch proving Failed".to_string(),
            ));
        },
    };

    end_timer!(timer);

    // a2 := sumcheck's point
    let a2 = &proof.point[..num_var];

    // build g'(X) = \sum_i=1..k \tilde eq_i(a2) * \tilde g_i(X) where (a2) is the
    // sumcheck's point \tilde eq_i(a2) = eq(a2, point_i)
    let step = start_timer!(|| "evaluate at a2");
    let mut g_prime = MLE::constant(E::ScalarField::zero(), num_var);
    for (merged_tilde_g, point) in merged_tilde_gs.iter().zip(deduped_points.iter()) {
        let eq_i_a2 = eq_eval(a2, point)?;
        g_prime += (eq_i_a2, merged_tilde_g);
    }
    end_timer!(step);

    let step = start_timer!(|| "pc open");
    let (g_prime_proof, _g_prime_eval) = PC::open(prover_param, &g_prime, a2.to_vec().as_ref())?;
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
///    via SumCheck verification 4. verify commitment
pub(crate) fn batch_verify_internal<E, PC>(
    verifier_param: &PC::VerifierParam,
    f_i_commitments: &[Commitment<E>],
    points: &[PC::Point],
    proof: &BatchProof<E, PC>,
    transcript: &mut IOPTranscript<E::ScalarField>,
) -> Result<bool, PCSError>
where
    E: Pairing,
    E::ScalarField: RawPrimeField,
    PC: PolynomialCommitmentScheme<
        E,
        Polynomial = MLE<E::ScalarField>,
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
    let subclaim = match <SumCheck<E::ScalarField>>::verify(
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
        },
    };
    let tilde_g_eval = subclaim.expected_evaluation;

    // verify commitment
    let res = PC::verify(
        verifier_param,
        &Commitment(g_prime_commit.into_affine()),
        a2.to_vec().as_ref(),
        &tilde_g_eval,
        &proof.g_prime_proof,
    )?;

    end_timer!(open_timer);
    Ok(res)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arithmetic::util::get_batched_nv;
    use crate::pc::multilinear_kzg::srs::MultilinearUniversalParams;
    use crate::pc::multilinear_kzg::PST13;
    use crate::pc::StructuredReferenceString;
    use ark_bls12_381::Bls12_381 as E;
    use ark_ec::pairing::Pairing;
    use ark_std::{rand::Rng, test_rng, vec::Vec, UniformRand};

    type Fr = <E as Pairing>::ScalarField;

    fn test_multi_open_helper<R: Rng>(
        ml_params: &MultilinearUniversalParams<E>,
        polys: &[MLE<Fr>],
        rng: &mut R,
    ) -> Result<(), PCSError> {
        let merged_nv = get_batched_nv(polys[0].num_vars(), polys.len());
        let (ml_ck, ml_vk) = ml_params.trim(merged_nv)?;

        let mut points = Vec::new();
        for poly in polys.iter() {
            let point = (0..poly.num_vars())
                .map(|_| Fr::rand(rng))
                .collect::<Vec<Fr>>();
            points.push(point);
        }

        let evals = polys
            .iter()
            .zip(points.iter())
            .map(|(f, p)| f.evaluate(p).unwrap())
            .collect::<Vec<_>>();

        let commitments = polys
            .iter()
            .map(|poly| PST13::commit(&ml_ck, poly).unwrap())
            .collect::<Vec<_>>();

        let mut transcript = IOPTranscript::new("test transcript".as_ref());
        transcript.append_field_element("init".as_ref(), &Fr::zero())?;

        let batch_proof =
            multi_open_internal::<E, PST13<E>>(&ml_ck, polys, &points, &evals, &mut transcript)?;

        // good path
        let mut transcript = IOPTranscript::new("test transcript".as_ref());
        transcript.append_field_element("init".as_ref(), &Fr::zero())?;
        assert!(batch_verify_internal::<E, PST13<E>>(
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

        let ml_params = MultilinearUniversalParams::<E>::gen_srs_for_testing(&mut rng, 20)?;
        for num_poly in 5..6 {
            for nv in 15..16 {
                let polys1: Vec<_> = (0..num_poly).map(|_| MLE::rand(nv, &mut rng)).collect();
                test_multi_open_helper(&ml_params, &polys1, &mut rng)?;
            }
        }

        Ok(())
    }
}
