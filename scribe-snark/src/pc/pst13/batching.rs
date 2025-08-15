use crate::pc::PCScheme;
use crate::pc::errors::PCError;
use crate::pc::structs::Commitment;
use crate::piop::{prelude::SumCheck, structs::IOPProof};
use crate::transcript::IOPTranscript;
use mle::{
    MLE, VirtualMLE, eq_eval,
    util::build_eq_x_r_vec,
    virtual_polynomial::{VPAuxInfo, VirtualPolynomial},
};
use scribe_streams::{
    iterator::{BatchedIterator, zip_many},
    serialize::RawPrimeField,
};

use ark_ec::pairing::Pairing;
use ark_ec::{CurveGroup, scalar_mul::variable_base::VariableBaseMSM};

use ark_std::{One, Zero, end_timer, log2, start_timer};
use ark_std::{collections::BTreeMap, marker::PhantomData};

use itertools::Itertools;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BatchProof<E, PC>
where
    E: Pairing,
    PC: PCScheme<E>,
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
    ck: &PC::CommitterKey,
    polynomials: &[PC::Polynomial],
    points: &[PC::Point],
    evals: &[PC::Evaluation],
    transcript: &mut IOPTranscript<E::ScalarField>,
) -> Result<BatchProof<E, PC>, PCError>
where
    E: Pairing,
    E::ScalarField: RawPrimeField,
    PC: PCScheme<
            E,
            Polynomial = VirtualMLE<E::ScalarField>,
            Point = Vec<E::ScalarField>,
            Evaluation = E::ScalarField,
        >,
{
    let open_timer = start_timer!(|| format!("multi open {} points", points.len()));

    // TODO: sanity checks
    let num_vars = polynomials[0].num_vars();
    let k = polynomials.len();
    let ell = log2(k) as usize;

    // challenge point t
    let t = transcript.get_and_append_challenge_vectors("t".as_ref(), ell)?;

    // eq(t, i) for i in [0..k]
    let eq_t_i_list = build_eq_x_r_vec(t.as_ref()).ok_or(PCError::InvalidParameters(
        "failed to build eq(t, i) for multi-open".to_string(),
    ))?;

    // \tilde g_i(b) = eq(t, i) * f_i(b)
    let timer = start_timer!(|| format!("compute tilde g for {} points", points.len()));
    // combine the polynomials that have same opening point first to reduce the
    // cost of sum check later.

    // This maps each point to the index of the first polynomial that has it as the opening point.
    let point_indices = points
        .iter()
        .fold(BTreeMap::<_, _>::new(), |mut indices, point| {
            let idx = indices.len();
            // If it is already in the map, we don't update the value
            // Otherwise, we insert the index of the first polynomial
            // that has `point` as the opening point
            indices.entry(point).or_insert(idx);
            indices
        });
    let deduped_points =
        BTreeMap::from_iter(point_indices.iter().map(|(point, idx)| (*idx, *point)))
            .into_values()
            .collect::<Vec<_>>();

    let mut v = BTreeMap::new();
    for ((poly, coeff), point) in polynomials.iter().zip(eq_t_i_list).zip(points) {
        v.entry(point).or_insert(Vec::new()).push((coeff, poly));
    }
    let mut v = v.into_iter().collect::<Vec<_>>();
    v.sort_by_key(|(point, _)| point_indices[point]);
    let mut buf = vec![];
    let merged_tilde_gs = v
        .into_iter()
        .map(|(_, coeffs_and_polys)| {
            let evals = coeffs_and_polys
                .into_iter()
                .map(|(c, p)| p.evals().map(move |e| e * c))
                .chunks(8)
                .into_iter()
                .map(|chunk| {
                    let mut chunk = chunk.collect::<Vec<_>>();
                    match chunk.len() {
                        1 => chunk.pop().unwrap().to_file_vec(),
                        2 => {
                            let a = chunk.pop().unwrap();
                            let b = chunk.pop().unwrap();
                            a.zip(b).map(|(a, b)| a + b).to_file_vec()
                        },
                        3 => {
                            let a = chunk.pop().unwrap();
                            let b = chunk.pop().unwrap();
                            let c = chunk.pop().unwrap();
                            a.zip(b).zip(c).map(|((a, b), c)| a + b + c).to_file_vec()
                        },
                        4 => {
                            let a = chunk.pop().unwrap();
                            let b = chunk.pop().unwrap();
                            let c = chunk.pop().unwrap();
                            let d = chunk.pop().unwrap();
                            a.zip(b)
                                .zip(c)
                                .zip(d)
                                .map(|(((a, b), c), d)| a + b + c + d)
                                .to_file_vec()
                        },
                        5 => {
                            let a = chunk.pop().unwrap();
                            let b = chunk.pop().unwrap();
                            let c = chunk.pop().unwrap();
                            let d = chunk.pop().unwrap();
                            let e = chunk.pop().unwrap();
                            a.zip(b)
                                .zip(c)
                                .zip(d)
                                .zip(e)
                                .map(|((((a, b), c), d), e)| a + b + c + d + e)
                                .to_file_vec()
                        },
                        6 => {
                            let a = chunk.pop().unwrap();
                            let b = chunk.pop().unwrap();
                            let c = chunk.pop().unwrap();
                            let d = chunk.pop().unwrap();
                            let e = chunk.pop().unwrap();
                            let f = chunk.pop().unwrap();
                            a.zip(b)
                                .zip(c)
                                .zip(d)
                                .zip(e)
                                .zip(f)
                                .map(|(((((a, b), c), d), e), f)| a + b + c + d + e + f)
                                .to_file_vec()
                        },
                        7 => {
                            let a = chunk.pop().unwrap();
                            let b = chunk.pop().unwrap();
                            let c = chunk.pop().unwrap();
                            let d = chunk.pop().unwrap();
                            let e = chunk.pop().unwrap();
                            let f = chunk.pop().unwrap();
                            let g = chunk.pop().unwrap();
                            a.zip(b)
                                .zip(c)
                                .zip(d)
                                .zip(e)
                                .zip(f)
                                .zip(g)
                                .map(|((((((a, b), c), d), e), f), g)| a + b + c + d + e + f + g)
                                .to_file_vec()
                        },
                        8 => {
                            let a = chunk.pop().unwrap();
                            let b = chunk.pop().unwrap();
                            let c = chunk.pop().unwrap();
                            let d = chunk.pop().unwrap();
                            let e = chunk.pop().unwrap();
                            let f = chunk.pop().unwrap();
                            let g = chunk.pop().unwrap();
                            let h = chunk.pop().unwrap();
                            a.zip(b)
                                .zip(c)
                                .zip(d)
                                .zip(e)
                                .zip(f)
                                .zip(g)
                                .zip(h)
                                .map(|(((((((a, b), c), d), e), f), g), h)| {
                                    a + b + c + d + e + f + g + h
                                })
                                .to_file_vec()
                        },
                        _ => unreachable!(),
                    }
                })
                .reduce(|mut acc, p| {
                    acc.zipped_for_each(p.iter_with_buf(&mut buf), |a, b| *a += b);
                    acc
                })
                .unwrap();
            MLE::from_evals(evals, num_vars)
        })
        .collect::<Vec<_>>();

    end_timer!(timer);

    let timer = start_timer!(|| format!("compute tilde eq for {} points", deduped_points.len()));
    let tilde_eqs: Vec<_> = deduped_points
        .iter()
        .map(|point| VirtualMLE::eq_x_r(point))
        .collect();

    end_timer!(timer);

    // built the virtual polynomial for SumCheck
    let timer = start_timer!(|| format!("sum check prove of {num_vars} variables"));

    let step = start_timer!(|| "add mle");
    let mut sum_check_vp = VirtualPolynomial::new(num_vars);
    for (merged_tilde_g, tilde_eq) in merged_tilde_gs.iter().zip(tilde_eqs.clone()) {
        sum_check_vp.add_virtual_mles(
            [merged_tilde_g.clone().into(), tilde_eq],
            E::ScalarField::one(),
        )?;
    }
    end_timer!(step);

    let proof = SumCheck::prove(&sum_check_vp, transcript)
        .map_err(|_| PCError::InvalidProver("Sumcheck in batch proving Failed".into()))?;
    end_timer!(timer);

    // a2 := sumcheck's point
    let a2 = &proof.point[..num_vars];

    // build g'(X) = \sum_i=1..k \tilde eq_i(a2) * \tilde g_i(X) where (a2) is the
    // sumcheck's point \tilde eq_i(a2) = eq(a2, point_i)
    let step = start_timer!(|| "evaluate at a2");
    let eq_q_a2_s = deduped_points
        .iter()
        .map(|point| eq_eval(a2, point))
        .collect::<Option<Vec<_>>>()
        .unwrap();

    let g_prime_evals = zip_many(merged_tilde_gs.iter().map(|g| g.evals().iter()))
        .map(|evals| {
            evals
                .into_iter()
                .zip(&eq_q_a2_s)
                .map(|(e, eq)| e * eq)
                .sum()
        })
        .to_file_vec();
    let g_prime = MLE::from_evals(g_prime_evals, num_vars).into();
    end_timer!(step);

    let step = start_timer!(|| "pc open");
    let (g_prime_proof, _) = PC::open(ck, &g_prime, &a2.to_vec())?;
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
    vk: &PC::VerifierKey,
    f_i_commitments: &[Commitment<E>],
    points: &[PC::Point],
    proof: &BatchProof<E, PC>,
    transcript: &mut IOPTranscript<E::ScalarField>,
) -> Result<bool, PCError>
where
    E: Pairing,
    E::ScalarField: RawPrimeField,
    PC: PCScheme<
            E,
            Polynomial = VirtualMLE<E::ScalarField>,
            Point = Vec<E::ScalarField>,
            Evaluation = E::ScalarField,
            Commitment = Commitment<E>,
        >,
{
    let open_timer = start_timer!(|| "batch verification");

    let k = f_i_commitments.len();
    let ell = log2(k) as usize;
    let num_vars = proof.sum_check_proof.point.len();

    // challenge point t
    let t = transcript.get_and_append_challenge_vectors("t".as_ref(), ell)?;

    // sum check point (a2)
    let a2 = &proof.sum_check_proof.point[..num_vars];

    // build g' commitment
    let step = start_timer!(|| "build homomorphic commitment");
    let eq_t_list = build_eq_x_r_vec(t.as_ref()).ok_or(PCError::InvalidParameters(
        "failed to build eq(t, i) for multi-open".into(),
    ))?;

    let mut scalars = vec![];
    let mut bases = vec![];

    for (i, point) in points.iter().enumerate() {
        let eq_i_a2 = eq_eval(a2, point).unwrap();
        scalars.push(eq_i_a2 * eq_t_list[i]);
        bases.push(f_i_commitments[i].0);
    }
    let g_prime_commit = E::G1::msm_unchecked(&bases, &scalars);
    end_timer!(step);

    // ensure \sum_i eq(t, <i>) * f_i_evals matches the sum via SumCheck
    let mut claimed_sum = E::ScalarField::zero();
    for (i, &e) in eq_t_list.iter().enumerate().take(k) {
        claimed_sum += e * proof.f_i_eval_at_point_i[i];
    }
    let aux_info = VPAuxInfo {
        max_degree: 2,
        num_variables: num_vars,
        phantom: PhantomData,
    };
    let subclaim = SumCheck::verify(claimed_sum, &proof.sum_check_proof, &aux_info, transcript)
        .map_err(|_| PCError::InvalidProver("Sumcheck in batch verification failed".into()))?;
    let tilde_g_eval = subclaim.expected_evaluation;

    // verify commitment
    let res = PC::verify(
        vk,
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
    use crate::pc::StructuredReferenceString;
    use crate::pc::pst13::PST13;
    use crate::pc::pst13::srs::SRS;
    use ark_bls12_381::Bls12_381 as E;
    use ark_ec::pairing::Pairing;
    use ark_std::{UniformRand, rand::Rng, test_rng, vec::Vec};
    use mle::util::get_batched_nv;

    type Fr = <E as Pairing>::ScalarField;

    fn test_multi_open_helper<R: Rng>(
        ml_params: &SRS<E>,
        polys: &[VirtualMLE<Fr>],
        rng: &mut R,
    ) -> Result<(), PCError> {
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
    fn test_multi_open_internal() -> Result<(), PCError> {
        let mut rng = test_rng();

        let ml_params = SRS::<E>::gen_srs_for_testing(&mut rng, 21)?;
        for num_poly in 5..6 {
            // for nv in 9..19 {
            for nv in 17..19 {
                let polys1: Vec<_> = (0..num_poly)
                    .map(|_| MLE::rand(nv, &mut rng).into())
                    .collect();
                test_multi_open_helper(&ml_params, &polys1, &mut rng)?;
            }
        }

        Ok(())
    }
}
