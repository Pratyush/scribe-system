pub(crate) mod batching;
pub(crate) mod srs;
pub(crate) mod util;
use crate::hyperplonk::pcs::multilinear_kzg::batching::multi_open_internal;
use crate::hyperplonk::pcs::StructuredReferenceString;
use crate::hyperplonk::pcs::{structs::Commitment, PCSError, PolynomialCommitmentScheme};
use crate::hyperplonk::transcript::IOPTranscript;
use crate::streams::file_vec::FileVec;
use crate::streams::{iterator::BatchedIterator, MLE};
use ark_ec::{
    pairing::Pairing,
    scalar_mul::{fixed_base::FixedBase, variable_base::VariableBaseMSM},
    AffineRepr, CurveGroup,
};
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{
    borrow::Borrow, end_timer, format, marker::PhantomData, rand::Rng, start_timer,
    string::ToString, vec::Vec, One, Zero,
};
use rayon::iter::{ParallelExtend, ParallelIterator};
use srs::{MultilinearProverParam, MultilinearUniversalParams, MultilinearVerifierParam};
use std::ops::Mul;

use self::batching::{batch_verify_internal, BatchProof};

/// KZG Polynomial Commitment Scheme on multilinear polynomials.
pub struct MultilinearKzgPCS<E: Pairing> {
    #[doc(hidden)]
    phantom: PhantomData<E>,
}

#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug, PartialEq, Eq)]
/// proof of opening
pub struct MultilinearKzgProof<E: Pairing> {
    /// Evaluation of quotients
    pub proofs: Vec<E::G1Affine>,
}

impl<E: Pairing> PolynomialCommitmentScheme<E> for MultilinearKzgPCS<E> {
    // Parameters
    type ProverParam = MultilinearProverParam<E>;
    type VerifierParam = MultilinearVerifierParam<E>;
    type SRS = MultilinearUniversalParams<E>;
    // Polynomial and its associated types
    type Polynomial = MLE<E::ScalarField>;
    type Point = Vec<E::ScalarField>;
    type Evaluation = E::ScalarField;
    // Commitments and proofs
    type Commitment = Commitment<E>;
    type Proof = MultilinearKzgProof<E>;
    type BatchProof = BatchProof<E, Self>;

    /// Build SRS for testing.
    ///
    /// - For univariate polynomials, `log_size` is the log of maximum degree.
    /// - For multilinear polynomials, `log_size` is the number of variables.
    ///
    /// WARNING: THIS FUNCTION IS FOR TESTING PURPOSE ONLY.
    /// THE OUTPUT SRS SHOULD NOT BE USED IN PRODUCTION.
    fn gen_srs_for_testing<R: Rng>(rng: &mut R, log_size: usize) -> Result<Self::SRS, PCSError> {
        MultilinearUniversalParams::<E>::gen_srs_for_testing(rng, log_size)
        // MultilinearUniversalParams::<E>::gen_fake_srs_for_testing(rng, log_size)
    }

    fn gen_fake_srs_for_testing<R: Rng>(
        rng: &mut R,
        log_size: usize,
    ) -> Result<Self::SRS, PCSError> {
        MultilinearUniversalParams::<E>::gen_fake_srs_for_testing(rng, log_size)
    }

    /// Trim the universal parameters to specialize the public parameters.
    /// Input both `supported_log_degree` for univariate and
    /// `supported_num_vars` for multilinear.
    fn trim(
        srs: impl Borrow<Self::SRS>,
        supported_degree: Option<usize>,
        supported_num_vars: Option<usize>,
    ) -> Result<(Self::ProverParam, Self::VerifierParam), PCSError> {
        assert!(supported_degree.is_none());

        let supported_num_vars = match supported_num_vars {
            Some(p) => p,
            None => {
                return Err(PCSError::InvalidParameters(
                    "multilinear should receive a num_var param".to_string(),
                ))
            }
        };
        let (ml_ck, ml_vk) = srs.borrow().trim(supported_num_vars)?;

        Ok((ml_ck, ml_vk))
    }

    /// Generate a commitment for a polynomial.
    ///
    /// This function takes `2^num_vars` number of scalar multiplications over
    /// G1.
    fn commit(
        prover_param: impl Borrow<Self::ProverParam>,
        poly: &Self::Polynomial,
    ) -> Result<Self::Commitment, PCSError> {
        let prover_param = prover_param.borrow();
        let poly_num_vars = poly.num_vars();

        let commit_timer = start_timer!(|| format!("commit poly nv = {}", poly_num_vars));
        if prover_param.num_vars < poly_num_vars {
            return Err(PCSError::InvalidParameters(format!(
                "MLE length ({}) exceeds param limit ({})",
                poly_num_vars, prover_param.num_vars
            )));
        }
        let ignored = prover_param.num_vars - poly_num_vars;

        let commitment = {
            let mut poly_evals = poly.evals().iter();
            let mut srs = prover_param.powers_of_g[ignored].evals.iter();
            let mut f_buf = Vec::with_capacity(crate::streams::BUFFER_SIZE);
            let mut g_buf = Vec::with_capacity(crate::streams::BUFFER_SIZE);
            let mut commitment = E::G1::zero();
            while let (Some(p), Some(g)) = (poly_evals.next_batch(), srs.next_batch()) {
                f_buf.clear();
                g_buf.clear();
                f_buf.par_extend(p);
                g_buf.par_extend(g);
                commitment += E::G1::msm_unchecked(&g_buf, &f_buf);
            }
            commitment.into_affine()
        };

        end_timer!(commit_timer);
        Ok(Commitment(commitment))
    }

    /// On input a polynomial `p` and a point `point`, outputs a proof for the
    /// same. This function does not need to take the evaluation value as an
    /// input.
    ///
    /// This function takes 2^{num_var +1} number of scalar multiplications over
    /// G1:
    /// - it prodceeds with `num_var` number of rounds,
    /// - at round i, we compute an MSM for `2^{num_var - i + 1}` number of G2
    ///   elements.
    fn open(
        prover_param: impl Borrow<Self::ProverParam>,
        polynomial: &Self::Polynomial,
        point: &Self::Point,
    ) -> Result<(Self::Proof, Self::Evaluation), PCSError> {
        open_internal(prover_param.borrow(), &polynomial, point)
    }

    // // this is the multi poly single point version
    // /// Input a list of multilinear extensions, and a same number of points, and
    // /// a transcript, compute a multi-opening for all the polynomials.
    // fn multi_open_single_point(
    //     prover_param: impl Borrow<Self::ProverParam>,
    //     polynomials: &[Self::Polynomial],
    //     point: Self::Point,
    //     transcript: &mut IOPTranscript<E::ScalarField>,
    // ) -> Result<(Self::Proof, E::ScalarField), PCSError> {
    //     let alpha = transcript.get_and_append_challenge(b"opening rlc").unwrap();

    //     // assert that poly has same num_vars as points length
    //     let num_vars = polynomials[0].lock().unwrap().num_vars;
    //     assert_eq!(num_vars, point.len());

    //     // create random linear combination of polynomials, a new stream in the form of poly0 + alpha * poly1 + alpha^2 * poly2 + ...
    //     let mut poly = DenseMLPolyStream::<E::ScalarField>::with_path(num_vars, None, None);

    //     // create a vector of 1, alpha, alpha^2, ..., alpha^polynomials.len()
    //     let alphas = (0..polynomials.len())
    //         .map(|i| alpha.pow(&[i as u64]))
    //         .collect::<Vec<E::ScalarField>>();

    //     // lock all polynomials and make sure they all have the same num_vars
    //     let mut polys_locks = polynomials
    //         .iter()
    //         .map(|p| p.lock().unwrap())
    //         .collect::<Vec<_>>();
    //     for poly_lock in &polys_locks {
    //         assert_eq!(
    //             poly_lock.num_vars, num_vars,
    //             "All polynomials must have the same number of variables."
    //         );
    //     }

    //     // for each locked polynomial, read the next element using polynomial_lock.read_next()
    //     // if the return value is Some(), multiply it to the corresponding alpha and sum it
    //     // write the sum to the result poly using poly.write_next_unchecked(sum)
    //     // note that there's a sum for each value read from the polynomials, so the result poly will have the same length as the source polynomials
    //     for _ in 0..(1 << num_vars) {
    //         let mut sum = E::ScalarField::zero();
    //         for (i, poly_lock) in polys_locks.iter_mut().enumerate() {
    //             if let Some(val) = poly_lock.read_next() {
    //                 // Multiply it to the corresponding alpha and sum it
    //                 sum += val * &alphas[i];
    //             }
    //         }
    //         // Write the sum to the result poly
    //         poly.write_next_unchecked(sum);
    //     }

    //     poly.swap_read_write();

    //     open_internal(prover_param.borrow(), Arc::new(Mutex::new(poly)), &point)
    // }

    /// Input a list of multilinear extensions, and a same number of points, and
    /// a transcript, compute a multi-opening for all the polynomials.
    fn multi_open(
        prover_param: impl Borrow<Self::ProverParam>,
        polynomials: &[Self::Polynomial],
        points: &[Self::Point],
        evals: &[Self::Evaluation],
        transcript: &mut IOPTranscript<E::ScalarField>,
    ) -> Result<BatchProof<E, Self>, PCSError> {
        multi_open_internal(
            prover_param.borrow(),
            polynomials,
            points,
            evals,
            transcript,
        )
    }

    /// Verifies that `value` is the evaluation at `x` of the polynomial
    /// committed inside `comm`.
    ///
    /// This function takes
    /// - num_var number of pairing product.
    /// - num_var number of MSM
    fn verify(
        verifier_param: &Self::VerifierParam,
        commitment: &Self::Commitment,
        point: &Self::Point,
        value: &E::ScalarField,
        proof: &Self::Proof,
    ) -> Result<bool, PCSError> {
        verify_internal(verifier_param, commitment, point, value, proof)
    }

    /// Verifies that `value_i` is the evaluation at `x_i` of the polynomial
    /// `poly_i` committed inside `comm`.
    fn batch_verify(
        verifier_param: &Self::VerifierParam,
        commitments: &[Self::Commitment],
        points: &[Self::Point],
        batch_proof: &Self::BatchProof,
        transcript: &mut IOPTranscript<E::ScalarField>,
    ) -> Result<bool, PCSError> {
        batch_verify_internal(verifier_param, commitments, points, batch_proof, transcript)
    }
}

/// On input a polynomial `p` and a point `point`, outputs a proof for the
/// same. This function does not need to take the evaluation value as an
/// input.
///
/// This function takes 2^{num_var} number of scalar multiplications over
/// G1:
/// - it proceeds with `num_var` number of rounds,
/// - at round i, we compute an MSM for `2^{num_var - i}` number of G1 elements.
fn open_internal<E: Pairing>(
    prover_param: &MultilinearProverParam<E>,
    polynomial: &MLE<E::ScalarField>,
    point: &[E::ScalarField],
) -> Result<(MultilinearKzgProof<E>, E::ScalarField), PCSError> {
    let open_timer = start_timer!(|| format!("open mle with {} variable", polynomial.num_vars()));

    if polynomial.num_vars() > prover_param.num_vars {
        return Err(PCSError::InvalidParameters(format!(
            "Polynomial num_vars {} exceed the limit {}",
            polynomial.num_vars(),
            prover_param.num_vars
        )));
    }

    if polynomial.num_vars() != point.len() {
        return Err(PCSError::InvalidParameters(format!(
            "Polynomial num_vars {} does not match point len {}",
            polynomial.num_vars(),
            point.len()
        )));
    }

    let nv = polynomial.num_vars();
    // the first `ignored` SRS vectors are unused for opening.
    let ignored = prover_param.num_vars - nv + 1;
    let mut f = polynomial.evals();
    let mut r = FileVec::<E::ScalarField>::new();
    let mut q = FileVec::<E::ScalarField>::new();

    let mut proofs = Vec::new();

    for (i, (&point_at_k, gi)) in point
        .iter()
        .zip(prover_param.powers_of_g[ignored..ignored + nv].iter())
        .enumerate()
    {
        let ith_round = start_timer!(|| format!("{}-th round", i));

        let ith_round_eval = start_timer!(|| format!("{}-th round eval", i));

        // TODO: confirm that FileVec in prior round's q and r are auto dropped via the Drop trait once q and r are assigned new FileVec
        (q, r) = f
            .iter()
            .array_chunks::<2>()
            .map(|chunk| {
                let q_bit = chunk[1] - chunk[0];
                let r_bit = chunk[0] + q_bit * point_at_k;
                (q_bit, r_bit)
            })
            .unzip();

        f = &r;

        end_timer!(ith_round_eval);

        let msm_timer =
            start_timer!(|| format!("msm of size {} at round {}", 1 << (nv - 1 - i), i));

        // let commitment = MultilinearKzgPCS::commit(prover_param, &MLE::from_evals(q, nv - 1 - i))?;

        let commitment = {
            let mut scalars = q.iter();
            let mut bases = gi.evals.iter();
            let mut scalars_buf = Vec::with_capacity(crate::streams::BUFFER_SIZE);
            let mut bases_buf = Vec::with_capacity(crate::streams::BUFFER_SIZE);
            let mut commitment = E::G1::zero();
            while let (Some(scalar_batch), Some(base_batch)) =
                (scalars.next_batch(), bases.next_batch())
            {
                scalars_buf.clear();
                bases_buf.clear();
                scalars_buf.par_extend(scalar_batch);
                bases_buf.par_extend(base_batch);
                commitment += E::G1::msm_unchecked(&bases_buf, &scalars_buf);
            }
            commitment.into_affine()
        };

        proofs.push(commitment);
        end_timer!(msm_timer);

        end_timer!(ith_round);
    }

    // Doesn't consumer the polynomial
    let eval = polynomial.evaluate(point).unwrap();
    end_timer!(open_timer);
    Ok((MultilinearKzgProof { proofs }, eval))
}

/// Verifies that `value` is the evaluation at `x` of the polynomial
/// committed inside `comm`.
///
/// This function takes
/// - num_var number of pairing product.
/// - num_var number of MSM
fn verify_internal<E: Pairing>(
    verifier_param: &MultilinearVerifierParam<E>,
    commitment: &Commitment<E>,
    point: &[E::ScalarField],
    value: &E::ScalarField,
    proof: &MultilinearKzgProof<E>,
) -> Result<bool, PCSError> {
    let verify_timer = start_timer!(|| "verify");
    let num_var = point.len();

    if num_var > verifier_param.num_vars {
        return Err(PCSError::InvalidParameters(format!(
            "point length ({}) exceeds param limit ({})",
            num_var, verifier_param.num_vars
        )));
    }

    let prepare_inputs_timer = start_timer!(|| "prepare pairing inputs");

    let scalar_size = E::ScalarField::MODULUS_BIT_SIZE as usize;
    let window_size = FixedBase::get_mul_window_size(num_var);

    let h_table =
        FixedBase::get_window_table(scalar_size, window_size, verifier_param.h.into_group());
    let h_mul: Vec<E::G2> = FixedBase::msm(scalar_size, window_size, &h_table, point);

    let ignored = verifier_param.num_vars - num_var;
    let h_vec: Vec<_> = (0..num_var)
        .map(|i| verifier_param.h_mask[ignored + i].into_group() - h_mul[i])
        .collect();
    let h_vec: Vec<E::G2Affine> = E::G2::normalize_batch(&h_vec);
    end_timer!(prepare_inputs_timer);

    let pairing_product_timer = start_timer!(|| "pairing product");

    let mut pairings: Vec<_> = proof
        .proofs
        .iter()
        .map(|&x| E::G1Prepared::from(x))
        .zip(h_vec.into_iter().take(num_var).map(E::G2Prepared::from))
        .collect();

    pairings.push((
        E::G1Prepared::from(
            (verifier_param.g.mul(*value) - commitment.0.into_group()).into_affine(),
        ),
        E::G2Prepared::from(verifier_param.h),
    ));

    let ps = pairings.iter().map(|(p, _)| p.clone());
    let hs = pairings.iter().map(|(_, h)| h.clone());

    let res = E::multi_pairing(ps, hs) == ark_ec::pairing::PairingOutput(E::TargetField::one());

    // println!("pairing result: {}", E::multi_pairing(ps, hs));
    // println!("pairing result: {}", ark_ec::pairing::PairingOutput(E::TargetField::one()));

    end_timer!(pairing_product_timer);
    end_timer!(verify_timer);
    Ok(res)
}

#[cfg(test)]
mod tests {
    // use crate::hyperplonk::full_snark::utils::memory_traces;

    use super::*;
    use ark_bls12_381::Bls12_381;
    use ark_ec::pairing::Pairing;
    use ark_std::{test_rng, vec::Vec, UniformRand};

    type E = Bls12_381;
    type Fr = <E as Pairing>::ScalarField;

    fn test_single_helper<R: Rng>(
        params: &MultilinearUniversalParams<E>,
        poly: &MLE<Fr>,
        rng: &mut R,
    ) -> Result<(), PCSError> {
        let nv = poly.num_vars();
        assert_ne!(nv, 0);
        let (ck, vk) = MultilinearKzgPCS::trim(params, None, Some(nv))?;
        let point: Vec<_> = (0..nv).map(|_| Fr::rand(rng)).collect();
        let com = MultilinearKzgPCS::commit(&ck, poly)?;
        let (proof, value) = MultilinearKzgPCS::open(&ck, poly, &point)?;

        assert!(MultilinearKzgPCS::verify(
            &vk, &com, &point, &value, &proof
        )?);

        let value = Fr::rand(rng);
        assert!(!MultilinearKzgPCS::verify(
            &vk, &com, &point, &value, &proof
        )?);

        Ok(())
    }

    #[test]
    fn test_single_commit() -> Result<(), PCSError> {
        let mut rng = test_rng();

        let params = MultilinearKzgPCS::<E>::gen_srs_for_testing(&mut rng, 10)?;

        // normal polynomials
        let poly1 = MLE::rand(8, &mut rng);
        test_single_helper(&params, &poly1, &mut rng)?;

        // single-variate polynomials
        let poly2 = MLE::rand(1, &mut rng);
        test_single_helper(&params, &poly2, &mut rng)?;

        Ok(())
    }

    #[test]
    fn setup_commit_verify_constant_polynomial() {
        let mut rng = test_rng();

        // normal polynomials
        assert!(MultilinearKzgPCS::<E>::gen_srs_for_testing(&mut rng, 0).is_err());
    }
}
