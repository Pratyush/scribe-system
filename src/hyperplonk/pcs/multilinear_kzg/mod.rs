pub(crate) mod batching;
pub(crate) mod srs;
pub(crate) mod util;
use crate::hyperplonk::pcs::StructuredReferenceString;

use crate::hyperplonk::pcs::{prelude::Commitment, PCSError, PolynomialCommitmentScheme};
use crate::hyperplonk::transcript::IOPTranscript;
use crate::read_write::DenseMLPolyStream;
use crate::read_write::ReadWriteStream;
use ark_ec::{
    pairing::Pairing,
    scalar_mul::{fixed_base::FixedBase, variable_base::VariableBaseMSM},
    AffineRepr, CurveGroup,
};
use ark_ff::{Field, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{
    borrow::Borrow, end_timer, format, marker::PhantomData, rand::Rng, start_timer,
    string::ToString, sync::Arc, vec::Vec, One, Zero,
};
use srs::{MultilinearProverParam, MultilinearUniversalParams, MultilinearVerifierParam};
use std::{ops::Mul, sync::Mutex};

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
    type Polynomial = Arc<Mutex<DenseMLPolyStream<E::ScalarField>>>;
    type Point = Vec<E::ScalarField>;
    type Evaluation = E::ScalarField;
    // Commitments and proofs
    type Commitment = Commitment<E>;
    type Proof = MultilinearKzgProof<E>;

    /// Build SRS for testing.
    ///
    /// - For univariate polynomials, `log_size` is the log of maximum degree.
    /// - For multilinear polynomials, `log_size` is the number of variables.
    ///
    /// WARNING: THIS FUNCTION IS FOR TESTING PURPOSE ONLY.
    /// THE OUTPUT SRS SHOULD NOT BE USED IN PRODUCTION.
    fn gen_srs_for_testing<R: Rng>(rng: &mut R, log_size: usize) -> Result<Self::SRS, PCSError> {
        MultilinearUniversalParams::<E>::gen_srs_for_testing(rng, log_size)
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
        let mut poly_lock = poly.lock().unwrap();
        let poly_num_vars = poly_lock.num_vars;

        let commit_timer: ark_std::perf_trace::TimerInfo =
            start_timer!(|| format!("commit poly nv = {}", poly_num_vars));
        if prover_param.num_vars < poly_num_vars {
            return Err(PCSError::InvalidParameters(format!(
                "MlE length ({}) exceeds param limit ({})",
                poly_num_vars, prover_param.num_vars
            )));
        }
        let ignored = prover_param.num_vars - poly_num_vars;

        let batch_size = 1 << 20; // Define the batch size.
        let mut final_commitment = E::G1::zero(); // Start with the identity element.
        let mut total_scalars_processed = 0usize; // Track the total number of scalars processed.

        let mut batch_scalars = Vec::with_capacity(batch_size);
        while let Some(scalar) = poly_lock.read_next() {
            batch_scalars.push(scalar);
            if batch_scalars.len() == batch_size {
                // Process the current batch
                let evals_slice = &prover_param.powers_of_g[ignored].evals
                    [total_scalars_processed..total_scalars_processed + batch_size];
                let commitment_batch = E::G1::msm_unchecked(evals_slice, &batch_scalars);
                final_commitment += commitment_batch;

                total_scalars_processed += batch_size; // Update the total number of scalars processed
                batch_scalars.clear(); // Reset for next batch
            }
        }

        // Process any remaining scalars in the last batch
        if !batch_scalars.is_empty() {
            let evals_slice = &prover_param.powers_of_g[ignored].evals
                [total_scalars_processed..total_scalars_processed + batch_scalars.len()];
            let commitment_batch = E::G1::msm_unchecked(evals_slice, &batch_scalars);
            final_commitment += commitment_batch;
        }

        let final_commitment = final_commitment.into_affine();

        poly_lock.read_restart();

        end_timer!(commit_timer);
        Ok(Commitment(final_commitment))
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
        open_internal(prover_param.borrow(), polynomial.clone(), point)
    }

    // this is the multi poly single point version
    /// Input a list of multilinear extensions, and a same number of points, and
    /// a transcript, compute a multi-opening for all the polynomials.
    fn multi_open_single_point(
        prover_param: impl Borrow<Self::ProverParam>,
        polynomials: &[Self::Polynomial],
        point: Self::Point,
        transcript: &mut IOPTranscript<E::ScalarField>,
    ) -> Result<(Self::Proof, E::ScalarField), PCSError> {
        let alpha = transcript.get_and_append_challenge(b"opening rlc").unwrap();

        // assert that poly has same num_vars as points length
        let num_vars = polynomials[0].lock().unwrap().num_vars;
        assert_eq!(num_vars, point.len());

        // create random linear combination of polynomials, a new stream in the form of poly0 + alpha * poly1 + alpha^2 * poly2 + ...
        let mut poly = DenseMLPolyStream::<E::ScalarField>::new(num_vars, None, None);

        // create a vector of 1, alpha, alpha^2, ..., alpha^polynomials.len()
        let alphas = (0..polynomials.len())
            .map(|i| alpha.pow(&[i as u64]))
            .collect::<Vec<E::ScalarField>>();

        // lock all polynomials and make sure they all have the same num_vars
        let mut polys_locks = polynomials
            .iter()
            .map(|p| p.lock().unwrap())
            .collect::<Vec<_>>();
        for poly_lock in &polys_locks {
            assert_eq!(
                poly_lock.num_vars, num_vars,
                "All polynomials must have the same number of variables."
            );
        }

        // for each locked polynomial, read the next element using polynomial_lock.read_next()
        // if the return value is Some(), multiply it to the corresponding alpha and sum it
        // write the sum to the result poly using poly.write_next_unchecked(sum)
        // note that there's a sum for each value read from the polynomials, so the result poly will have the same length as the source polynomials
        for _ in 0..(1 << num_vars) {
            let mut sum = E::ScalarField::zero();
            for (i, poly_lock) in polys_locks.iter_mut().enumerate() {
                if let Some(val) = poly_lock.read_next() {
                    // Multiply it to the corresponding alpha and sum it
                    sum += val * &alphas[i];
                }
            }
            // Write the sum to the result poly
            poly.write_next_unchecked(sum);
        }

        poly.swap_read_write();

        open_internal(prover_param.borrow(), Arc::new(Mutex::new(poly)), &point)
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
    polynomial: Arc<Mutex<DenseMLPolyStream<E::ScalarField>>>,
    point: &[E::ScalarField],
) -> Result<(MultilinearKzgProof<E>, E::ScalarField), PCSError> {
    let mut poly_lock = polynomial.lock().unwrap();
    let nv = poly_lock.num_vars;
    let open_timer = start_timer!(|| format!("open mle with {} variable", nv));

    if nv > prover_param.num_vars {
        return Err(PCSError::InvalidParameters(format!(
            "Polynomial num_vars {} exceed the limit {}",
            nv, prover_param.num_vars
        )));
    }

    if nv != point.len() {
        return Err(PCSError::InvalidParameters(format!(
            "Polynomial num_vars {} does not match point len {}",
            nv,
            point.len()
        )));
    }

    // the first `ignored` SRS vectors are unused for opening.
    let ignored = prover_param.num_vars - nv + 1;
    // let mut f = polynomial.to_evaluations();

    let mut proofs = Vec::new();

    for (i, (&point_at_k, gi)) in point
        .iter()
        .zip(prover_param.powers_of_g[ignored..ignored + nv].iter())
        .enumerate()
    {
        let ith_round = start_timer!(|| format!("{}-th round", i));

        // evaluation and commit together
        let batch_size = 1 << 20; // Define the batch size.
        let mut final_commitment = E::G1::zero(); // Start with the identity element.
        let mut total_scalars_processed = 0usize; // Track the total number of scalars processed.

        let mut batch_scalars = Vec::with_capacity(batch_size);
        while let (Some(poly_even), Some(poly_odd)) = (poly_lock.read_next(), poly_lock.read_next())
        {
            let q = poly_odd - poly_even;
            batch_scalars.push(q);
            poly_lock.write_next(poly_even + (q * point_at_k));
            if batch_scalars.len() == batch_size {
                // Process the current batch
                let evals_slice =
                    &gi.evals[total_scalars_processed..total_scalars_processed + batch_size];
                let commitment_batch = E::G1::msm_unchecked(evals_slice, &batch_scalars);
                final_commitment += commitment_batch;

                total_scalars_processed += batch_size; // Update the total number of scalars processed
                batch_scalars.clear(); // Reset for next batch
            }
        }

        // Process any remaining scalars in the last batch
        if !batch_scalars.is_empty() {
            let evals_slice =
                &gi.evals[total_scalars_processed..total_scalars_processed + batch_scalars.len()];
            let commitment_batch = E::G1::msm_unchecked(evals_slice, &batch_scalars);
            final_commitment += commitment_batch;
        }

        let final_commitment = final_commitment.into_affine();

        proofs.push(final_commitment);

        poly_lock.decrement_num_vars();
        poly_lock.swap_read_write();

        end_timer!(ith_round);
    }

    assert_eq!(poly_lock.num_vars, 0);

    let eval = poly_lock.read_next().unwrap();
    poly_lock.read_restart();

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

    if res {
        println!("pairing verify success");
    }

    end_timer!(pairing_product_timer);
    end_timer!(verify_timer);
    Ok(res)
}

#[cfg(test)]
mod tests {
    use crate::hyperplonk::full_snark::utils::memory_traces;

    use super::*;
    use ark_bls12_381::Bls12_381;
    use ark_ec::pairing::Pairing;
    use ark_std::{test_rng, vec::Vec, UniformRand};

    type E = Bls12_381;
    type Fr = <E as Pairing>::ScalarField;

    fn test_single_helper<R: Rng>(
        params: &MultilinearUniversalParams<E>,
        poly: &Arc<Mutex<DenseMLPolyStream<Fr>>>,
        rng: &mut R,
    ) -> Result<(), PCSError> {
        let nv = poly.lock().unwrap().num_vars;
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
        env_logger::init();
        memory_traces();

        let mut rng = test_rng();

        let SUPPORTED_DEGREE = 10;
        // let params = MultilinearKzgPCS::<E>::gen_fake_srs_for_testing(&mut rng, SUPPORTED_DEGREE)?;
        let params = MultilinearKzgPCS::<E>::gen_srs_for_testing(&mut rng, SUPPORTED_DEGREE)?;

        for i in 5..(SUPPORTED_DEGREE + 1) {
            let poly1 = Arc::new(Mutex::new(DenseMLPolyStream::<Fr>::rand(i, &mut rng)));
            test_single_helper(&params, &poly1, &mut rng)?;
        }

        Ok(())
    }

    #[test]
    fn setup_commit_verify_constant_polynomial() {
        let mut rng = test_rng();

        // normal polynomials
        assert!(MultilinearKzgPCS::<E>::gen_srs_for_testing(&mut rng, 0).is_err());
    }
}
