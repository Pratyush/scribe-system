pub(crate) mod batching;
pub mod srs;
pub(crate) mod util;
use crate::pc::pst13::batching::multi_open_internal;
use crate::pc::StructuredReferenceString;
use crate::pc::{structs::Commitment, PCError, PCScheme};
use crate::transcript::IOPTranscript;
use ark_ec::{
    pairing::Pairing,
    scalar_mul::{fixed_base::FixedBase, variable_base::VariableBaseMSM},
    AffineRepr, CurveGroup,
};
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{
    borrow::Borrow, end_timer, format, marker::PhantomData, rand::Rng, start_timer, vec::Vec, One,
    Zero,
};
use mle::MLE;
use rayon::iter::ParallelExtend;
use scribe_streams::iterator::BatchedIterator;
use scribe_streams::serialize::{RawAffine, RawPrimeField};
use srs::{CommitterKey, VerifierKey, SRS};
use std::ops::Mul;

use self::batching::{batch_verify_internal, BatchProof};

/// KZG Polynomial Commitment Scheme on multilinear polynomials.
pub struct PST13<E: Pairing> {
    #[doc(hidden)]
    phantom: PhantomData<E>,
}

#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug, PartialEq, Eq)]
/// proof of opening
pub struct MultilinearKzgProof<E: Pairing> {
    /// Evaluation of quotients
    pub proofs: Vec<E::G1Affine>,
}

impl<E: Pairing> PCScheme<E> for PST13<E>
where
    E::G1Affine: RawAffine,
    E::ScalarField: RawPrimeField,
{
    // Parameters
    type CommitterKey = CommitterKey<E>;
    type VerifierKey = VerifierKey<E>;
    type SRS = SRS<E>;
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
    fn gen_srs_for_testing<R: Rng>(rng: &mut R, log_size: usize) -> Result<Self::SRS, PCError> {
        SRS::<E>::gen_srs_for_testing(rng, log_size)
    }

    fn gen_fake_srs_for_testing<R: Rng>(
        rng: &mut R,
        log_size: usize,
    ) -> Result<Self::SRS, PCError> {
        SRS::<E>::gen_fake_srs_for_testing(rng, log_size)
    }

    /// Trim the universal parameters to specialize the public parameters.
    /// Input both `supported_log_degree` for univariate and
    /// `supported_num_vars` for multilinear.
    fn trim(
        srs: impl Borrow<Self::SRS>,
        supported_num_vars: usize,
    ) -> Result<(Self::CommitterKey, Self::VerifierKey), PCError> {
        srs.borrow().trim(supported_num_vars)
    }

    /// Generate a commitment for a polynomial.
    ///
    /// This function takes `2^num_vars` number of scalar multiplications over
    /// G1.
    fn commit(
        ck: impl Borrow<Self::CommitterKey>,
        poly: &Self::Polynomial,
    ) -> Result<Self::Commitment, PCError> {
        let prover_param = ck.borrow();
        let poly_num_vars = poly.num_vars();

        let commit_timer = start_timer!(|| format!("commit poly nv = {}", poly_num_vars));
        if prover_param.num_vars < poly_num_vars {
            return Err(PCError::InvalidParameters(format!(
                "MLE length ({}) exceeds param limit ({})",
                poly_num_vars, prover_param.num_vars
            )));
        }
        let ignored = prover_param.num_vars - poly_num_vars;

        let commitment = {
            let mut poly_evals = poly.evals().iter();
            let mut srs = prover_param.powers_of_g[ignored].iter();
            let mut f_buf = Vec::with_capacity(scribe_streams::BUFFER_SIZE);
            let mut g_buf = Vec::with_capacity(scribe_streams::BUFFER_SIZE);
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
        ck: impl Borrow<Self::CommitterKey>,
        polynomial: &Self::Polynomial,
        point: &Self::Point,
    ) -> Result<(Self::Proof, Self::Evaluation), PCError> {
        open_internal(ck.borrow(), polynomial, point.as_ref())
    }

    /// Input a list of multilinear extensions, and a same number of points, and
    /// a transcript, compute a multi-opening for all the polynomials.
    fn multi_open(
        ck: impl Borrow<Self::CommitterKey>,
        polynomials: &[Self::Polynomial],
        points: &[Self::Point],
        evals: &[Self::Evaluation],
        transcript: &mut IOPTranscript<E::ScalarField>,
    ) -> Result<BatchProof<E, Self>, PCError> {
        multi_open_internal(ck.borrow(), polynomials, points, evals, transcript)
    }

    /// Verifies that `value` is the evaluation at `x` of the polynomial
    /// committed inside `comm`.
    ///
    /// This function takes
    /// - num_var number of pairing product.
    /// - num_var number of MSM
    fn verify(
        vk: &Self::VerifierKey,
        commitment: &Self::Commitment,
        point: &Self::Point,
        value: &E::ScalarField,
        proof: &Self::Proof,
    ) -> Result<bool, PCError> {
        verify_internal(vk, commitment, point, value, proof)
    }

    /// Verifies that `value_i` is the evaluation at `x_i` of the polynomial
    /// `poly_i` committed inside `comm`.
    fn batch_verify(
        vk: &Self::VerifierKey,
        commitments: &[Self::Commitment],
        points: &[Self::Point],
        batch_proof: &Self::BatchProof,
        transcript: &mut IOPTranscript<E::ScalarField>,
    ) -> Result<bool, PCError> {
        batch_verify_internal(vk, commitments, points, batch_proof, transcript)
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
    prover_param: &CommitterKey<E>,
    polynomial: &MLE<E::ScalarField>,
    point: &[E::ScalarField],
) -> Result<(MultilinearKzgProof<E>, E::ScalarField), PCError>
where
    E::G1Affine: RawAffine,
    E::ScalarField: RawPrimeField,
{
    let open_timer = start_timer!(|| format!("open mle with {} variable", polynomial.num_vars()));

    if polynomial.num_vars() > prover_param.num_vars {
        return Err(PCError::InvalidParameters(format!(
            "Polynomial num_vars {} exceed the limit {}",
            polynomial.num_vars(),
            prover_param.num_vars
        )));
    }

    if polynomial.num_vars() != point.len() {
        return Err(PCError::InvalidParameters(format!(
            "Polynomial num_vars {} does not match point len {}",
            polynomial.num_vars(),
            point.len()
        )));
    }

    let nv = polynomial.num_vars();
    // the first `ignored` SRS vectors are unused for opening.
    let ignored = prover_param.num_vars - nv + 1;
    let mut f = polynomial.evals();
    let mut r;
    let mut q;

    let mut proofs = Vec::new();

    let mut scalars_buf = Vec::with_capacity(scribe_streams::BUFFER_SIZE);
    let mut bases_buf = Vec::with_capacity(scribe_streams::BUFFER_SIZE);
    for (_i, (&point_at_k, gi)) in point
        .iter()
        .zip(prover_param.powers_of_g[ignored..ignored + nv].iter())
        .enumerate()
    {
        let ith_round = start_timer!(|| format!("{_i}-th round"));

        let ith_round_eval = start_timer!(|| format!("{_i}-th round eval"));

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
            start_timer!(|| format!("msm of size {} at round {}", 1 << (nv - 1 - _i), _i));

        // let commitment = PST13::commit(prover_param, &MLE::from_evals(q, nv - 1 - i))?;

        let commitment = {
            let mut scalars = q.iter();
            let mut bases = gi.iter();
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
    vk: &VerifierKey<E>,
    commitment: &Commitment<E>,
    point: &[E::ScalarField],
    value: &E::ScalarField,
    proof: &MultilinearKzgProof<E>,
) -> Result<bool, PCError> {
    let verify_timer = start_timer!(|| "verify");
    let num_var = point.len();

    if num_var > vk.num_vars {
        return Err(PCError::InvalidParameters(format!(
            "point length ({}) exceeds param limit ({})",
            num_var, vk.num_vars
        )));
    }

    let prepare_inputs_timer = start_timer!(|| "prepare pairing inputs");

    let scalar_size = E::ScalarField::MODULUS_BIT_SIZE as usize;
    let window_size = FixedBase::get_mul_window_size(num_var);

    let h_table = FixedBase::get_window_table(scalar_size, window_size, vk.h.into_group());
    let h_mul: Vec<E::G2> = FixedBase::msm(scalar_size, window_size, &h_table, point);

    let ignored = vk.num_vars - num_var;
    let h_vec: Vec<_> = (0..num_var)
        .map(|i| vk.h_mask[ignored + i].into_group() - h_mul[i])
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
        E::G1Prepared::from((vk.g.mul(*value) - commitment.0.into_group()).into_affine()),
        E::G2Prepared::from(vk.h),
    ));

    let ps = pairings.iter().map(|(p, _)| p.clone());
    let hs = pairings.iter().map(|(_, h)| h.clone());

    let res = E::multi_pairing(ps, hs) == ark_ec::pairing::PairingOutput(E::TargetField::one());

    end_timer!(pairing_product_timer);
    end_timer!(verify_timer);
    Ok(res)
}

#[cfg(test)]
mod tests {
    // use crate::full_snark::utils::memory_traces;

    use super::*;
    use ark_bls12_381::Bls12_381;
    use ark_ec::pairing::Pairing;
    use ark_std::{test_rng, vec::Vec, UniformRand};

    type E = Bls12_381;
    type Fr = <E as Pairing>::ScalarField;

    fn test_single_helper<R: Rng>(
        params: &SRS<E>,
        poly: &MLE<Fr>,
        rng: &mut R,
    ) -> Result<(), PCError> {
        let nv = poly.num_vars();
        assert_ne!(nv, 0);
        let (ck, vk) = PST13::trim(params, nv)?;
        let point: Vec<_> = (0..nv).map(|_| Fr::rand(rng)).collect();
        let com = PST13::commit(&ck, poly)?;
        let (proof, value) = PST13::open(&ck, poly, &point)?;

        assert!(PST13::verify(&vk, &com, &point, &value, &proof)?);

        let value = Fr::rand(rng);
        assert!(!PST13::verify(&vk, &com, &point, &value, &proof)?);

        Ok(())
    }

    #[test]
    fn test_single_commit() -> Result<(), PCError> {
        let mut rng = test_rng();

        let params = PST13::<E>::gen_srs_for_testing(&mut rng, 10)?;

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
        assert!(PST13::<E>::gen_srs_for_testing(&mut rng, 0).is_err());
    }
}
