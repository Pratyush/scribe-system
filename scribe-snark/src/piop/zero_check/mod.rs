use std::fmt::Debug;

use crate::piop::{errors::PIOPError, sum_check::SumCheck};
use crate::transcript::IOPTranscript;
use ark_ff::PrimeField;
use ark_std::{end_timer, start_timer};
use mle::{
    eq_eval,
    virtual_polynomial::{VPAuxInfo, VirtualPolynomial},
};
use scribe_streams::serialize::RawPrimeField;

use super::sum_check::SumCheckProof;

/// A zero check IOP subclaim for `f(x)` consists of the following:
///   - the initial challenge vector r which is used to build eq(x, r) in
///     SumCheck
///   - the random vector `v` to be evaluated
///   - the claimed evaluation of `f(v)`
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ZeroCheckSubClaim<F: PrimeField> {
    // the evaluation point
    pub point: Vec<F>,
    /// the expected evaluation
    pub expected_evaluation: F,
    // the initial challenge r which is used to build eq(x, r)
    pub init_challenge: Vec<F>,
}

/// A ZeroCheck for `f(x)` proves that `f(x) = 0` for all `x \in {0,1}^num_vars`
/// It is derived from SumCheck.
pub struct ZeroCheck<F: RawPrimeField>(std::marker::PhantomData<F>);

pub type ZeroCheckProof<F> = SumCheckProof<F>;

impl<F: RawPrimeField> ZeroCheck<F> {
    /// Initialize the system with a transcript
    ///
    /// This function is optional -- in the case where a ZeroCheck is
    /// an building block for a more complex protocol, the transcript
    /// may be initialized by this complex protocol, and passed to the
    /// ZeroCheck prover/verifier.
    pub fn init_transcript() -> IOPTranscript<F> {
        IOPTranscript::<F>::new(b"Initializing ZeroCheck transcript")
    }

    /// initialize the prover to argue for the sum of polynomial over
    /// {0,1}^`num_vars` is zero.
    pub fn prove(
        poly: &VirtualPolynomial<F>,
        transcript: &mut IOPTranscript<F>,
    ) -> Result<ZeroCheckProof<F>, PIOPError> {
        let f_hat = Self::prove_emit_virtual_poly(poly, transcript)?;
        SumCheck::<F>::prove(&f_hat, transcript)
    }

    pub fn prove_emit_virtual_poly(
        poly: &VirtualPolynomial<F>,
        transcript: &mut IOPTranscript<F>,
    ) -> Result<VirtualPolynomial<F>, PIOPError> {
        let start = start_timer!(|| "zero check prove");

        let length = poly.aux_info.num_variables;
        let r = transcript.get_and_append_challenge_vectors(b"0check r", length)?;
        let f_hat = poly.build_f_hat(r.as_ref())?;
        end_timer!(start);
        Ok(f_hat)
    }

    /// verify the claimed sum using the proof
    pub fn verify(
        proof: &ZeroCheckProof<F>,
        fx_aux_info: &VPAuxInfo<F>,
        transcript: &mut IOPTranscript<F>,
    ) -> Result<ZeroCheckSubClaim<F>, PIOPError> {
        let start = start_timer!(|| "zero check verify");

        // check that the sum is zero
        let initial_sum = proof.proofs[0].evaluations[0] + proof.proofs[0].evaluations[1];
        if initial_sum != F::zero() {
            end_timer!(start);
            eprintln!("zero check: sum {initial_sum} is not zero");
            return Err(PIOPError::InvalidProof(format!(
                "zero check: sum {initial_sum} is not zero",
            )));
        }

        // generate `r` and pass it to the caller for correctness check
        let length = fx_aux_info.num_variables;
        let r = transcript.get_and_append_challenge_vectors(b"0check r", length)?;

        // hat_fx's max degree is increased by eq(x, r).degree() which is 1
        let mut hat_fx_aux_info = fx_aux_info.clone();
        hat_fx_aux_info.max_degree += 1;
        let sum_subclaim = SumCheck::<F>::verify(F::zero(), proof, &hat_fx_aux_info, transcript)?;

        // expected_eval = sumcheck.expect_eval/eq(v, r)
        // where v = sum_check_sub_claim.point
        let eq_x_r_eval = eq_eval(&sum_subclaim.point, &r).ok_or(
            mle::errors::ArithError::InvalidParameters("eq_eval failed".to_string()),
        )?;
        let expected_evaluation = sum_subclaim.expected_evaluation / eq_x_r_eval;

        end_timer!(start);
        Ok(ZeroCheckSubClaim {
            point: sum_subclaim.point,
            expected_evaluation,
            init_challenge: r,
        })
    }
}

#[cfg(test)]
mod test {

    use super::ZeroCheck;
    use crate::piop::errors::PIOPError;
    use ark_bls12_381::Fr;
    use ark_std::rand::rngs::StdRng;
    use ark_std::rand::SeedableRng;
    use mle::VirtualPolynomial;

    fn test_zerocheck(
        nv: usize,
        num_multiplicands_range: (usize, usize),
        num_products: usize,
    ) -> Result<(), PIOPError> {
        let seed = [
            1, 0, 0, 0, 23, 0, 0, 0, 200, 1, 0, 0, 210, 30, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0,
        ];
        let mut rng = StdRng::from_seed(seed);

        {
            // good path: zero virtual poly
            let poly =
                VirtualPolynomial::rand_zero(nv, num_multiplicands_range, num_products, &mut rng)?;

            let mut transcript = ZeroCheck::<Fr>::init_transcript();
            transcript.append_message(b"testing", b"initializing transcript for testing")?;

            let proof = ZeroCheck::<Fr>::prove(&poly, &mut transcript)?;

            let poly_info = poly.aux_info.clone();
            let mut transcript = ZeroCheck::<Fr>::init_transcript();
            transcript.append_message(b"testing", b"initializing transcript for testing")?;
            let zero_subclaim = ZeroCheck::<Fr>::verify(&proof, &poly_info, &mut transcript)?;

            let evaluated_point = poly.evaluate(&zero_subclaim.point).unwrap();
            assert!(
                evaluated_point == zero_subclaim.expected_evaluation,
                "wrong subclaim"
            );
        }

        {
            // bad path: random virtual poly whose sum is not zero
            let (poly, _sum) =
                VirtualPolynomial::<Fr>::rand(nv, num_multiplicands_range, num_products, &mut rng)?;

            let mut transcript = ZeroCheck::<Fr>::init_transcript();
            transcript.append_message(b"testing", b"initializing transcript for testing")?;
            let proof = ZeroCheck::<Fr>::prove(&poly, &mut transcript)?;

            let poly_info = poly.aux_info.clone();
            let mut transcript = ZeroCheck::<Fr>::init_transcript();
            transcript.append_message(b"testing", b"initializing transcript for testing")?;

            assert!(ZeroCheck::<Fr>::verify(&proof, &poly_info, &mut transcript).is_err());
        }

        Ok(())
    }

    #[test]
    fn trivial_polynomial() -> Result<(), PIOPError> {
        let nv = 1;
        let num_multiplicands_range = (1, 2);
        let num_products = 1;

        test_zerocheck(nv, num_multiplicands_range, num_products)
    }
    #[test]
    fn normal_polynomial() -> Result<(), PIOPError> {
        for nv in 9..20 {
            let num_multiplicands_range = (4, 9);
            let num_products = 4;
            test_zerocheck(nv, num_multiplicands_range, num_products)?
        }
        Ok(())
    }

    #[test]
    fn zero_polynomial_should_error() -> Result<(), PIOPError> {
        let nv = 0;
        let num_multiplicands_range = (4, 13);
        let num_products = 5;

        assert!(test_zerocheck(nv, num_multiplicands_range, num_products).is_err());
        Ok(())
    }
}
