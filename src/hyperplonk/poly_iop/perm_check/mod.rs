use crate::{
    hyperplonk::{
        arithmetic::virtual_polynomial::{VPAuxInfo, VirtualPolynomial},
        poly_iop::{
            errors::PolyIOPErrors,
            structs::{IOPProof, IOPProverState, IOPVerifierState},
            PolyIOP,
        },
        transcript::IOPTranscript,
    },
    read_write::DenseMLPolyStream,
};
// use arithmetic::{VPAuxInfo, VirtualPolynomial};
use ark_ff::PrimeField;
// use ark_poly::DenseMultilinearExtension;
use ark_std::{end_timer, start_timer, Zero};
use std::{fmt::Debug, io::Seek, sync::Arc};

use super::zero_check::ZeroCheck;
// use transcript::IOPTranscript;

mod util;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PermutationCheckSubClaim<F: PrimeField, ZC: ZeroCheck<F>> {
    pub zero_check_sub_claim: ZC::ZeroCheckSubClaim,
}

pub trait PermutationCheck<F: PrimeField>: ZeroCheck<F> {
    type PermutationCheckSubClaim: Clone + Debug + Default + PartialEq;
    type PermutationCheckProof: Clone + Debug + Default + PartialEq;

    /// Initialize the system with a transcript
    ///
    /// This function is optional -- in the case where a ProductCheck is
    /// an building block for a more complex protocol, the transcript
    /// may be initialized by this complex protocol, and passed to the
    /// ProductCheck prover/verifier.
    fn init_transcript() -> Self::Transcript;

    /// Proves that two lists of n-variate multilinear polynomials `(f1, f2,
    /// ..., fk)` and `(g1, ..., gk)` satisfy:
    ///   \prod_{x \in {0,1}^n} f1(x) * ... * fk(x)
    /// = \prod_{x \in {0,1}^n} g1(x) * ... * gk(x)
    ///
    /// Inputs:
    /// - fxs: the list of numerator multilinear polynomial
    /// - gxs: the list of denominator multilinear polynomial
    /// - transcript: the IOP transcript
    /// - pk: PCS committing key
    ///
    /// Outputs
    /// - the product check proof
    /// - the product polynomial (used for testing)
    /// - the fractional polynomial (used for testing)
    ///
    /// Cost: O(N)
    #[allow(clippy::type_complexity)]
    fn prove(
        // pcs_param: &PCS::ProverParam,
        p: Self::MultilinearExtension,
        q: Self::MultilinearExtension,
        pi: Self::MultilinearExtension,
        transcript: &mut IOPTranscript<F>,
    ) -> Result<
        (
            Self::PermutationCheckProof,
            // Self::MultilinearExtension,
            // Self::MultilinearExtension,
        ),
        PolyIOPErrors,
    >;

    /// Verify that for witness multilinear polynomials (f1, ..., fk, g1, ...,
    /// gk) it holds that
    ///      `\prod_{x \in {0,1}^n} f1(x) * ... * fk(x)
    ///     = \prod_{x \in {0,1}^n} g1(x) * ... * gk(x)`
    fn verify(
        proof: &Self::PermutationCheckProof,
        aux_info: &VPAuxInfo<F>,
        transcript: &mut Self::Transcript,
    ) -> Result<Self::PermutationCheckSubClaim, PolyIOPErrors>;
}

/// A product check proof consists of
/// - a zerocheck proof
/// - a product polynomial commitment
/// - a polynomial commitment for the fractional polynomial
#[derive(Clone, Debug, Default, PartialEq)]
pub struct PermutationCheckProof<
    // E: Pairing,
    // PCS: PolynomialCommitmentScheme<E>,
    F: PrimeField,
    ZC: ZeroCheck<F>,
> {
    pub zero_check_proof: ZC::ZeroCheckProof, // sumcheck proof
                                              // pub prod_x_comm: PCS::Commitment,
                                              // pub frac_comm: PCS::Commitment,
}

impl<F: PrimeField> PermutationCheck<F> for PolyIOP<F>
where
// E: Pairing,
// PCS: PolynomialCommitmentScheme<E, Polynomial = Arc<DenseMultilinearExtension<E::ScalarField>>>,
{
    type PermutationCheckSubClaim = PermutationCheckSubClaim<F, Self>;
    type PermutationCheckProof = PermutationCheckProof<F, Self>;

    fn init_transcript() -> Self::Transcript {
        IOPTranscript::<F>::new(b"Initializing PermuCheck transcript")
    }

    fn prove(
        // pcs_param: &PCS::ProverParam,
        mut p: Self::MultilinearExtension,
        mut q: Self::MultilinearExtension,
        mut pi: Self::MultilinearExtension,
        transcript: &mut IOPTranscript<F>,
    ) -> Result<
        (
            Self::PermutationCheckProof,
            // Self::MultilinearExtension,
            // Self::MultilinearExtension,
        ),
        PolyIOPErrors,
    > {
        let start = start_timer!(|| "perm_check prove");

        // assume that p, q, and pi have equal length

        // get challenge alpha
        let alpha = transcript.get_and_append_challenge(b"alpha r")?;

        // compute the fractional polynomials h_p and h_q
        let (mut h_p, mut h_q) = util::compute_frac_poly(p, q, pi, alpha).unwrap();

        unimplemented!()
    }

    fn verify(
        proof: &Self::PermutationCheckProof,
        aux_info: &VPAuxInfo<F>,
        transcript: &mut Self::Transcript,
    ) -> Result<Self::PermutationCheckSubClaim, PolyIOPErrors> {
        unimplemented!()
    }
}
