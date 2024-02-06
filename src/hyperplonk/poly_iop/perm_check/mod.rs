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
    read_write::{DenseMLPolyStream, ReadWriteStream},
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
    ) -> Result<Self::PermutationCheckProof, PolyIOPErrors>;

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

impl<F: PrimeField> PermutationCheck<F> for PolyIOP<F>
where
// E: Pairing,
// PCS: PolynomialCommitmentScheme<E, Polynomial = Arc<DenseMultilinearExtension<E::ScalarField>>>,
{
    type PermutationCheckSubClaim = PermutationCheckSubClaim<F, Self>;
    type PermutationCheckProof = Self::ZeroCheckProof;

    fn init_transcript() -> Self::Transcript {
        IOPTranscript::<F>::new(b"Initializing PermuCheck transcript")
    }

    fn prove(
        // pcs_param: &PCS::ProverParam,
        mut p: Self::MultilinearExtension,
        mut q: Self::MultilinearExtension,
        mut pi: Self::MultilinearExtension,
        transcript: &mut IOPTranscript<F>,
    ) -> Result<Self::PermutationCheckProof, PolyIOPErrors> {
        let start = start_timer!(|| "perm_check prove");

        // assume that p, q, and pi have equal length

        // get challenge alpha for h_p = 1/(p + alpha * pi) and h_q = 1/(q + alpha)
        let alpha = transcript.get_and_append_challenge(b"alpha")?;

        // compute the fractional polynomials h_p and h_q
        let (mut h_p, mut h_q) = util::compute_frac_poly(&p, &q, &pi, alpha).unwrap();

        // get challenge r for batch zero check of t_1 + r * t_2, where t_1 = h_p * (p + alpha * pi) - 1 and t_2 = h_q * (q + alpha) - 1
        let r = transcript.get_and_append_challenge(b"r")?;

        // poly = t_1 + r * t_2 = h_p * (p + alpha * pi) - 1 + r * (h_q * (q + alpha) - 1)
        let poly = VirtualPolynomial::build_perm_check_poly(h_p, h_q, p, q, pi, alpha, r).unwrap();

        let res = <PolyIOP<F> as ZeroCheck<F>>::prove(&poly, transcript)?;

        Ok(res)
    }

    fn verify(
        proof: &Self::PermutationCheckProof,
        aux_info: &VPAuxInfo<F>,
        transcript: &mut Self::Transcript,
    ) -> Result<Self::PermutationCheckSubClaim, PolyIOPErrors> {
        unimplemented!()
    }
}

#[cfg(test)]
mod test {

    use super::ZeroCheck;
    use crate::hyperplonk::arithmetic::virtual_polynomial::VirtualPolynomial;
    use crate::hyperplonk::poly_iop::{errors::PolyIOPErrors, PolyIOP};
    // use ark_bls12_381::Fr;
    use ark_std::test_rng;
    use ark_test_curves::bls12_381::Fr;

    fn test_zerocheck(
        nv: usize,
        num_multiplicands_range: (usize, usize),
        num_products: usize,
    ) -> Result<(), PolyIOPErrors> {
        let mut rng = test_rng();

        {
            // good path: zero virtual poly
            let poly =
                VirtualPolynomial::rand_zero(nv, num_multiplicands_range, num_products, &mut rng)?;

            let mut transcript = <PolyIOP<Fr> as ZeroCheck<Fr>>::init_transcript();
            transcript.append_message(b"testing", b"initializing transcript for testing")?;
            // print products of poly
            // poly.products.iter().for_each(|p| {
            //     println!("test_zero_check before prove product: {:?}", p);
            // });
            let proof = <PolyIOP<Fr> as ZeroCheck<Fr>>::prove(&poly, &mut transcript)?;

            let poly_info = poly.aux_info.clone();
            let mut transcript = <PolyIOP<Fr> as ZeroCheck<Fr>>::init_transcript();
            transcript.append_message(b"testing", b"initializing transcript for testing")?;
            let zero_subclaim =
                <PolyIOP<Fr> as ZeroCheck<Fr>>::verify(&proof, &poly_info, &mut transcript)?;

            let evaluated_point = poly
                .evaluate(std::slice::from_ref(
                    &zero_subclaim.point[poly_info.num_variables - 1],
                ))
                .unwrap();
            assert!(
                evaluated_point == zero_subclaim.expected_evaluation,
                "wrong subclaim"
            );
        }

        {
            // bad path: random virtual poly whose sum is not zero
            let (poly, _sum) =
                VirtualPolynomial::<Fr>::rand(nv, num_multiplicands_range, num_products, &mut rng)?;

            let mut transcript = <PolyIOP<Fr> as ZeroCheck<Fr>>::init_transcript();
            transcript.append_message(b"testing", b"initializing transcript for testing")?;
            let proof = <PolyIOP<Fr> as ZeroCheck<Fr>>::prove(&poly, &mut transcript)?;

            let poly_info = poly.aux_info.clone();
            let mut transcript = <PolyIOP<Fr> as ZeroCheck<Fr>>::init_transcript();
            transcript.append_message(b"testing", b"initializing transcript for testing")?;

            assert!(
                <PolyIOP<Fr> as ZeroCheck<Fr>>::verify(&proof, &poly_info, &mut transcript)
                    .is_err()
            );
        }

        Ok(())
    }
}
