use crate::{
    arithmetic::virtual_polynomial::{VPAuxInfo, VirtualPolynomial},
    streams::{serialize::RawPrimeField, MLE},
    {
        piop::{
            errors::PIOPError,
            structs::{IOPProof, IOPProverState, IOPVerifierState},
        },
        transcript::IOPTranscript,
    },
};
use ark_ff::PrimeField;
use ark_std::{end_timer, start_timer};
use std::fmt::Debug;

mod prover;
mod verifier;

/// Trait for sum check protocol prover side APIs.
pub trait SumCheckProver<F: PrimeField>
where
    Self: Sized,
{
    type VirtualPolynomial;
    type ProverMessage;

    /// Initialize the prover state to argue for the sum of the input polynomial
    /// over {0,1}^`num_vars`.
    fn prover_init(polynomial: &Self::VirtualPolynomial) -> Result<Self, PIOPError>;

    /// Receive message from verifier, generate prover message, and proceed to
    /// next round.
    ///
    /// Main algorithm used is from section 3.2 of [XZZPS19](https://eprint.iacr.org/2019/317.pdf#subsection.3.2).
    fn prove_round_and_update_state(
        &mut self,
        challenge: &Option<F>,
    ) -> Result<Self::ProverMessage, PIOPError>;
}

/// Trait for sum check protocol verifier side APIs.
pub trait SumCheckVerifier<F: PrimeField> {
    type VPAuxInfo;
    type ProverMessage;
    type Challenge;
    type Transcript;
    type SumCheckSubClaim;

    /// Initialize the verifier's state.
    fn verifier_init(index_info: &Self::VPAuxInfo) -> Self;

    /// Run verifier for the current round, given a prover message.
    ///
    /// Note that `verify_round_and_update_state` only samples and stores
    /// challenges; and update the verifier's state accordingly. The actual
    /// verifications are deferred (in batch) to `check_and_generate_subclaim`
    /// at the last step.
    fn verify_round_and_update_state(
        &mut self,
        prover_msg: &Self::ProverMessage,
        transcript: &mut Self::Transcript,
    ) -> Result<Self::Challenge, PIOPError>;

    /// This function verifies the deferred checks in the interactive version of
    /// the protocol; and generate the subclaim. Returns an error if the
    /// proof failed to verify.
    ///
    /// If the asserted sum is correct, then the multilinear polynomial
    /// evaluated at `subclaim.point` will be `subclaim.expected_evaluation`.
    /// Otherwise, it is highly unlikely that those two will be equal.
    /// Larger field size guarantees smaller soundness error.
    fn check_and_generate_subclaim(
        &self,
        asserted_sum: &F,
    ) -> Result<Self::SumCheckSubClaim, PIOPError>;
}

/// A SumCheckSubClaim is a claim generated by the verifier at the end of
/// verification when it is convinced.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SumCheckSubClaim<F: PrimeField> {
    /// the multi-dimensional point that this multilinear extension is evaluated
    /// to
    pub point: Vec<F>,
    /// the expected evaluation
    pub expected_evaluation: F,
}

pub struct SumCheck<F: PrimeField>(std::marker::PhantomData<F>);

pub type SumCheckProof<F> = IOPProof<F>;
pub type MultilinearExtension<F> = MLE<F>;
pub type Transcript<F> = IOPTranscript<F>;

impl<F: RawPrimeField> SumCheck<F> {
    pub fn extract_sum(proof: &SumCheckProof<F>) -> F {
        let start = start_timer!(|| "extract sum");
        let res = proof.proofs[0].evaluations[0] + proof.proofs[0].evaluations[1];
        end_timer!(start);
        res
    }

    pub fn init_transcript() -> Transcript<F> {
        let start = start_timer!(|| "init transcript");
        let res = IOPTranscript::<F>::new(b"Initializing SumCheck transcript");
        end_timer!(start);
        res
    }

    pub fn prove(
        poly: &VirtualPolynomial<F>,
        transcript: &mut Transcript<F>,
    ) -> Result<SumCheckProof<F>, PIOPError> {
        let start = start_timer!(|| "sum check prove");

        transcript.append_serializable_element(b"aux info", &poly.aux_info)?;

        let mut prover_state = IOPProverState::prover_init(poly)?;
        let mut challenge = None;
        let mut prover_msgs = Vec::with_capacity(poly.aux_info.num_variables);
        for _i in 0..poly.aux_info.num_variables {
            let prover_msg =
                IOPProverState::prove_round_and_update_state(&mut prover_state, &challenge)?;

            transcript.append_serializable_element(b"prover msg", &prover_msg)?;
            prover_msgs.push(prover_msg);
            challenge = Some(transcript.get_and_append_challenge(b"Internal round")?);
        }
        // pushing the last challenge point to the state
        if let Some(p) = challenge {
            prover_state.challenges.push(p)
        };

        end_timer!(start);
        Ok(IOPProof {
            point: prover_state.challenges,
            proofs: prover_msgs,
        })
    }

    pub fn verify(
        claimed_sum: F,
        proof: &SumCheckProof<F>,
        aux_info: &VPAuxInfo<F>,
        transcript: &mut Transcript<F>,
    ) -> Result<SumCheckSubClaim<F>, PIOPError> {
        let start = start_timer!(|| "sum check verify");

        transcript.append_serializable_element(b"aux info", aux_info)?;
        let mut verifier_state = IOPVerifierState::verifier_init(aux_info);

        #[cfg(debug_assertions)]
        println!(
            "sum check verifier aux_info.num_variables: {}",
            aux_info.num_variables
        );

        for i in 0..aux_info.num_variables {
            let prover_msg = proof.proofs.get(i).expect("proof is incomplete");
            transcript.append_serializable_element(b"prover msg", prover_msg)?;
            let challenge = IOPVerifierState::verify_round_and_update_state(
                &mut verifier_state,
                prover_msg,
                transcript,
            )?;

            #[cfg(debug_assertions)]
            println!("round={}, verifier challenge: {}", i, challenge);
        }

        let res = IOPVerifierState::check_and_generate_subclaim(&verifier_state, &claimed_sum);

        end_timer!(start);
        res
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        arithmetic::virtual_polynomial::VirtualPolynomial, streams::iterator::BatchedIterator,
    };
    use ark_bls12_381::Fr;
    use ark_ff::UniformRand;
    use ark_std::{
        rand::{rngs::StdRng, SeedableRng},
        test_rng,
    };

    fn test_sumcheck(
        nv: usize,
        num_multiplicands_range: (usize, usize),
        num_products: usize,
    ) -> Result<(), PIOPError> {
        let seed = [
            1, 0, 0, 0, 23, 0, 0, 0, 200, 1, 0, 0, 210, 30, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0,
        ];
        let mut rng = StdRng::from_seed(seed);
        let mut transcript = SumCheck::<Fr>::init_transcript();

        let (poly, asserted_sum) =
            VirtualPolynomial::rand(nv, num_multiplicands_range, num_products, &mut rng)?;

        println!("generated asserted sum: {}", asserted_sum);

        #[cfg(debug_assertions)]
        for eval in poly.mles[0].evals().iter().to_vec() {
            println!("sum check product eval: {}", eval);
        }

        let proof = SumCheck::prove(&poly, &mut transcript)?;
        let poly_info = poly.aux_info.clone();
        let mut transcript = SumCheck::<Fr>::init_transcript();
        let subclaim = SumCheck::verify(asserted_sum, &proof, &poly_info, &mut transcript)?;

        let evaluated_point = poly.evaluate(&subclaim.point).unwrap();
        assert!(
            // expected_evaluation is interpolated; in the full protocol, the evaluated_point should be a commitment query at subclaim point rather than evaluated from scratch
            evaluated_point == subclaim.expected_evaluation,
            "{}",
            format!(
                "wrong subclaim: evaluated: {}, expected: {}",
                evaluated_point, subclaim.expected_evaluation
            )
        );
        Ok(())
    }

    fn test_sumcheck_internal(
        nv: usize,
        num_multiplicands_range: (usize, usize),
        num_products: usize,
    ) -> Result<(), PIOPError> {
        let seed = [
            1, 0, 0, 0, 23, 0, 0, 0, 200, 1, 0, 0, 210, 30, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0,
        ];
        let mut rng = StdRng::from_seed(seed);
        let (poly, asserted_sum) =
            VirtualPolynomial::<Fr>::rand(nv, num_multiplicands_range, num_products, &mut rng)?;

        let poly_info = poly.aux_info.clone();
        let mut prover_state = IOPProverState::prover_init(&poly)?;
        let mut verifier_state = IOPVerifierState::verifier_init(&poly_info);
        let mut challenge = None;
        let mut transcript = IOPTranscript::new(b"a test transcript");
        transcript
            .append_message(b"testing", b"initializing transcript for testing")
            .unwrap();
        for _ in 0..poly.aux_info.num_variables {
            let prover_message =
                IOPProverState::prove_round_and_update_state(&mut prover_state, &challenge)
                    .unwrap();

            challenge = Some(
                IOPVerifierState::verify_round_and_update_state(
                    &mut verifier_state,
                    &prover_message,
                    &mut transcript,
                )
                .unwrap(),
            );
        }
        let subclaim =
            IOPVerifierState::check_and_generate_subclaim(&verifier_state, &asserted_sum)
                .expect("fail to generate subclaim");

        let evaluated_point = poly.evaluate(&subclaim.point).unwrap();
        assert!(
            evaluated_point == subclaim.expected_evaluation, // the expected evaluation is interpolated; in the full protocol, the poly evaluation should be a commitment query at subclaim point rather than evaluated from scratch
            "{}",
            format!(
                "wrong subclaim: evaluated: {}, expected: {}",
                evaluated_point, subclaim.expected_evaluation
            )
        );
        Ok(())
    }

    #[test]
    fn test_trivial_polynomial() -> Result<(), PIOPError> {
        let nv = 1;
        let num_multiplicands_range = (3, 4);
        let num_products = 1;

        test_sumcheck(nv, num_multiplicands_range, num_products)?;
        test_sumcheck_internal(nv, num_multiplicands_range, num_products)
    }

    #[test]
    fn test_normal_polynomial() -> Result<(), PIOPError> {
        let nv = 3;
        let num_multiplicands_range = (1, 2);
        let num_products = 1;

        test_sumcheck(nv, num_multiplicands_range, num_products)?;
        test_sumcheck_internal(nv, num_multiplicands_range, num_products)
    }
    #[test]
    fn zero_polynomial_should_error() {
        let nv = 0;
        let num_multiplicands_range = (4, 13);
        let num_products = 5;

        assert!(test_sumcheck(nv, num_multiplicands_range, num_products).is_err());
        assert!(test_sumcheck_internal(nv, num_multiplicands_range, num_products).is_err());
    }

    #[test]
    fn test_extract_sum() -> Result<(), PIOPError> {
        let mut rng = test_rng();
        let mut transcript = SumCheck::<Fr>::init_transcript();
        let (poly, asserted_sum) = VirtualPolynomial::<Fr>::rand(8, (3, 4), 3, &mut rng)?;

        let proof = SumCheck::prove(&poly, &mut transcript)?;
        assert_eq!(SumCheck::<Fr>::extract_sum(&proof), asserted_sum);
        Ok(())
    }

    #[test]
    /// Test that the memory usage of shared-reference is linear to number of
    /// unique MLExtensions instead of total number of multiplicands.
    fn test_shared_reference() -> Result<(), PIOPError> {
        let mut rng = test_rng();
        let ml_extensions: Vec<_> = (0..5).map(|_| MLE::<Fr>::rand(8, &mut rng)).collect();
        let mut poly = VirtualPolynomial::new(8);
        poly.add_mles(
            vec![
                ml_extensions[2].clone(),
                ml_extensions[3].clone(),
                ml_extensions[0].clone(),
            ],
            Fr::rand(&mut rng),
        )?;
        poly.add_mles(
            vec![
                ml_extensions[1].clone(),
                ml_extensions[4].clone(),
                ml_extensions[4].clone(),
            ],
            Fr::rand(&mut rng),
        )?;
        poly.add_mles(
            vec![
                ml_extensions[3].clone(),
                ml_extensions[2].clone(),
                ml_extensions[1].clone(),
            ],
            Fr::rand(&mut rng),
        )?;
        poly.add_mles(
            vec![ml_extensions[0].clone(), ml_extensions[0].clone()],
            Fr::rand(&mut rng),
        )?;
        poly.add_mles(vec![ml_extensions[4].clone()], Fr::rand(&mut rng))?;

        assert_eq!(poly.mles.len(), 5);

        #[cfg(debug_assertions)]
        {
            // print each product indices of virtualpolynomial
            for (coeff, product) in poly.products.iter() {
                println!("coeff: {}, product: {:?}", coeff, product);
            }
        }

        // test memory usage for prover
        let prover = IOPProverState::<Fr>::prover_init(&poly).unwrap();
        assert_eq!(prover.poly.mles.len(), 5);
        drop(prover);

        let mut transcript = SumCheck::<Fr>::init_transcript();
        let poly_info = poly.aux_info.clone();
        let proof = SumCheck::<Fr>::prove(&poly, &mut transcript)?;
        let asserted_sum = SumCheck::<Fr>::extract_sum(&proof);

        let mut transcript = SumCheck::<Fr>::init_transcript();
        let subclaim = SumCheck::verify(asserted_sum, &proof, &poly_info, &mut transcript)?;

        let evaluated_point = poly.evaluate(&subclaim.point).unwrap();
        assert!(
            evaluated_point == subclaim.expected_evaluation,
            "wrong subclaim"
        );
        Ok(())
    }
}
