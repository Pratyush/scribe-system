// Copyright (c) 2023 Espresso Systems (espressosys.com)
// This file is part of the HyperPlonk library.

// You should have received a copy of the MIT License
// along with the HyperPlonk library. If not, see <https://mit-license.org/>.

//! This module implements the sum check protocol.

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
use ark_std::{end_timer, start_timer};
use std::{fmt::Debug, io::Seek, sync::Arc};
// use transcript::IOPTranscript;

mod prover;
mod verifier;

/// Trait for doing sum check protocols.
pub trait SumCheck<F: PrimeField> {
    type VirtualPolynomial;
    type VPAuxInfo;
    // type MultilinearExtension;

    type SumCheckProof: Clone + Debug + Default + PartialEq;
    type Transcript;
    type SumCheckSubClaim: Clone + Debug + Default + PartialEq;

    /// Extract sum from the proof
    fn extract_sum(proof: &Self::SumCheckProof) -> F;

    /// Initialize the system with a transcript
    ///
    /// This function is optional -- in the case where a SumCheck is
    /// an building block for a more complex protocol, the transcript
    /// may be initialized by this complex protocol, and passed to the
    /// SumCheck prover/verifier.
    fn init_transcript() -> Self::Transcript;

    /// Generate proof of the sum of polynomial over {0,1}^`num_vars`
    ///
    /// The polynomial is represented in the form of a VirtualPolynomial.
    fn prove(
        poly: &Self::VirtualPolynomial,
        transcript: &mut Self::Transcript,
    ) -> Result<Self::SumCheckProof, PolyIOPErrors>;

    /// Verify the claimed sum using the proof
    fn verify(
        sum: F,
        proof: &Self::SumCheckProof,
        aux_info: &Self::VPAuxInfo,
        transcript: &mut Self::Transcript,
    ) -> Result<Self::SumCheckSubClaim, PolyIOPErrors>;
}

/// Trait for sum check protocol prover side APIs.
pub trait SumCheckProver<F: PrimeField>
where
    Self: Sized,
{
    type VirtualPolynomial;
    type ProverMessage;

    /// Initialize the prover state to argue for the sum of the input polynomial
    /// over {0,1}^`num_vars`.
    fn prover_init(polynomial: &Self::VirtualPolynomial) -> Result<Self, PolyIOPErrors>;

    /// Receive message from verifier, generate prover message, and proceed to
    /// next round.
    ///
    /// Main algorithm used is from section 3.2 of [XZZPS19](https://eprint.iacr.org/2019/317.pdf#subsection.3.2).
    fn prove_round_and_update_state(
        &mut self,
        challenge: &Option<F>,
    ) -> Result<Self::ProverMessage, PolyIOPErrors>;
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
    ) -> Result<Self::Challenge, PolyIOPErrors>;

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
    ) -> Result<Self::SumCheckSubClaim, PolyIOPErrors>;
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

impl<F: PrimeField> SumCheck<F> for PolyIOP<F> {
    type SumCheckProof = IOPProof<F>;
    type VirtualPolynomial = VirtualPolynomial<F>;
    type VPAuxInfo = VPAuxInfo<F>;
    // type MultilinearExtension = Arc<DenseMultilinearExtension<F>>;
    type SumCheckSubClaim = SumCheckSubClaim<F>;
    type Transcript = IOPTranscript<F>;

    fn extract_sum(proof: &Self::SumCheckProof) -> F {
        let start = start_timer!(|| "extract sum");
        let res = proof.proofs[0].evaluations[0] + proof.proofs[0].evaluations[1];
        end_timer!(start);
        res
    }

    fn init_transcript() -> Self::Transcript {
        let start = start_timer!(|| "init transcript");
        let res = IOPTranscript::<F>::new(b"Initializing SumCheck transcript");
        end_timer!(start);
        res
    }

    fn prove(
        poly: &Self::VirtualPolynomial,
        transcript: &mut Self::Transcript,
    ) -> Result<Self::SumCheckProof, PolyIOPErrors> {
        let start = start_timer!(|| "sum check prove");

        transcript.append_serializable_element(b"aux info", &poly.aux_info)?;

        let mut prover_state = IOPProverState::prover_init(poly)?;
        let mut challenge = None;
        let mut prover_msgs = Vec::with_capacity(poly.aux_info.num_variables);
        for i in 0..poly.aux_info.num_variables {
            let prover_msg =
                IOPProverState::prove_round_and_update_state(&mut prover_state, &challenge)?;
            // print the position of read pointer of each mle in poly
            for mle in poly.flattened_ml_extensions.iter() {
                // read next on mle and print each element 
                let mut mle_stream = mle.lock().unwrap();
                // println!("starting read pointer position of `prove` argument poly: {}", mle_stream.read_pointer.stream_position().unwrap());
            }
            for mle in prover_state.poly.flattened_ml_extensions.iter() {
                // read next on mle and print each element 
                let mut mle_stream = mle.lock().unwrap();
                // println!("starting read pointer position of prover_state poly: {}", mle_stream.read_pointer.stream_position().unwrap());
            }
            // println!("round={}, prover challenge: {:?}", i, challenge);
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

    fn verify(
        claimed_sum: F,
        proof: &Self::SumCheckProof,
        aux_info: &Self::VPAuxInfo,
        transcript: &mut Self::Transcript,
    ) -> Result<Self::SumCheckSubClaim, PolyIOPErrors> {
        let start = start_timer!(|| "sum check verify");

        transcript.append_serializable_element(b"aux info", aux_info)?;
        let mut verifier_state = IOPVerifierState::verifier_init(aux_info);
        for i in 0..aux_info.num_variables {
            let prover_msg = proof.proofs.get(i).expect("proof is incomplete");
            transcript.append_serializable_element(b"prover msg", prover_msg)?;
            let challenge = IOPVerifierState::verify_round_and_update_state(
                &mut verifier_state,
                prover_msg,
                transcript,
            )?;
            // println!("round={}, verifier challenge: {}", i, challenge);
        }

        let res = IOPVerifierState::check_and_generate_subclaim(&verifier_state, &claimed_sum);

        end_timer!(start);
        res
    }
}

#[cfg(test)]
mod test {

    use super::*;
    // use ark_bls12_381::Fr;
    use ark_test_curves::bls12_381::Fr;
    use ark_ff::UniformRand;
    use ark_poly::{DenseMultilinearExtension, MultilinearExtension};
    use ark_std::{rand::{rngs::StdRng, SeedableRng}, test_rng};
    use std::sync::{Arc, Mutex};
    use crate::read_write::ReadWriteStream;
    use std::io::Seek;
    use std::str::FromStr;

    fn test_sumcheck(
        nv: usize,
        num_multiplicands_range: (usize, usize),
        num_products: usize,
    ) -> Result<(), PolyIOPErrors> {
        let seed = [
        1, 0, 0, 0, 23, 0, 0, 0, 200, 1, 0, 0, 210, 30, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0,
        ];
        let mut rng = StdRng::from_seed(seed);
        let mut transcript = <PolyIOP<Fr> as SumCheck<Fr>>::init_transcript();

        let (poly, asserted_sum) =
            VirtualPolynomial::rand(nv, num_multiplicands_range, num_products, &mut rng)?;
        
          // print the position of read pointer of each mle in poly
        // for mle in poly.flattened_ml_extensions.iter() {
            // read next on mle and print each element 
            // let mut mle_stream = mle.lock().unwrap();
            // println!("starting read pointer position: {}", mle_stream.read_pointer.stream_position().unwrap());
        // }
        
        let proof = <PolyIOP<Fr> as SumCheck<Fr>>::prove(&poly, &mut transcript)?;
        let poly_info = poly.aux_info.clone();
        let mut transcript = <PolyIOP<Fr> as SumCheck<Fr>>::init_transcript();
        let subclaim = <PolyIOP<Fr> as SumCheck<Fr>>::verify(
            asserted_sum,
            &proof,
            &poly_info,
            &mut transcript,
        )?;

        // print read pointer position of each mle in poly
        // for mle in poly.flattened_ml_extensions.iter() {
            // read next on mle and print each element 
            // let mut mle_stream = mle.lock().unwrap();
            // println!("ending read pointer position: {}", mle_stream.read_pointer.stream_position().unwrap());
        // }

        // // loop over and print all elements of all ml extensions of poly
        // for mle in poly.flattened_ml_extensions.iter() {
        //     // read next on mle and print each element 
        //     let mut mle_stream = mle.lock().unwrap();
        //     while let (Some(elem)) =
        //     (mle_stream.read_next())
        //     {
        //         println!("evaluate elem: {}", elem);
        //     }
        // }

        // print subclaim point
        // for point in subclaim.point.iter() {
            // println!("evaluate point: {}", point);
        // }

        // print read pointer position of each mle in poly
        // for mle in poly.flattened_ml_extensions.iter() {
            // read next on mle and print each element 
            // let mut mle_stream = mle.lock().unwrap();
            // println!("ending read pointer position: {}", mle_stream.read_pointer.stream_position().unwrap());
        // }

        let evaluated_point = poly.evaluate(std::slice::from_ref(&subclaim.point[poly_info.num_variables - 1])).unwrap();
        assert!(
            evaluated_point == subclaim.expected_evaluation, // expected_evaluation is interpolated; in the full protocol, the evaluated_point should be a commitment query at subclaim point rather than evaluated from scratch
            "{}", format!("wrong subclaim: evaluated: {}, expected: {}", evaluated_point, subclaim.expected_evaluation)
        );
        Ok(())
    }

    fn test_sumcheck_internal(
        nv: usize,
        num_multiplicands_range: (usize, usize),
        num_products: usize,
    ) -> Result<(), PolyIOPErrors> {
        let seed = [
        1, 0, 0, 0, 23, 0, 0, 0, 200, 1, 0, 0, 210, 30, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0,
        ];
        let mut rng = StdRng::from_seed(seed);
        let (poly, asserted_sum) =
            VirtualPolynomial::<Fr>::rand(nv, num_multiplicands_range, num_products, &mut rng)?;
        // print the position of read pointer of each mle in poly
        // for mle in poly.flattened_ml_extensions.iter() {
            // read next on mle and print each element 
            // let mut mle_stream = mle.lock().unwrap();
            // println!("starting read pointer position: {}", mle_stream.read_pointer.stream_position().unwrap());
        // }
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

        let evaluated_point = poly.evaluate(std::slice::from_ref(&subclaim.point[poly_info.num_variables - 1])).unwrap();
        assert!(
            evaluated_point == subclaim.expected_evaluation, // the expected evaluation is interpolated; in the full protocol, the poly evaluation should be a commitment query at subclaim point rather than evaluated from scratch
            "{}", format!("wrong subclaim: evaluated: {}, expected: {}", evaluated_point, subclaim.expected_evaluation)
        );
        Ok(())
    }

    #[test]
    fn test_field() {
        let even = Fr::from_str("46726240763639862128214388288720131204625575015731614850157206947646262134152").unwrap();
        let odd = Fr::from_str("43289727388036023252294560744145593863815462211184144675663927741862919848062").unwrap();
        let r = Fr::from_str("48518066819672969227993919640561737464634267551386147702542572494009347136503").unwrap();
        let evaluated = even + r * (odd - even);
        // println!("evaluated: {}", evaluated);
    }

    #[test]
    fn test_trivial_polynomial() -> Result<(), PolyIOPErrors> {
        let nv = 1;
        let num_multiplicands_range = (4, 13);
        let num_products = 5;

        test_sumcheck(nv, num_multiplicands_range, num_products)?;
        test_sumcheck_internal(nv, num_multiplicands_range, num_products)
    }
    #[test]
    fn test_normal_polynomial() -> Result<(), PolyIOPErrors> {
        let nv = 12;
        let num_multiplicands_range = (4, 9);
        let num_products = 5;

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
    fn test_extract_sum() -> Result<(), PolyIOPErrors> {
        let mut rng = test_rng();
        let mut transcript = <PolyIOP<Fr> as SumCheck<Fr>>::init_transcript();
        let (poly, asserted_sum) = VirtualPolynomial::<Fr>::rand(8, (3, 4), 3, &mut rng)?;

        let proof = <PolyIOP<Fr> as SumCheck<Fr>>::prove(&poly, &mut transcript)?;
        assert_eq!(
            <PolyIOP<Fr> as SumCheck<Fr>>::extract_sum(&proof),
            asserted_sum
        );
        Ok(())
    }

    #[test]
    /// Test that the memory usage of shared-reference is linear to number of
    /// unique MLExtensions instead of total number of multiplicands.
    fn test_shared_reference() -> Result<(), PolyIOPErrors> {
        let mut rng = test_rng();
        let ml_extensions: Vec<_> = (0..5)
            .map(|_| Arc::new(Mutex::new(DenseMLPolyStream::<Fr>::rand(8, &mut rng))))
            .collect();
        let mut poly = VirtualPolynomial::new(8);
        poly.add_mle_list(
            vec![
                ml_extensions[2].clone(),
                ml_extensions[3].clone(),
                ml_extensions[0].clone(),
            ],
            Fr::rand(&mut rng),
        )?;
        poly.add_mle_list(
            vec![
                ml_extensions[1].clone(),
                ml_extensions[4].clone(),
                ml_extensions[4].clone(),
            ],
            Fr::rand(&mut rng),
        )?;
        poly.add_mle_list(
            vec![
                ml_extensions[3].clone(),
                ml_extensions[2].clone(),
                ml_extensions[1].clone(),
            ],
            Fr::rand(&mut rng),
        )?;
        poly.add_mle_list(
            vec![ml_extensions[0].clone(), ml_extensions[0].clone()],
            Fr::rand(&mut rng),
        )?;
        poly.add_mle_list(vec![ml_extensions[4].clone()], Fr::rand(&mut rng))?;

        assert_eq!(poly.flattened_ml_extensions.len(), 5);

        // print each product indices of virtualpolynomial
        for (coeff, product) in poly.products.iter() {
            println!("coeff: {}, product: {:?}", coeff, product);
        }

        // test memory usage for prover
        let prover = IOPProverState::<Fr>::prover_init(&poly).unwrap();
        assert_eq!(prover.poly.flattened_ml_extensions.len(), 5);
        drop(prover);

        let mut transcript = <PolyIOP<Fr> as SumCheck<Fr>>::init_transcript();
        let poly_info = poly.aux_info.clone();
        let proof = <PolyIOP<Fr> as SumCheck<Fr>>::prove(&poly, &mut transcript)?;
        let asserted_sum = <PolyIOP<Fr> as SumCheck<Fr>>::extract_sum(&proof);

        let mut transcript = <PolyIOP<Fr> as SumCheck<Fr>>::init_transcript();
        let subclaim = <PolyIOP<Fr> as SumCheck<Fr>>::verify(
            asserted_sum,
            &proof,
            &poly_info,
            &mut transcript,
        )?;
        assert!(
            poly.evaluate(&subclaim.point)? == subclaim.expected_evaluation,
            "wrong subclaim"
        );
        Ok(())
    }
}
