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
use std::{fmt::Debug, io::Seek, iter::Sum, sync::Arc};

use super::{sum_check::SumCheck, zero_check::ZeroCheck};
// use transcript::IOPTranscript;

mod util;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PermutationCheckSubClaim<F: PrimeField> {
    /// the multi-dimensional point that this multilinear extension is evaluated
    /// to
    pub point: Vec<F>,
    /// the expected evaluation
    pub expected_evaluation: F,
    pub permu_check_challenge: F,
    pub batch_sum_check_challenge: F,
    pub zero_check_init_challenge: Vec<F>,
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
        index: Self::MultilinearExtension,
        transcript: &mut IOPTranscript<F>,
    ) -> Result<
        (
            Self::PermutationCheckProof,
            Self::MultilinearExtension,
            Self::MultilinearExtension,
            Self::MultilinearExtension,
        ),
        PolyIOPErrors,
    >;

    #[allow(clippy::type_complexity)]
    fn prove_plonk(
        // pcs_param: &PCS::ProverParam,
        p: Self::MultilinearExtension,
        pi: Self::MultilinearExtension,
        index: Self::MultilinearExtension,
        transcript: &mut IOPTranscript<F>,
    ) -> Result<
        (
            Self::PermutationCheckProof,
            Self::MultilinearExtension,
            Self::MultilinearExtension,
            Self::MultilinearExtension,
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

impl<F: PrimeField> PermutationCheck<F> for PolyIOP<F>
where
// E: Pairing,
// PCS: PolynomialCommitmentScheme<E, Polynomial = Arc<DenseMultilinearExtension<E::ScalarField>>>,
{
    type PermutationCheckSubClaim = PermutationCheckSubClaim<F>;
    type PermutationCheckProof = Self::ZeroCheckProof;

    fn init_transcript() -> Self::Transcript {
        IOPTranscript::<F>::new(b"Initializing PermuCheck transcript")
    }

    fn prove(
        // pcs_param: &PCS::ProverParam,
        mut p: Self::MultilinearExtension,
        mut q: Self::MultilinearExtension,
        mut pi: Self::MultilinearExtension,
        mut index: Self::MultilinearExtension,
        transcript: &mut IOPTranscript<F>,
    ) -> Result<
        (
            Self::PermutationCheckProof,
            Self::MultilinearExtension, // h_p
            Self::MultilinearExtension, // h_q
            Self::MultilinearExtension, // eq_x_r
        ),
        PolyIOPErrors,
    > {
        let start = start_timer!(|| "perm_check prove");

        // assume that p, q, and pi have equal length

        // get challenge alpha for h_p = 1/(p + alpha * pi) and h_q = 1/(q + alpha)
        let alpha = transcript.get_and_append_challenge(b"alpha")?;

        // // print prover alpha
        // println!("prover alpha: {}", alpha);

        // compute the fractional polynomials h_p and h_q
        let (mut h_p, mut h_q) = util::compute_frac_poly(&p, &q, &pi, &index, alpha).unwrap();

        // get challenge batch_factor for batch zero check of t_1 + batch_factor * t_2, where t_1 = h_p * (p + alpha * pi) - 1 and t_2 = h_q * (q + alpha) - 1
        let batch_factor = transcript.get_and_append_challenge(b"batch_factor")?;

        // // print prover batch_factor
        // println!("prover batch_factor: {}", batch_factor);

        // poly = t_1 + r * t_2 = h_p * (p + alpha * pi) - 1 + r * (h_q * (q + alpha) - 1)
        let poly = VirtualPolynomial::build_perm_check_poly(
            h_p.clone(),
            h_q.clone(),
            p,
            q,
            pi,
            index,
            alpha,
            batch_factor,
        )
        .unwrap();

        // get challenge r for building eq_x_r
        let length = poly.aux_info.num_variables;
        let r = transcript.get_and_append_challenge_vectors(b"0check r", length)?;

        // // print prover r
        // r.iter().for_each(|r| println!("prover r: {}", r));

        let mut final_poly = poly.build_f_hat(r.as_ref())?;

        // get sumcheck for t_0 = sum over x in {0,1}^n of (h_p(x) - h_q(x)) = 0
        // add term batch_factor^2 * t_0 to f_hat
        // t_0 = h_p - h_q
        let _ = final_poly.add_mle_list(vec![h_p.clone()], batch_factor * batch_factor);
        let _ = final_poly.add_mle_list(vec![h_q.clone()], -batch_factor * batch_factor);

        // // print products of final_poly
        // for (coeff, products) in &final_poly.products {
        //     println!("prover final_poly coeff: {}, products: {:?}", coeff, products);
        // }
        // // print each stream of final poly
        // for (i, stream) in final_poly.flattened_ml_extensions.clone().iter().enumerate() {
        //     let mut stream_locked = stream.lock().unwrap();
        //     while let Some(val) = stream_locked.read_next() {
        //         println!("prover final_poly stream {}: {}", i, val);
        //     }
        //     stream_locked.read_restart();
        //     drop(stream_locked);
        // }

        let proof = <Self as SumCheck<F>>::prove(&final_poly, transcript)?;

        let eq_x_r = final_poly.flattened_ml_extensions
            [final_poly.flattened_ml_extensions.len() - 1]
            .clone();

        end_timer!(start);
        Ok((proof, h_p, h_q, eq_x_r))
    }

    fn prove_plonk(
        // pcs_param: &PCS::ProverParam,
        mut p: Self::MultilinearExtension,
        mut pi: Self::MultilinearExtension,
        mut index: Self::MultilinearExtension,
        transcript: &mut IOPTranscript<F>,
    ) -> Result<
        (
            Self::PermutationCheckProof,
            Self::MultilinearExtension, // h_p
            Self::MultilinearExtension, // h_q
            Self::MultilinearExtension, // eq_x_r
        ),
        PolyIOPErrors,
    > {
        let start = start_timer!(|| "perm_check prove");

        // assume that p, q, and pi have equal length

        // get challenge alpha for h_p = 1/(p + alpha * pi) and h_q = 1/(q + alpha)
        let alpha = transcript.get_and_append_challenge(b"alpha")?;

        // // print prover alpha
        // println!("prover alpha: {}", alpha);

        // compute the fractional polynomials h_p and h_q
        let (mut h_p, mut h_q) = util::compute_frac_poly_plonk(&p, &pi, &index, alpha).unwrap();

        // get challenge batch_factor for batch zero check of t_1 + batch_factor * t_2, where t_1 = h_p * (p + alpha * pi) - 1 and t_2 = h_q * (q + alpha) - 1
        let batch_factor = transcript.get_and_append_challenge(b"batch_factor")?;

        // // print prover batch_factor
        // println!("prover batch_factor: {}", batch_factor);

        // poly = t_1 + r * t_2 = h_p * (p + alpha * pi) - 1 + r * (h_q * (q + alpha) - 1)
        let poly = VirtualPolynomial::build_perm_check_poly_plonk(
            h_p.clone(),
            h_q.clone(),
            p,
            pi,
            index,
            alpha,
            batch_factor,
        )
        .unwrap();

        // get challenge r for building eq_x_r
        let length = poly.aux_info.num_variables;
        let r = transcript.get_and_append_challenge_vectors(b"0check r", length)?;

        // // print prover r
        // r.iter().for_each(|r| println!("prover r: {}", r));

        let mut final_poly = poly.build_f_hat(r.as_ref())?;

        // get sumcheck for t_0 = sum over x in {0,1}^n of (h_p(x) - h_q(x)) = 0
        // add term batch_factor^2 * t_0 to f_hat
        // t_0 = h_p - h_q
        let _ = final_poly.add_mle_list(vec![h_p.clone()], batch_factor * batch_factor);
        let _ = final_poly.add_mle_list(vec![h_q.clone()], -batch_factor * batch_factor);

        // // print products of final_poly
        // for (coeff, products) in &final_poly.products {
        //     println!("prover final_poly coeff: {}, products: {:?}", coeff, products);
        // }
        // // print each stream of final poly
        // for (i, stream) in final_poly.flattened_ml_extensions.clone().iter().enumerate() {
        //     let mut stream_locked = stream.lock().unwrap();
        //     while let Some(val) = stream_locked.read_next() {
        //         println!("prover final_poly stream {}: {}", i, val);
        //     }
        //     stream_locked.read_restart();
        //     drop(stream_locked);
        // }

        let proof = <Self as SumCheck<F>>::prove(&final_poly, transcript)?;

        let eq_x_r = final_poly.flattened_ml_extensions
            [final_poly.flattened_ml_extensions.len() - 1]
            .clone();

        end_timer!(start);
        Ok((proof, h_p, h_q, eq_x_r))
    }

    fn verify(
        proof: &Self::PermutationCheckProof,
        aux_info: &VPAuxInfo<F>,
        transcript: &mut Self::Transcript,
    ) -> Result<Self::PermutationCheckSubClaim, PolyIOPErrors> {
        let start: ark_std::perf_trace::TimerInfo = start_timer!(|| "perm_check verify");

        // check that the sum is zero
        if proof.proofs[0].evaluations[0] + proof.proofs[0].evaluations[1] != F::zero() {
            return Err(PolyIOPErrors::InvalidProof(format!(
                "zero check: sum {} is not zero",
                proof.proofs[0].evaluations[0] + proof.proofs[0].evaluations[1]
            )));
        }
        // else {
        //     println!("SUCCESS! zero check sum is zero!");
        // }

        // get challenge alpha for h_p = 1/(p + alpha * pi) and h_q = 1/(q + alpha * index)
        let alpha = transcript.get_and_append_challenge(b"alpha")?;

        // // print verifier alpha
        // println!("verifier alpha: {}", alpha);

        // get challenge batch_factor for batch zero check of t_1 + batch_factor * t_2, where t_1 = h_p * (p + alpha * pi) - 1 and t_2 = h_q * (q + alpha) - 1
        let batch_factor = transcript.get_and_append_challenge(b"batch_factor")?;

        // // print verifier batch_factor
        // println!("verifier batch_factor: {}", batch_factor);

        // get challenge r for building eq_x_r
        let length = aux_info.num_variables;
        let r = transcript.get_and_append_challenge_vectors(b"0check r", length)?;

        // // print verifier r
        // r.iter().for_each(|r| println!("verifier r: {}", r));

        // hat_fx's max degree is increased by eq(x, r).degree() which is 1
        let mut hat_fx_aux_info = aux_info.clone();
        hat_fx_aux_info.max_degree += 1;
        let sum_subclaim =
            <Self as SumCheck<F>>::verify(F::zero(), proof, &hat_fx_aux_info, transcript)?;

        end_timer!(start);

        Ok(PermutationCheckSubClaim {
            point: sum_subclaim.point,
            expected_evaluation: sum_subclaim.expected_evaluation,
            permu_check_challenge: alpha,
            batch_sum_check_challenge: batch_factor,
            zero_check_init_challenge: r,
        })
    }
}

#[cfg(test)]
mod test {
    use super::{PermutationCheck, PermutationCheckSubClaim};
    use crate::hyperplonk::arithmetic::virtual_polynomial::VPAuxInfo;
    use crate::hyperplonk::{
        // pcs::{prelude::MultilinearKzgPCS, PolynomialCommitmentScheme},
        arithmetic::virtual_polynomial::VirtualPolynomial,
        poly_iop::{errors::PolyIOPErrors, PolyIOP},
    };
    use crate::read_write::{identity_permutation_mles, random_permutation_mles};

    // use ark_bls12_381::Bls12_381;
    // use ark_ec::pairing::Pairing;
    use crate::read_write::{DenseMLPoly, DenseMLPolyStream, ReadWriteStream};

    use ark_ff::PrimeField;
    use ark_std::{
        rand::{rngs::StdRng, SeedableRng},
        test_rng,
    };
    use ark_test_curves::bls12_381::Fr;
    use std::{
        marker::PhantomData,
        sync::{Arc, Mutex},
    };

    use ark_ff::Field;
    use std::str::FromStr;

    // type Kzg = MultilinearKzgPCS<Bls12_381>;

    // fn test_permutation_check_helper<E, PCS>(
    fn test_permutation_check_helper<F: PrimeField>(
        // pcs_param: &PCS::ProverParam,
        fxs: Vec<Arc<Mutex<DenseMLPolyStream<F>>>>,
        gxs: Vec<Arc<Mutex<DenseMLPolyStream<F>>>>,
        perms: Vec<Arc<Mutex<DenseMLPolyStream<F>>>>,
        indexes: Vec<Arc<Mutex<DenseMLPolyStream<F>>>>,
    ) -> Result<(), PolyIOPErrors>
// where
    //     E: Pairing,
    //     PCS: PolynomialCommitmentScheme<
    //         E,
    //         Polynomial = Arc<DenseMultilinearExtension<E::ScalarField>>,
    //     >,
    {
        let nv = fxs[0].lock().unwrap().num_vars;
        // what's AuxInfo used for?
        let poly_info = VPAuxInfo {
            max_degree: fxs.len() + 1,
            num_variables: nv,
            phantom: PhantomData::default(),
        };

        // prover
        let mut transcript = <PolyIOP<F> as PermutationCheck<F>>::init_transcript();
        transcript.append_message(b"testing", b"initializing transcript for testing")?;
        let (proof, h_p, h_q, eq_x_r) = <PolyIOP<F> as PermutationCheck<F>>::prove(
            // pcs_param,
            fxs[0].clone(),
            gxs[0].clone(),
            perms[0].clone(),
            indexes[0].clone(),
            &mut transcript,
        )?;

        // verifier
        let mut transcript = <PolyIOP<F> as PermutationCheck<F>>::init_transcript();
        transcript.append_message(b"testing", b"initializing transcript for testing")?;

        let PermutationCheckSubClaim {
            point,
            expected_evaluation,
            permu_check_challenge,
            batch_sum_check_challenge,
            zero_check_init_challenge,
        } = <PolyIOP<F> as PermutationCheck<F>>::verify(&proof, &poly_info, &mut transcript)?;

        let mut poly = VirtualPolynomial::build_perm_check_poly(
            h_p.clone(),
            h_q.clone(),
            fxs[0].clone(),
            gxs[0].clone(),
            perms[0].clone(),
            indexes[0].clone(),
            permu_check_challenge,
            batch_sum_check_challenge,
        )
        .unwrap();

        poly.mul_by_mle(eq_x_r, F::ONE)?;

        // get sumcheck for t_0 = sum over x in {0,1}^n of (h_q(x) - h_q(x)) = 0
        // add term batch_factor^2 * t_0 to f_hat
        // t_0 = h_p - h_q
        let _ = poly.add_mle_list(
            vec![h_p],
            batch_sum_check_challenge * batch_sum_check_challenge,
        );
        let _ = poly.add_mle_list(
            vec![h_q],
            -batch_sum_check_challenge * batch_sum_check_challenge,
        );

        // // print challenges
        // println!("test alpha: {}", permu_check_challenge);
        // println!("test batch_factor: {}", batch_sum_check_challenge);
        // zero_check_init_challenge.iter().for_each(|r| println!("test r: {}", r));
        // // print products of poly
        // for (coeff, products) in &poly.products {
        //     println!("test poly coeff: {}, products: {:?}", coeff, products);
        // }
        // // print each stream of poly
        // for (i, stream) in poly.flattened_ml_extensions.clone().iter().enumerate() {
        //     let mut stream_locked = stream.lock().unwrap();
        //     while let Some(val) = stream_locked.read_next() {
        //         println!("test poly stream {}: {}", i, val);
        //     }
        //     stream_locked.read_restart();
        //     drop(stream_locked);
        // }

        let evaluated_point = poly
            .evaluate(std::slice::from_ref(&point[poly_info.num_variables - 1]))
            .unwrap();
        assert!(
            evaluated_point == expected_evaluation,
            "{}",
            format!(
                "wrong subclaim, expected: {}, got: {}",
                expected_evaluation, evaluated_point
            )
        );

        // check product subclaim
        // if evaluate_opt(
        //     &prod_x,
        //     &perm_check_sub_claim.product_check_sub_claim.final_query.0,
        // ) != perm_check_sub_claim.product_check_sub_claim.final_query.1
        // {
        //     return Err(PolyIOPErrors::InvalidVerifier("wrong subclaim".to_string()));
        // };

        Ok(())
    }

    fn test_permutation_check<F: PrimeField>(nv: usize) -> Result<(), PolyIOPErrors> {
        let seed = [
            1, 0, 0, 0, 23, 0, 0, 0, 200, 1, 0, 0, 210, 30, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0,
        ];

        // let srs = MultilinearKzgPCS::<Bls12_381>::gen_srs_for_testing(&mut rng, nv)?;
        // let (pcs_param, _) = MultilinearKzgPCS::<Bls12_381>::trim(&srs, None, Some(nv))?;

        {
            let mut rng = StdRng::from_seed(seed);
            let mut rng_2 = StdRng::from_seed(seed);

            let id_perms = identity_permutation_mles::<Fr>(nv, 1);
            let id_perms_2 = identity_permutation_mles::<Fr>(nv, 1);

            // // print each entry of id_perms and id_perms_2
            // let mut id_perms_locked = id_perms[0].lock().unwrap();
            // let mut id_perms_2_locked = id_perms_2[0].lock().unwrap();
            // while let Some(val) = id_perms_locked.read_next() {
            //     println!("id_perms entry: {}", val);
            // }
            // while let Some(val) = id_perms_2_locked.read_next() {
            //     println!("id_perms_2 entry: {}", val);
            // }
            // id_perms_locked.read_restart();
            // id_perms_2_locked.read_restart();
            // drop(id_perms_locked);
            // drop(id_perms_2_locked);

            // good path: (q1, q2) is a permutation of (q1, q2) itself under the identify
            // map
            let qs = vec![
                Arc::new(Mutex::new(DenseMLPolyStream::rand(nv, &mut rng))),
                // Arc::new(Mutex::new(DenseMLPolyStream::rand(nv, &mut rng))),
            ];

            let qs_2 = vec![
                Arc::new(Mutex::new(DenseMLPolyStream::rand(nv, &mut rng_2))),
                // Arc::new(Mutex::new(DenseMLPolyStream::rand(nv, &mut rng))),
            ];

            // // print each entry of qs and qs_2
            // let mut qs_locked = qs[0].lock().unwrap();
            // let mut qs_2_locked = qs_2[0].lock().unwrap();
            // while let Some(val) = qs_locked.read_next() {
            //     println!("qs entry: {}", val);
            // }
            // while let Some(val) = qs_2_locked.read_next() {
            //     println!("qs_2 entry: {}", val);
            // }
            // qs_locked.read_restart();
            // qs_2_locked.read_restart();
            // drop(qs_locked);
            // drop(qs_2_locked);

            // perms is the identity map
            // test_permutation_check_helper::<Bls12_381, Kzg>(&pcs_param, &ws, &ws, &id_perms)?;
            test_permutation_check_helper(qs, qs_2, id_perms, id_perms_2)?;
        }

        // {
        //     // good path: f = (w1, w2) is a permutation of g = (w2, w1) itself under a map
        //     let mut fs = vec![
        //         Arc::new(Mutex::new(DenseMLPolyStream::rand(nv, &mut rng))),
        //         // Arc::new(Mutex::new(DenseMLPolyStream::rand(nv, &mut rng))),
        //     ];
        //     let gs = fs.clone();
        //     fs.reverse();
        //     // perms is the reverse identity map
        //     let mut perms = id_perms.clone();
        //     perms.reverse();
        //     test_permutation_check_helper::<Bls12_381, Kzg>(&pcs_param, &fs, &gs, &perms)?;
        // }

        {
            // bad path 1: w is a not permutation of w itself under a random map

            let mut rng = StdRng::from_seed(seed);
            let mut rng_2 = StdRng::from_seed(seed);
            let mut rng_3 = StdRng::from_seed(seed);

            let id_perms = identity_permutation_mles(nv, 1);
            // perms is a random map
            let perms = random_permutation_mles(nv, 1, &mut rng_3);

            let ws = vec![
                Arc::new(Mutex::new(DenseMLPolyStream::rand(nv, &mut rng))),
                // Arc::new(Mutex::new(DenseMLPolyStream::rand(nv, &mut rng))),
            ];
            let ws_2 = vec![
                Arc::new(Mutex::new(DenseMLPolyStream::rand(nv, &mut rng_2))),
                // Arc::new(Mutex::new(DenseMLPolyStream::rand(nv, &mut rng))),
            ];

            assert!(test_permutation_check_helper::<Fr>(ws, ws_2, perms, id_perms).is_err());
        }

        {
            // bad path 2: f is a not permutation of g under a identity map

            let mut rng = StdRng::from_seed(seed);

            let id_perms = identity_permutation_mles(nv, 1);
            let id_perms_2 = identity_permutation_mles(nv, 1);

            let fs = vec![
                Arc::new(Mutex::new(DenseMLPolyStream::rand(nv, &mut rng))),
                // Arc::new(Mutex::new(DenseMLPolyStream::rand(nv, &mut rng))),
            ];
            let gs = vec![
                Arc::new(Mutex::new(DenseMLPolyStream::rand(nv, &mut rng))),
                // Arc::new(Mutex::new(DenseMLPolyStream::rand(nv, &mut rng))),
            ];
            // s_perm is the identity map

            assert!(test_permutation_check_helper::<Fr>(fs, gs, id_perms, id_perms_2).is_err());
        }

        Ok(())
    }

    #[test]
    fn test_normal_polynomial() -> Result<(), PolyIOPErrors> {
        test_permutation_check::<Fr>(5)
    }

    #[test]
    fn zero_polynomial_should_error() -> Result<(), PolyIOPErrors> {
        assert!(test_permutation_check::<Fr>(0).is_err());
        Ok(())
    }

    #[test]
    fn calculate_field_for_test() {
        // - 1 - batch_factor (const): 0
        let const_stream = vec![
            Fr::from_str(
                "40744973617062391610337174437753381748580953252093867764620585989552951032455",
            )
            .unwrap(),
            Fr::from_str(
                "40744973617062391610337174437753381748580953252093867764620585989552951032455",
            )
            .unwrap(),
        ];

        // h_p: 1
        let h_p = vec![
            Fr::from_str(
                "21996397529139848876384377638919389586825039307097218089820653239418429039384",
            )
            .unwrap(),
            Fr::from_str(
                "27381181559375337688005045179157799767490277191703804301016616522414594481176",
            )
            .unwrap(),
        ];

        // p: 2
        let p = vec![
            Fr::from_str(
                "46726240763639862128214388288720131204625575015731614850157206947646262134152",
            )
            .unwrap(),
            Fr::from_str(
                "43289727388036023252294560744145593863815462211184144675663927741862919848062",
            )
            .unwrap(),
        ];

        // pi: 3
        let pi = vec![Fr::from_str("0").unwrap(), Fr::from_str("1").unwrap()];

        // h_q: 4
        let h_q = vec![
            Fr::from_str(
                "21996397529139848876384377638919389586825039307097218089820653239418429039384",
            )
            .unwrap(),
            Fr::from_str(
                "27381181559375337688005045179157799767490277191703804301016616522414594481176",
            )
            .unwrap(),
        ];

        // q: 5
        let q = vec![
            Fr::from_str(
                "46726240763639862128214388288720131204625575015731614850157206947646262134152",
            )
            .unwrap(),
            Fr::from_str(
                "43289727388036023252294560744145593863815462211184144675663927741862919848062",
            )
            .unwrap(),
        ];

        // index: 6
        let index = vec![Fr::from_str("0").unwrap(), Fr::from_str("1").unwrap()];

        // eq_x_r: 7
        let eq_x_r = vec![
            Fr::from_str(
                "19058826771326529821285799901014068225982668167321986975491853937558185481750",
            )
            .unwrap(),
            Fr::from_str(
                "33377048403799660658161940607171897611707884333205650847111804762380395702764",
            )
            .unwrap(),
        ];

        // 1 * (- 1 - batch_factor) * eq_x_r
        // prover final_poly coeff: 1, products: [0, 7]

        // 1 * h_p * p * eq_x_r
        // prover final_poly coeff: 1, products: [1, 2, 7]

        // alpha * h_p * pi * eq_x_r
        // prover final_poly coeff: 46768989744111976527193404927882014417138686501367131404245902097480820692517, products: [1, 3, 7]

        // batch_factor * h_q * q * eq_x_r
        // prover final_poly coeff: 11690901558063798869110566070432584089109599248433770057983072710385630152057, products: [4, 5, 7]

        // (alpha * batch_factor) * h_q * index * eq_x_r
        // prover final_poly coeff: 45013647124392960146610703642441223468120771381231137560614344880249679433230, products: [4, 6, 7]

        // batch_factor * batch_factor * h_p
        // prover final_poly coeff: 31813992623836710996112529321322891097929226721012340238743082530274941758853, products: [1]

        // - batch_factor * batch_factor * h_q
        // prover final_poly coeff: 20621882551289479483335211186863074739761325779515297583860576169663639425660, products: [4]

        let alpha = Fr::from_str(
            "46768989744111976527193404927882014417138686501367131404245902097480820692517",
        )
        .unwrap();
        let batch_factor = Fr::from_str(
            "11690901558063798869110566070432584089109599248433770057983072710385630152057",
        )
        .unwrap();
        let r = Fr::from_str(
            "33377048403799660658161940607171897611707884333205650847111804762380395702764",
        )
        .unwrap();

        let one_minus_r = Fr::ONE - r;
        println!("1 - r: {}", one_minus_r); // 19058826771326529821285799901014068225982668167321986975491853937558185481750

        let batch_factor_squared = batch_factor * batch_factor;
        println!("batch_factor^2: {}", batch_factor_squared); // 31813992623836710996112529321322891097929226721012340238743082530274941758853

        let neg_batch_factor_squared = -batch_factor_squared;
        println!("-batch_factor^2: {}", neg_batch_factor_squared); // 20621882551289479483335211186863074739761325779515297583860576169663639425660

        let alpha_batch_factor = alpha * batch_factor;
        println!("alpha * batch_factor: {}", alpha_batch_factor); // 45013647124392960146610703642441223468120771381231137560614344880249679433230

        let minus_one_minus_batch_factor = -Fr::ONE - batch_factor;
        println!("- 1 - batch_factor: {}", minus_one_minus_batch_factor); // 40744973617062391610337174437753381748580953252093867764620585989552951032455

        // let h_q = q.iter().map(|q| x * x).collect::<Vec<Fr>>();

        // prover messages
    }
}
