use crate::{hyperplonk::{
    pcs::PolynomialCommitmentScheme,
    poly_iop::{
        errors::PolyIOPErrors,
        prod_check::util::{compute_frac_poly, compute_product_poly, prove_zero_check},
        zero_check::ZeroCheck,
        PolyIOP,
    },
}, read_write::DenseMLPolyStream};
use crate::hyperplonk::arithmetic::virtual_polynomial::VPAuxInfo;
use ark_ec::pairing::Pairing;
use ark_ff::{One, PrimeField, Zero};
use ark_poly::DenseMultilinearExtension;
use ark_std::{end_timer, start_timer};
use std::sync::{Arc, Mutex};
use crate::hyperplonk::transcript::IOPTranscript;

mod util;

/// A product-check proves that two lists of n-variate multilinear polynomials
/// `(f1, f2, ..., fk)` and `(g1, ..., gk)` satisfy:
/// \prod_{x \in {0,1}^n} f1(x) * ... * fk(x) = \prod_{x \in {0,1}^n} g1(x) *
/// ... * gk(x)
///
/// A ProductCheck is derived from ZeroCheck.
///
/// Prover steps:
/// 1. build MLE `frac(x)` s.t. `frac(x) = f1(x) * ... * fk(x) / (g1(x) * ... *
/// gk(x))` for all x \in {0,1}^n 2. build `prod(x)` from `frac(x)`, where
/// `prod(x)` equals to `v(1,x)` in the paper 2. push commitments of `frac(x)`
/// and `prod(x)` to the transcript,    and `generate_challenge` from current
/// transcript (generate alpha) 3. generate the zerocheck proof for the virtual
/// polynomial Q(x):       prod(x) - p1(x) * p2(x)
///     + alpha * frac(x) * g1(x) * ... * gk(x)
///     - alpha * f1(x) * ... * fk(x)
/// where p1(x) = (1-x1) * frac(x2, ..., xn, 0)
///             + x1 * prod(x2, ..., xn, 0),
/// and p2(x) = (1-x1) * frac(x2, ..., xn, 1)
///           + x1 * prod(x2, ..., xn, 1)
///
/// Verifier steps:
/// 1. Extract commitments of `frac(x)` and `prod(x)` from the proof, push
/// them to the transcript
/// 2. `generate_challenge` from current transcript (generate alpha)
/// 3. `verify` to verify the zerocheck proof and generate the subclaim for
/// polynomial evaluations
pub trait ProductCheck<E, PCS>: ZeroCheck<E::ScalarField>
where
    E: Pairing,
    PCS: PolynomialCommitmentScheme<E>,
{
    type ProductCheckSubClaim;
    type ProductCheckProof;

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
        pcs_param: &PCS::ProverParam,
        fxs: Vec<Self::MultilinearExtension>,
        gxs: Vec<Self::MultilinearExtension>,
        transcript: &mut IOPTranscript<E::ScalarField>,
    ) -> Result<
        (
            Self::ProductCheckProof,
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
        proof: &Self::ProductCheckProof,
        aux_info: &VPAuxInfo<E::ScalarField>,
        transcript: &mut Self::Transcript,
    ) -> Result<Self::ProductCheckSubClaim, PolyIOPErrors>;
}

/// A product check subclaim consists of
/// - A zero check IOP subclaim for the virtual polynomial
/// - The random challenge `alpha`
/// - A final query for `prod(1, ..., 1, 0) = 1`.
// Note that this final query is in fact a constant that
// is independent from the proof. So we should avoid
// (de)serialize it.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ProductCheckSubClaim<F: PrimeField, ZC: ZeroCheck<F>> {
    // the SubClaim from the ZeroCheck
    pub zero_check_sub_claim: ZC::ZeroCheckSubClaim,
    // final query which consists of
    // - the vector `(1, ..., 1, 0)` (needs to be reversed because Arkwork's MLE uses big-endian
    //   format for points)
    // The expected final query evaluation is 1
    pub final_query: (Vec<F>, F),
    pub alpha: F,
}

/// A product check proof consists of
/// - a zerocheck proof
/// - a product polynomial commitment
/// - a polynomial commitment for the fractional polynomial
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ProductCheckProof<
    E: Pairing,
    PCS: PolynomialCommitmentScheme<E>,
    ZC: ZeroCheck<E::ScalarField>,
> {
    pub zero_check_proof: ZC::ZeroCheckProof,
    pub prod_x_comm: PCS::Commitment,
    pub frac_comm: PCS::Commitment,
}

impl<E, PCS> ProductCheck<E, PCS> for PolyIOP<E::ScalarField>
where
    E: Pairing,
    PCS: PolynomialCommitmentScheme<E, Polynomial = Arc<Mutex<DenseMLPolyStream<E::ScalarField>>>>,
{
    type ProductCheckSubClaim = ProductCheckSubClaim<E::ScalarField, Self>;
    type ProductCheckProof = ProductCheckProof<E, PCS, Self>;

    fn init_transcript() -> Self::Transcript {
        IOPTranscript::<E::ScalarField>::new(b"Initializing ProductCheck transcript")
    }

    fn prove(
        pcs_param: &PCS::ProverParam,
        fxs: Vec<Self::MultilinearExtension>,
        gxs: Vec<Self::MultilinearExtension>,
        transcript: &mut IOPTranscript<E::ScalarField>,
    ) -> Result<
        (
            Self::ProductCheckProof,
            Self::MultilinearExtension,
            Self::MultilinearExtension,
        ),
        PolyIOPErrors,
    > {
        let start = start_timer!(|| "prod_check prove");

        if fxs.is_empty() {
            return Err(PolyIOPErrors::InvalidParameters("fxs is empty".to_string()));
        }
        if fxs.len() != gxs.len() {
            return Err(PolyIOPErrors::InvalidParameters(
                "fxs and gxs have different number of polynomials".to_string(),
            ));
        }
        for poly in fxs.iter().chain(gxs.iter()) {
            if poly.lock().unwrap().num_vars != fxs[0].lock().unwrap().num_vars {
                return Err(PolyIOPErrors::InvalidParameters(
                    "fx and gx have different number of variables".to_string(),
                ));
            }
        }

        // compute the fractional polynomial frac_p s.t.
        // frac_p(x) = f1(x) * ... * fk(x) / (g1(x) * ... * gk(x))
        let frac_poly = compute_frac_poly(fxs.clone(), gxs.clone())?;
        // compute the product polynomial
        let prod_x = compute_product_poly(&frac_poly, 1 << 20)?;

        // generate challenge
        let frac_comm = PCS::commit(pcs_param, &frac_poly)?;
        let prod_x_comm = PCS::commit(pcs_param, &prod_x)?;
        transcript.append_serializable_element(b"frac(x)", &frac_comm)?;
        transcript.append_serializable_element(b"prod(x)", &prod_x_comm)?;
        let alpha = transcript.get_and_append_challenge(b"alpha")?;

        // build the zero-check proof
        let (zero_check_proof, _) =
            prove_zero_check(fxs, gxs, &frac_poly, &prod_x, &alpha, transcript, 1 << 20)?;

        end_timer!(start);

        Ok((
            ProductCheckProof {
                zero_check_proof,
                prod_x_comm,
                frac_comm,
            },
            prod_x,
            frac_poly,
        ))
    }

    fn verify(
        proof: &Self::ProductCheckProof,
        aux_info: &VPAuxInfo<E::ScalarField>,
        transcript: &mut Self::Transcript,
    ) -> Result<Self::ProductCheckSubClaim, PolyIOPErrors> {
        let start = start_timer!(|| "prod_check verify");

        // update transcript and generate challenge
        transcript.append_serializable_element(b"frac(x)", &proof.frac_comm)?;
        transcript.append_serializable_element(b"prod(x)", &proof.prod_x_comm)?;
        let alpha = transcript.get_and_append_challenge(b"alpha")?;

        // invoke the zero check on the iop_proof
        // the virtual poly info for Q(x)
        let zero_check_sub_claim = <Self as ZeroCheck<E::ScalarField>>::verify(
            &proof.zero_check_proof,
            aux_info,
            transcript,
        )?;

        // the final query is on prod_x
        // little endian version of [1, 1, 1, ..., 1, 0], i.e. the final product, which should be 1 for permu check
        let mut final_query = vec![E::ScalarField::one(); aux_info.num_variables];
        // the point has to be reversed because Arkworks uses big-endian.
        final_query[0] = E::ScalarField::zero();
        let final_eval = E::ScalarField::one();

        end_timer!(start);

        Ok(ProductCheckSubClaim {
            zero_check_sub_claim,
            final_query: (final_query, final_eval),
            alpha,
        })
    }
}

#[cfg(test)]
mod test {
    use super::ProductCheck;
    use crate::{hyperplonk::{
        pcs::{prelude::MultilinearKzgPCS, PolynomialCommitmentScheme},
        poly_iop::{errors::PolyIOPErrors, PolyIOP},
    }, read_write::{copy_mle, DenseMLPolyStream, ReadWriteStream}};
    use crate::hyperplonk::arithmetic::virtual_polynomial::VPAuxInfo;
    use ark_bls12_381::{Bls12_381, Fr};
    use ark_ec::pairing::Pairing;
    use ark_std::test_rng;
    use std::{marker::PhantomData, sync::{Arc, Mutex}};
    use ark_std::UniformRand;

    fn check_frac_poly<E>(
        frac_poly: &Arc<Mutex<DenseMLPolyStream<E::ScalarField>>>,
        fs: Vec<Arc<Mutex<DenseMLPolyStream<E::ScalarField>>>>,
        gs: Vec<Arc<Mutex<DenseMLPolyStream<E::ScalarField>>>>,
    ) where
        E: Pairing,
    {
        let mut flag = true;
        let num_vars = frac_poly.lock().unwrap().num_vars;
        while let Some(frac) = frac_poly.lock().unwrap().read_next() {
            let nom = fs
                .iter()
                .fold(E::ScalarField::from(1u8), |acc, f| acc * f.lock().unwrap().read_next().unwrap());
            let denom = gs
                .iter()
                .fold(E::ScalarField::from(1u8), |acc, g| acc * g.lock().unwrap().read_next().unwrap());
            if denom * frac != nom {
                flag = false;
                break;
            }
        }
        assert!(flag);
    }
    // fs and gs are guaranteed to have the same product
    // fs and hs doesn't have the same product
    fn test_product_check_helper<E, PCS>(
        fs: Vec<Arc<Mutex<DenseMLPolyStream<E::ScalarField>>>>,
        gs: Vec<Arc<Mutex<DenseMLPolyStream<E::ScalarField>>>>,
        hs: Vec<Arc<Mutex<DenseMLPolyStream<E::ScalarField>>>>,
        pcs_param: &PCS::ProverParam,
    ) -> Result<(), PolyIOPErrors>
    where
        E: Pairing,
        PCS: PolynomialCommitmentScheme<
            E,
            Polynomial = Arc<Mutex<DenseMLPolyStream<E::ScalarField>>>,
        >,
    {
        let mut transcript = <PolyIOP<E::ScalarField> as ProductCheck<E, PCS>>::init_transcript();
        transcript.append_message(b"testing", b"initializing transcript for testing")?;

        let num_vars = fs[0].lock().unwrap().num_vars;
        let fs_copy: Vec<Arc<Mutex<DenseMLPolyStream<E::ScalarField>>>> = fs.iter().map(|f| {
            copy_mle(f, None, None)
        }).collect();

        let gs_copy: Vec<Arc<Mutex<DenseMLPolyStream<E::ScalarField>>>> = gs.iter().map(|g| {
            copy_mle(g, None, None)
        }).collect();

        let (proof, prod_x, frac_poly) = <PolyIOP<E::ScalarField> as ProductCheck<E, PCS>>::prove(
            pcs_param,
            fs_copy.clone(),
            gs_copy.clone(),
            &mut transcript,
        )?;

        let mut transcript = <PolyIOP<E::ScalarField> as ProductCheck<E, PCS>>::init_transcript();
        transcript.append_message(b"testing", b"initializing transcript for testing")?;

        // what's aux_info for?
        let aux_info = VPAuxInfo {
            max_degree: fs_copy.len() + 1,
            num_variables: num_vars,
            phantom: PhantomData::default(),
        };
        let prod_subclaim = <PolyIOP<E::ScalarField> as ProductCheck<E, PCS>>::verify(
            &proof,
            &aux_info,
            &mut transcript,
        )?;
        assert_eq!(
            prod_x.lock().unwrap().evaluate(std::slice::from_ref(&prod_subclaim.final_query.0.last().unwrap())).unwrap(),
            prod_subclaim.final_query.1,
            "different product"
        );

        check_frac_poly::<E>(&frac_poly, fs_copy, gs_copy);

        // bad path
        let mut transcript = <PolyIOP<E::ScalarField> as ProductCheck<E, PCS>>::init_transcript();
        transcript.append_message(b"testing", b"initializing transcript for testing")?;

        let (bad_proof, prod_x_bad, frac_poly) = <PolyIOP<E::ScalarField> as ProductCheck<
            E,
            PCS,
        >>::prove(
            pcs_param, fs.clone(), hs.clone(), &mut transcript
        )?;

        let mut transcript = <PolyIOP<E::ScalarField> as ProductCheck<E, PCS>>::init_transcript();
        transcript.append_message(b"testing", b"initializing transcript for testing")?;
        let bad_subclaim = <PolyIOP<E::ScalarField> as ProductCheck<E, PCS>>::verify(
            &bad_proof,
            &aux_info,
            &mut transcript,
        )?;
        assert_ne!(
            prod_x_bad.lock().unwrap().evaluate(std::slice::from_ref(&bad_subclaim.final_query.0.last().unwrap())).unwrap(),
            bad_subclaim.final_query.1,
            "can't detect wrong proof"
        );
        // the frac_poly should still be computed correctly
        check_frac_poly::<E>(&frac_poly, fs, hs);

        Ok(())
    }

    fn test_product_check(nv: usize) -> Result<(), PolyIOPErrors> {
        let mut rng = test_rng();

        // get a random vector with 1 << nv elements
        let rand_vals = (0..1 << nv)
            .map(|_| Fr::rand(&mut rng))
            .collect::<Vec<Fr>>();
        let rand_vals_reverse = rand_vals.iter().rev().cloned().collect::<Vec<Fr>>();
        let f1: DenseMLPolyStream<Fr> = DenseMLPolyStream::from_evaluations_vec(nv, rand_vals, None, None);
        let g1: DenseMLPolyStream<Fr> = DenseMLPolyStream::from_evaluations_vec(nv, rand_vals_reverse, None, None);
        
        // get another random vector with 1 << nv elements
        let rand_vals_2 = (0..1 << nv)
            .map(|_| Fr::rand(&mut rng))
            .collect::<Vec<Fr>>();
        let rand_vals_2_reverse = rand_vals_2.iter().rev().cloned().collect::<Vec<Fr>>();
        let f2: DenseMLPolyStream<Fr> = DenseMLPolyStream::from_evaluations_vec(nv, rand_vals_2, None, None);
        let g2: DenseMLPolyStream<Fr> = DenseMLPolyStream::from_evaluations_vec(nv, rand_vals_2_reverse, None, None);
        
        let fs = vec![Arc::new(Mutex::new(f1)), Arc::new(Mutex::new(f2))];
        let gs = vec![Arc::new(Mutex::new(g1)), Arc::new(Mutex::new(g2))];
        let mut hs = vec![];
        for _ in 0..fs.len() {
            hs.push(Arc::new(Mutex::new(DenseMLPolyStream::rand(
                nv,
                &mut rng,
            ))));
        }

        let srs = MultilinearKzgPCS::<Bls12_381>::gen_srs_for_testing(&mut rng, nv)?;
        let (pcs_param, _) = MultilinearKzgPCS::<Bls12_381>::trim(&srs, None, Some(nv))?;

        test_product_check_helper::<Bls12_381, MultilinearKzgPCS<Bls12_381>>(
            fs, gs, hs, &pcs_param,
        )?;

        Ok(())
    }

    #[test]
    fn test_trivial_polynomial() -> Result<(), PolyIOPErrors> {
        test_product_check(1)
    }
    #[test]
    fn test_normal_polynomial() -> Result<(), PolyIOPErrors> {
        test_product_check(10)
    }
}
