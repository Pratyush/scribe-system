use crate::{
    pc::PCScheme,
    piop::{
        errors::PIOPError,
        prod_check::util::{compute_frac_poly, compute_product_poly, prove_zero_check},
        zero_check::ZeroCheck,
    },
    transcript::IOPTranscript,
};
use ark_ec::pairing::Pairing;
use ark_ff::{One, Zero};
use mle::{MLE, virtual_polynomial::VPAuxInfo};
use scribe_streams::serialize::RawPrimeField;

use ark_std::{end_timer, start_timer};

use super::zero_check::{ZeroCheckProof, ZeroCheckSubClaim};

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
///    gk(x))` for all x \in {0,1}^n 2. build `prod(x)` from `frac(x)`, where
///    `prod(x)` equals to `v(1,x)` in the paper 2. push commitments of `frac(x)`
///    and `prod(x)` to the transcript,    and `generate_challenge` from current
///    transcript (generate alpha) 3. generate the zerocheck proof for the virtual
///    polynomial Q(x):       prod(x) - p1(x) * p2(x)
///        + alpha * frac(x) * g1(x) * ... * gk(x)
///        - alpha * f1(x) * ... * fk(x)
///    where p1(x) = (1-x1) * frac(x2, ..., xn, 0)
///                + x1 * prod(x2, ..., xn, 0),
///    and p2(x) = (1-x1) * frac(x2, ..., xn, 1)
///           + x1 * prod(x2, ..., xn, 1)
///
/// Verifier steps:
/// 1. Extract commitments of `frac(x)` and `prod(x)` from the proof, push
///    them to the transcript
/// 2. `generate_challenge` from current transcript (generate alpha)
/// 3. `verify` to verify the zerocheck proof and generate the subclaim for
///    polynomial evaluations
pub struct ProductCheck<E, PC>(std::marker::PhantomData<(E, PC)>);

/// A product check subclaim consists of
/// - A zero check IOP subclaim for the virtual polynomial
/// - The random challenge `alpha`
/// - A final query for `prod(1, ..., 1, 0) = 1`.
// Note that this final query is in fact a constant that
// is independent from the proof. So we should avoid
// (de)serialize it.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ProductCheckSubClaim<F: RawPrimeField> {
    // the SubClaim from the ZeroCheck
    pub zero_check_sub_claim: ZeroCheckSubClaim<F>,
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
pub struct ProductCheckProof<E: Pairing, PC: PCScheme<E>>
where
    E::ScalarField: RawPrimeField,
{
    pub zero_check_proof: ZeroCheckProof<E::ScalarField>,
    pub prod_x_comm: PC::Commitment,
    pub frac_comm: PC::Commitment,
}

impl<E, PC> ProductCheck<E, PC>
where
    E: Pairing,
    E::ScalarField: RawPrimeField,
    PC: PCScheme<E, Polynomial = MLE<E::ScalarField>>,
{
    pub fn init_transcript() -> IOPTranscript<E::ScalarField> {
        IOPTranscript::<E::ScalarField>::new(b"Initializing ProductCheck transcript")
    }

    pub fn prove(
        ck: &PC::CommitterKey,
        fxs: &[MLE<E::ScalarField>],
        gxs: &[MLE<E::ScalarField>],
        transcript: &mut IOPTranscript<E::ScalarField>,
    ) -> Result<
        (
            ProductCheckProof<E, PC>,
            MLE<E::ScalarField>,
            MLE<E::ScalarField>,
        ),
        PIOPError,
    > {
        let start = start_timer!(|| "prod_check prove");

        if fxs.is_empty() {
            return Err(PIOPError::InvalidParameters("fxs is empty".to_string()));
        }
        if fxs.len() != gxs.len() {
            return Err(PIOPError::InvalidParameters(
                "fxs and gxs have different number of polynomials".to_string(),
            ));
        }
        for poly in fxs.iter().chain(gxs.iter()) {
            if poly.num_vars() != fxs[0].num_vars() {
                return Err(PIOPError::InvalidParameters(
                    "fx and gx have different number of variables".to_string(),
                ));
            }
        }

        // compute the fractional polynomial frac_p s.t.
        // frac_p(x) = f1(x) * ... * fk(x) / (g1(x) * ... * gk(x))
        let frac_poly = compute_frac_poly(fxs, gxs)?;
        // compute the product polynomial
        let prod_x = compute_product_poly(&frac_poly)?;

        // generate challenge

        let commit_time = start_timer!(|| "prod_check commit");
        let [frac_comm, prod_x_comm] = PC::batch_commit(ck, &[frac_poly.clone(), prod_x.clone()])?
            .as_slice()
            .try_into()
            .unwrap();
        end_timer!(commit_time);
        transcript.append_serializable_element(b"frac(x)", &frac_comm)?;
        transcript.append_serializable_element(b"prod(x)", &prod_x_comm)?;
        let alpha = transcript.get_and_append_challenge(b"alpha")?;

        let (zero_check_proof, _) =
            prove_zero_check(fxs, gxs, &frac_poly, &prod_x, &alpha, transcript)?;

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

    pub fn verify(
        proof: &ProductCheckProof<E, PC>,
        aux_info: &VPAuxInfo<E::ScalarField>,
        transcript: &mut IOPTranscript<E::ScalarField>,
    ) -> Result<ProductCheckSubClaim<E::ScalarField>, PIOPError> {
        let start = start_timer!(|| "prod_check verify");

        // update transcript and generate challenge
        transcript.append_serializable_element(b"frac(x)", &proof.frac_comm)?;
        transcript.append_serializable_element(b"prod(x)", &proof.prod_x_comm)?;
        let alpha = transcript.get_and_append_challenge(b"alpha")?;

        // invoke the zero check on the iop_proof
        // the virtual poly info for Q(x)
        let zero_check_sub_claim =
            ZeroCheck::<E::ScalarField>::verify(&proof.zero_check_proof, aux_info, transcript)?;

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
    use crate::{
        pc::{PCScheme, pst13::PST13},
        piop::errors::PIOPError,
    };
    use ark_bls12_381::{Bls12_381, Fr};
    use ark_ec::pairing::Pairing;
    use ark_std::UniformRand;
    use ark_std::test_rng;
    use mle::{MLE, virtual_polynomial::VPAuxInfo};
    use scribe_streams::file_vec::FileVec;
    use scribe_streams::iterator::BatchedIterator;
    use scribe_streams::iterator::zip_many;
    use scribe_streams::serialize::RawPrimeField;
    use std::marker::PhantomData;

    fn check_frac_poly<E>(
        frac_poly: &MLE<E::ScalarField>,
        fs: &[MLE<E::ScalarField>],
        gs: &[MLE<E::ScalarField>],
    ) where
        E: Pairing,
        E::ScalarField: RawPrimeField,
    {
        let nom: FileVec<E::ScalarField> = zip_many(fs.iter().map(|f| f.evals().iter()))
            .map(|fs| fs.iter().product())
            .to_file_vec();

        let denom: FileVec<E::ScalarField> = zip_many(gs.iter().map(|g| g.evals().iter()))
            .map(|gs| gs.iter().product())
            .to_file_vec();

        zip_many(vec![nom.iter(), denom.iter(), frac_poly.evals().iter()]).for_each(
            |vals| assert!(vals[0] == vals[1] * vals[2]), // nom == denom * frac
        );
    }

    #[test]
    fn test_check_frac_poly() {
        let f1 = MLE::from_evals_vec(vec![Fr::from(2), Fr::from(3)], 1);
        let f2 = MLE::from_evals_vec(vec![Fr::from(4), Fr::from(6)], 1);
        let fs = vec![f1, f2];
        let g1 = MLE::from_evals_vec(vec![Fr::from(2), Fr::from(1)], 1);
        let g2 = MLE::from_evals_vec(vec![Fr::from(1), Fr::from(2)], 1);
        let gs = vec![g1, g2];
        let frac_poly = MLE::from_evals_vec(vec![Fr::from(4), Fr::from(9)], 1);

        check_frac_poly::<Bls12_381>(&frac_poly, &fs, &gs);
    }

    // fs and gs are guaranteed to have the same product
    // fs and hs doesn't have the same product
    fn test_product_check_helper<E, PC>(
        fs: &[MLE<E::ScalarField>],
        gs: &[MLE<E::ScalarField>],
        hs: &[MLE<E::ScalarField>],
        pcs_param: &PC::CommitterKey,
    ) -> Result<(), PIOPError>
    where
        E: Pairing,
        E::ScalarField: RawPrimeField,
        PC: PCScheme<E, Polynomial = MLE<E::ScalarField>>,
    {
        let mut transcript = ProductCheck::<E, PC>::init_transcript();
        transcript.append_message(b"testing", b"initializing transcript for testing")?;

        let (proof, prod_x, frac_poly) =
            ProductCheck::<E, PC>::prove(pcs_param, fs, gs, &mut transcript)?;

        let mut transcript = ProductCheck::<E, PC>::init_transcript();
        transcript.append_message(b"testing", b"initializing transcript for testing")?;

        // what's aux_info for?
        let aux_info = VPAuxInfo {
            max_degree: fs.len() + 1,
            num_variables: fs[0].num_vars(),
            phantom: PhantomData::default(),
        };
        let prod_subclaim = ProductCheck::<E, PC>::verify(&proof, &aux_info, &mut transcript)?;
        assert_eq!(
            prod_x.evaluate(&prod_subclaim.final_query.0).unwrap(),
            prod_subclaim.final_query.1,
            "different product"
        );
        check_frac_poly::<E>(&frac_poly, fs, gs);

        // bad path
        let mut transcript = ProductCheck::<E, PC>::init_transcript();
        transcript.append_message(b"testing", b"initializing transcript for testing")?;

        let (bad_proof, _prod_x_bad, frac_poly) =
            ProductCheck::<E, PC>::prove(pcs_param, fs, hs, &mut transcript)?;

        let mut transcript = ProductCheck::<E, PC>::init_transcript();
        transcript.append_message(b"testing", b"initializing transcript for testing")?;
        let bad_subclaim = ProductCheck::<E, PC>::verify(&bad_proof, &aux_info, &mut transcript);
        assert!(bad_subclaim.is_err());
        // the frac_poly should still be computed correctly
        check_frac_poly::<E>(&frac_poly, &fs, &hs);

        Ok(())
    }

    fn test_product_check(nv: usize) -> Result<(), PIOPError> {
        let mut rng = test_rng();

        let f1_evals = (0..(1 << nv))
            .map(|_| Fr::rand(&mut rng))
            .collect::<Vec<Fr>>();
        let f2_evals = (0..(1 << nv))
            .map(|_| Fr::rand(&mut rng))
            .collect::<Vec<Fr>>();

        let mut g1_evals = f1_evals.clone();
        let mut g2_evals = f2_evals.clone();

        g1_evals.reverse();
        g2_evals.reverse();

        let f1 = MLE::from_evals_vec(f1_evals, nv);
        let f2 = MLE::from_evals_vec(f2_evals, nv);

        let g1 = MLE::from_evals_vec(g1_evals, nv);
        let g2 = MLE::from_evals_vec(g2_evals, nv);

        let h1 = MLE::rand(nv, &mut rng);
        let h2 = MLE::rand(nv, &mut rng);

        let fs = vec![f1, f2];
        let gs = vec![g1, g2];
        let hs = vec![h1, h2];

        let srs = PST13::<Bls12_381>::gen_srs_for_testing(&mut rng, nv)?;
        let (pcs_param, _) = PST13::trim(&srs, nv)?;

        test_product_check_helper::<Bls12_381, PST13<Bls12_381>>(&fs, &gs, &hs, &pcs_param)?;

        Ok(())
    }

    #[test]
    fn test_trivial_polynomial() -> Result<(), PIOPError> {
        test_product_check(2)
    }

    #[test]
    fn test_normal_polynomial() -> Result<(), PIOPError> {
        test_product_check(10)
    }
}
