use crate::hyperplonk::transcript::IOPTranscript;
use crate::{
    arithmetic::virtual_polynomial::VirtualPolynomial,
    streams::{
        file_vec::FileVec,
        iterator::{chain_many, zip_many, BatchedIterator},
        MLE,
    },
};
use crate::{
    hyperplonk::poly_iop::{errors::PIOPError, structs::IOPProof, zero_check::ZeroCheck, PolyIOP},
    streams::serialize::RawPrimeField,
};

use ark_std::{end_timer, start_timer};

/// Compute multilinear fractional polynomial s.t. frac(x) = f1(x) * ... * fk(x)
/// / (g1(x) * ... * gk(x)) for all x \in {0,1}^n
///
/// The caller needs to sanity-check that the number of polynomials and
/// variables match in fxs and gxs; and gi(x) has no zero entries.
pub(super) fn compute_frac_poly<F: RawPrimeField>(
    fxs: &[MLE<F>],
    gxs: &[MLE<F>],
) -> Result<MLE<F>, PIOPError> {
    let start = start_timer!(|| "compute frac(x)");

    let numerator_product =
        zip_many(fxs.iter().map(|p| p.evals().iter())).map(|v| v.into_iter().product::<F>());
    let denominator_evals = zip_many(gxs.iter().map(|p| p.evals().iter()))
        .map(|v| v.into_iter().product())
        .to_file_vec();
    let mut denominator = MLE::from_evals(denominator_evals, gxs[0].num_vars());
    denominator.invert_in_place();
    denominator
        .evals_mut()
        .zipped_for_each(numerator_product, |den_inv, num| {
            *den_inv *= num;
        });
    let result = denominator;

    end_timer!(start);
    Ok(result)
}

/// Compute the product polynomial `prod(x)` such that
/// `prod(x) = [(1-x1)*frac(x2, ..., xn, 0) + x1*prod(x2, ..., xn, 0)] *
/// [(1-x1)*frac(x2, ..., xn, 1) + x1*prod(x2, ..., xn, 1)]` on the boolean
/// hypercube {0,1}^n
///
/// The caller needs to check num_vars matches in f and g
/// Cost: linear in N.
pub(super) fn compute_product_poly<F: RawPrimeField>(
    frac_poly: &MLE<F>,
) -> Result<MLE<F>, PIOPError> {
    let start = start_timer!(|| "compute evaluations of prod polynomial");
    let num_vars = frac_poly.num_vars();
    // assert that num_vars is at least two

    // single stream for read and write pointers
    let product = frac_poly.fold_odd_even(|a, b| *a * b);
    let mut products = vec![product];
    while products.last().unwrap().num_vars() > 0 {
        let product = products.last().unwrap();
        products.push(product.fold_odd_even(|a, b| *a * b));
    }
    products.push(MLE::from_evals_vec(vec![F::one()], 0));
    let evals = chain_many(products.iter().map(|p| p.evals().iter())).to_file_vec();
    let product = MLE::from_evals(evals, num_vars);
    end_timer!(start);
    Ok(product)
}

/// generate the zerocheck proof for the virtual polynomial
///    prod(x) - p1(x) * p2(x) + alpha * [frac(x) * g1(x) * ... * gk(x) - f1(x)
/// * ... * fk(x)] where p1(x) = (1-x1) * frac(x2, ..., xn, 0) + x1 * prod(x2,
///   ..., xn, 0), p2(x) = (1-x1) * frac(x2, ..., xn, 1) + x1 * prod(x2, ...,
///   xn, 1)
/// Returns proof.
///
/// Cost: O(N)
pub(super) fn prove_zero_check<F: RawPrimeField>(
    fxs: &[MLE<F>],
    gxs: &[MLE<F>],
    frac_poly: &MLE<F>,
    prod_x: &MLE<F>,
    alpha: &F,
    transcript: &mut IOPTranscript<F>,
) -> Result<(IOPProof<F>, VirtualPolynomial<F>), PIOPError> {
    // this is basically a batch zero check with alpha as the batch factor
    // the first zero check is prod(x) - p1(x) * p2(x),
    // which is checking that prod is computed correctly from frac_poly in the first half
    // and computed correctly from prod itself in the second half
    // the second zero check is frac * g1 * ... * gk - f1 * ... * fk
    // which is checking that frac is computed correctly from fxs and gxs
    let start = start_timer!(|| "zerocheck in product check");

    println!("printed zero check");
    frac_poly
        .evals()
        .deep_copy()
        .for_each(|e| println!("frac_poly eval: {}", e));
    prod_x
        .evals()
        .deep_copy()
        .for_each(|e| println!("prod_x eval: {}", e));

    let (p1, p2): (FileVec<F>, FileVec<F>) = chain_many(
        vec![frac_poly, prod_x]
            .iter()
            .map(|mle| (*mle).evals().iter().array_chunks()),
    )
    .map(|[even, odd]| (even, odd))
    .unzip_faster();

    let num_vars = frac_poly.num_vars();

    // compute Q(x)
    // prod(x)
    let mut q_x = VirtualPolynomial::new_from_mle(prod_x, F::one());

    //   prod(x)
    // - p1(x) * p2(x)
    q_x.add_mles(
        [MLE::from_evals(p1, num_vars), MLE::from_evals(p2, num_vars)],
        -F::one(),
    )?;

    //   prod(x)
    // - p1(x) * p2(x)
    // + alpha * frac(x) * g1(x) * ... * gk(x)
    let mut mle_list = gxs.to_vec();
    mle_list.push(frac_poly.clone());
    q_x.add_mles(mle_list, *alpha)?;

    //   prod(x)
    // - p1(x) * p2(x)
    // + alpha * frac(x) * g1(x) * ... * gk(x)
    // - alpha * f1(x) * ... * fk(x)]
    q_x.add_mles(fxs.to_vec(), -*alpha)?;

    let iop_proof = <PolyIOP<F> as ZeroCheck<F>>::prove(&q_x, transcript)?;

    end_timer!(start);
    Ok((iop_proof, q_x))
}

#[cfg(test)]
mod test {
    use super::compute_product_poly;
    use super::*;

    use crate::streams::MLE;
    use ark_bls12_381::Fr;

    use ark_std::rand::distributions::{Distribution, Standard};
    use ark_std::rand::rngs::StdRng;
    use ark_std::rand::SeedableRng;

    use std::vec::Vec;

    // in memory vector version of calculating the prod_poly from frac_poly
    fn compute_product_poly_in_memory<F: RawPrimeField>(
        frac_poly: Vec<F>,
        num_vars: usize,
    ) -> Vec<F> {
        assert!(frac_poly.len() == (1 << num_vars));

        let mut prod_poly = Vec::with_capacity(frac_poly.len());

        let mut offset = 0;

        for round in 1..=num_vars {
            if round == 1 {
                for i in 0..1 << (num_vars - round) {
                    prod_poly.push(frac_poly[2 * i] * frac_poly[2 * i + 1]);
                }
            } else {
                for i in 0..1 << (num_vars - round) {
                    prod_poly.push(prod_poly[offset + 2 * i] * prod_poly[offset + 2 * i + 1]);
                }
                offset += 1 << (num_vars - round + 1);
            }
        }

        prod_poly.push(F::from(1u64));
        assert!(prod_poly.len() == 1 << num_vars);

        prod_poly
    }

    #[test]
    fn test_compute_product_poly_in_memory() {
        // create a stream with values 1, 2, 3, 4
        let frac_poly = vec![
            Fr::from(1u64),
            Fr::from(2u64),
            Fr::from(3u64),
            Fr::from(4u64),
        ];
        let num_vars = 2;
        let prod_poly = compute_product_poly_in_memory(frac_poly, num_vars);
        assert_eq!(
            prod_poly,
            vec![
                Fr::from(2u64),
                Fr::from(12u64),
                Fr::from(24u64),
                Fr::from(1)
            ]
        );
    }

    #[test]
    fn test_compute_product_poly() {
        let mut rng = StdRng::seed_from_u64(42); // Fixed seed for reproducibility

        // create vector to populate stream
        let num_vars = 4;
        let mut frac_poly_vec: Vec<Fr> = Vec::with_capacity(1 << num_vars);
        for _i in 0..(1 << num_vars) {
            frac_poly_vec.push(Standard.sample(&mut rng));
        }

        // Create a stream with 2^10 elements
        let mle = MLE::from_evals_vec(frac_poly_vec.clone(), num_vars);

        // Compute the product polynomial
        let result = compute_product_poly(&mle).unwrap();

        // Compute expected
        let expected = MLE::from_evals_vec(
            compute_product_poly_in_memory(frac_poly_vec, num_vars),
            num_vars,
        );

        // compare the two mles
        result
            .evals()
            .iter()
            .zip(expected.evals().iter())
            .for_each(|(a, b)| {
                println!("a: {}, b: {}", a, b);
                // assert_eq!(a, b, "Product polynomial evaluation is incorrect");
            });
    }

    // #[test]
    // fn test_prove_zero_check() {
    //     let nv = 2;
    //     let mut rng = StdRng::seed_from_u64(42); // Fixed seed for reproducibility
    //     let mut transcript = <PolyIOP<Fr> as ProductCheck<E, PCS>>::init_transcript();

    //     // let srs = MultilinearKzgPCS::<Bls12_381>::gen_srs_for_testing(&mut rng, nv).unwrap();
    //     // let (pcs_param, _) = MultilinearKzgPCS::<Bls12_381>::trim(&srs, None, Some(nv)).unwrap();

    //     // create fxs
    //     let f1 = vec![Fr::from(1u64), Fr::from(2u64), Fr::from(3u64), Fr::from(4u64)];
    //     let f2 = vec![Fr::from(5u64), Fr::from(6u64), Fr::from(7u64), Fr::from(8u64)];
    //     let fxs = vec![MLE::from_evals_vec(f1, 2), MLE::from_evals_vec(f2, 2)];

    //     // create gxs
    //     let g1 = vec![Fr::from(1u64), Fr::from(3u64), Fr::from(5u64), Fr::from(7u64)];
    //     let g2 = vec![Fr::from(2u64), Fr::from(4u64), Fr::from(6u64), Fr::from(8u64)];
    //     let gxs = vec![MLE::from_evals_vec(g1, 2), MLE::from_evals_vec(g2, 2)];

    //     // compute the fractional polynomial frac_p s.t.
    //     // frac_p(x) = f1(x) * ... * fk(x) / (g1(x) * ... * gk(x))
    //     let frac_poly = compute_frac_poly(&fxs, &gxs).unwrap();
    //     // compute the product polynomial
    //     let prod_x = compute_product_poly(&frac_poly).unwrap();

    //     // // generate challenge
    //     // let frac_comm = PCS::commit(pcs_param, &frac_poly)?;
    //     // let prod_x_comm = PCS::commit(pcs_param, &prod_x)?;
    //     let alpha = Fr::from(1u64);
    //     // build the zero-check proof
    //     let (zero_check_proof, _) =
    //         prove_zero_check(&fxs, &gxs, &frac_poly, &prod_x, &alpha, transcript)?;

    // }

    // #[test]
    // fn test_prover_zero_check() {
    //     use ark_ff::Field;

    //     // frac_0: 44242769679012723217034031053781908675551403672320194412821837028073177874433
    //     // frac_1: 7490839310732312925635391501169423691098650357218233974657665528562654454931
    //     // frac_2: 13108968793781547619861935127046491459422638125131909455650914674984645296130
    //     // frac_3: 10487175035025238095889548101637193167538110500105527564520731739987716236909
    //     // prod_0: 2809064741524617347113271812938533884161993883956837740496624573210995420599
    //     // prod_1: 31461525105075714287668644304911579502614331500316582693562195219963148710719
    //     // prod_2: 1
    //     // prod_3: 1
    //     // neg_1: 52435875175126190479447740508185965837690552500527637822603658699938581184512
    //     // p1_0: 44242769679012723217034031053781908675551403672320194412821837028073177874433
    //     // p1_1: 13108968793781547619861935127046491459422638125131909455650914674984645296130
    //     // p1_2: 2809064741524617347113271812938533884161993883956837740496624573210995420599
    //     // p1_3: 1
    //     // p2_0: 7490839310732312925635391501169423691098650357218233974657665528562654454931
    //     // p2_1: 10487175035025238095889548101637193167538110500105527564520731739987716236909
    //     // p2_2: 31461525105075714287668644304911579502614331500316582693562195219963148710719
    //     // p2_3: 1

    //     let frac_0 = Fr::from(1)
    //         * Fr::from(5)
    //         * Fr::from(4).inverse().unwrap()
    //         * Fr::from(8).inverse().unwrap();
    //     println!("frac_0: {}", frac_0);

    //     let frac_1 = Fr::from(2)
    //         * Fr::from(6)
    //         * Fr::from(3).inverse().unwrap()
    //         * Fr::from(7).inverse().unwrap();
    //     println!("frac_1: {}", frac_1);

    //     let frac_2 = Fr::from(3)
    //         * Fr::from(7)
    //         * Fr::from(2).inverse().unwrap()
    //         * Fr::from(6).inverse().unwrap();
    //     println!("frac_2: {}", frac_2);

    //     let frac_3 = Fr::from(4)
    //         * Fr::from(8)
    //         * Fr::from(1).inverse().unwrap()
    //         * Fr::from(5).inverse().unwrap();
    //     println!("frac_3: {}", frac_3);

    //     let prod_0 = frac_0 * frac_1;
    //     println!("prod_0: {}", prod_0);

    //     let prod_1 = frac_2 * frac_3;
    //     println!("prod_1: {}", prod_1);

    //     let prod_2 = prod_0 * prod_1;
    //     println!("prod_2: {}", prod_2);

    //     let prod_3 = Fr::from(1);
    //     println!("prod_3: {}", prod_3);

    //     // [1, 2, 8] has coefficient of -1
    //     let neg_1 = -Fr::from(1);
    //     println!("neg_1: {}", neg_1);

    //     let p1_0 = frac_0;
    //     let p1_1 = frac_2;
    //     let p1_2 = prod_0;
    //     let p1_3 = prod_2;
    //     println!("p1_0: {}", p1_0);
    //     println!("p1_1: {}", p1_1);
    //     println!("p1_2: {}", p1_2);
    //     println!("p1_3: {}", p1_3);

    //     let p2_0 = frac_1;
    //     let p2_1 = frac_3;
    //     let p2_2 = prod_1;
    //     let p2_3 = prod_3;
    //     println!("p2_0: {}", p2_0);
    //     println!("p2_1: {}", p2_1);
    //     println!("p2_2: {}", p2_2);
    //     println!("p2_3: {}", p2_3);
    // }
}
