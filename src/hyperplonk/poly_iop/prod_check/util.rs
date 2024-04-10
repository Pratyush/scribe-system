use crate::hyperplonk::arithmetic::virtual_polynomial::VirtualPolynomial;
use crate::hyperplonk::poly_iop::{
    errors::PIOPError, structs::IOPProof, zero_check::ZeroCheck, PolyIOP,
};
use crate::hyperplonk::transcript::IOPTranscript;
use crate::streams::{DenseMLPolyStream, ReadWriteStream};
use ark_poly::DenseMultilinearExtension as DenseMLPoly;

use ark_ff::PrimeField;
use ark_serialize::Write;
use ark_std::{end_timer, start_timer};

use std::io::Seek;
use std::sync::{Arc, Mutex};

/// Compute multilinear fractional polynomial s.t. frac(x) = f1(x) * ... * fk(x)
/// / (g1(x) * ... * gk(x)) for all x \in {0,1}^n
///
/// The caller needs to sanity-check that the number of polynomials and
/// variables match in fxs and gxs; and gi(x) has no zero entries.
pub(super) fn compute_frac_poly<F: PrimeField>(
    fxs: &mut [DenseMLPolyStream<F>],
    gxs: &mut [DenseMLPolyStream<F>],
) -> Result<DenseMLPolyStream<F>, PIOPError> {
    let start = start_timer!(|| "compute frac(x)");

    // TODO: might need to delete some of these to release disk space later
    let numerator = DenseMLPolyStream::prod_multi(fxs).unwrap();
    let mut denominator = DenseMLPolyStream::prod_multi(gxs).unwrap();
    let denominator_inverse = denominator.batch_inversion().unwrap();
    let result = DenseMLPolyStream::prod_multi(&mut [numerator, denominator_inverse]).unwrap();

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
pub(super) fn compute_product_poly<F: PrimeField>(
    frac_poly: &DenseMLPolyStream<F>,
) -> Result<Arc<Mutex<DenseMLPolyStream<F>>>, PIOPError> {
    let start = start_timer!(|| "compute evaluations of prod polynomial");
    frac_poly.read_restart();
    /* let num_vars = frac_poly_stream.num_vars();
    #[cfg(debug_assertions)]
    {
        println!(
            "frac_poly_stream read pointer: {}",
            frac_poly_stream.read_pointer.stream_position().unwrap()
        );
        println!(
            "frac_poly_stream write pointer: {}",
            frac_poly_stream.write_pointer.stream_position().unwrap()
        );
    } */

    // assert that num_vars is at least two
    assert!(num_vars >= 2);

    // single stream for read and write pointers
    let mut prod_stream = DenseMLPolyStream::new_single_stream(num_vars, None);

    let mut read_buffer = Vec::with_capacity(buffer_size);
    let mut write_buffer = Vec::with_capacity(buffer_size >> 1);
    
    let mut prod_stream = frac_poly.fold_odd_even(f);


    // let 
    // round 1
    // read frac_poly to read_buffer till it's full
    // note that this would fail if the frac_poly_stream has odd number of elements, but this shouldn't possibly happen
    while let Some(val) = frac_poly_stream.read_next_unchecked() {
        #[cfg(debug_assertions)]
        {
            println!("val: {}", val);
            println!(
                "frac_poly_stream read pointer: {}",
                frac_poly_stream.read_pointer.stream_position().unwrap()
            );
            println!(
                "frac_poly_stream write pointer: {}",
                frac_poly_stream.write_pointer.stream_position().unwrap()
            );
        }
        read_buffer.push(val);

        if read_buffer.len() >= buffer_size {
            (0..(buffer_size >> 1))
                .for_each(|i| write_buffer.push(read_buffer[2 * i] * read_buffer[2 * i + 1]));

            for val in write_buffer.drain(..) {
                prod_stream
                    .write_next_unchecked(val)
                    .expect("Failed to write to prod stream");
            }
            // after draining our in-memory write buffer, still need to flush the BufWriter buffer,
            // because they are two different buffers. Otherwise we can't read from the stream.
            prod_stream.write_pointer.flush().unwrap();
            read_buffer.clear();
        }
    }

    frac_poly_stream.read_restart();

    if !read_buffer.is_empty() {
        (0..(read_buffer.len() >> 1))
            .for_each(|i| write_buffer.push(read_buffer[2 * i] * read_buffer[2 * i + 1]));

        for val in write_buffer.drain(..) {
            prod_stream
                .write_next_unchecked(val)
                .expect("Failed to write to prod stream");
        }
        prod_stream.write_pointer.flush().unwrap();
        read_buffer.clear();
    }

    // prod_stream.write_pointer.flush().unwrap();

    for round in 2..=num_vars {
        for i in 0..(1 << (num_vars - round + 1)) {
            #[cfg(debug_assertions)]
            {
                println!("round: {}, i: {}", round, i);
                // print read pointer position
                println!(
                    "prod_stream read pointer: {}",
                    prod_stream.read_pointer.stream_position().unwrap()
                );
                // print write pointer position
                println!(
                    "prod_stream write pointer: {}",
                    prod_stream.write_pointer.stream_position().unwrap()
                );
            }

            read_buffer.push(prod_stream.read_next_unchecked().expect("Failed to read from prod stream"));

            if read_buffer.len() >= buffer_size {
                (0..(buffer_size >> 1))
                    .for_each(|i| write_buffer.push(read_buffer[2 * i] * read_buffer[2 * i + 1]));

                for val in write_buffer.drain(..) {
                    prod_stream
                        .write_next_unchecked(val)
                        .expect("Failed to write to MLE stream");
                }
                prod_stream.write_pointer.flush().unwrap();
                read_buffer.clear();
            }
        }

        if !read_buffer.is_empty() {
            (0..(read_buffer.len() >> 1))
                .for_each(|i| write_buffer.push(read_buffer[2 * i] * read_buffer[2 * i + 1]));

            for val in write_buffer.drain(..) {
                prod_stream
                    .write_next_unchecked(val)
                    .expect("Failed to write to MLE stream");
            }
            prod_stream.write_pointer.flush().unwrap();
            read_buffer.clear();
        }
    }

    prod_stream.write_next_unchecked(F::one());

    prod_stream.read_restart();
    prod_stream.write_restart();

    end_timer!(start);

    Ok(Arc::new(Mutex::new(prod_stream)))
}

/// generate the zerocheck proof for the virtual polynomial
///    prod(x) - p1(x) * p2(x) + alpha * [frac(x) * g1(x) * ... * gk(x) - f1(x)
/// * ... * fk(x)] where p1(x) = (1-x1) * frac(x2, ..., xn, 0) + x1 * prod(x2,
///   ..., xn, 0), p2(x) = (1-x1) * frac(x2, ..., xn, 1) + x1 * prod(x2, ...,
///   xn, 1)
/// Returns proof.
///
/// Cost: O(N)
pub(super) fn prove_zero_check<F: PrimeField>(
    fxs: Vec<Arc<Mutex<DenseMLPolyStream<F>>>>,
    gxs: Vec<Arc<Mutex<DenseMLPolyStream<F>>>>,
    frac_poly: &Arc<Mutex<DenseMLPolyStream<F>>>,
    prod_x: &Arc<Mutex<DenseMLPolyStream<F>>>,
    alpha: &F,
    transcript: &mut IOPTranscript<F>,
    batch_size: usize,
) -> Result<(IOPProof<F>, VirtualPolynomial<F>), PIOPError> {
    // this is basically a batch zero check with alpha as the batch factor
    // the first zero check is prod(x) - p1(x) * p2(x),
    // which is checking that prod is computed correctly from frac_poly in the first half
    // and computed correctly from prod itself in the second half
    // the second zero check is frac * g1 * ... * gk - f1 * ... * fk
    // which is checking that frac is computed correctly from fxs and gxs
    let start = start_timer!(|| "zerocheck in product check");
    let num_vars = frac_poly.lock().unwrap().num_vars();

    let mut frac_poly_stream = frac_poly.lock().unwrap();
    let mut prod_x_stream = prod_x.lock().unwrap();

    // compute p1(x) = (1-x1) * frac(x2, ..., xn, 0) + x1 * prod(x2, ..., xn, 0)
    // compute p2(x) = (1-x1) * frac(x2, ..., xn, 1) + x1 * prod(x2, ..., xn, 1)
    let mut p1_stream = DenseMLPolyStream::new_from_tempfile(num_vars);
    let mut p2_stream = DenseMLPolyStream::new_from_tempfile(num_vars);

    let mut p1_vals = Vec::with_capacity(batch_size);
    let mut p2_vals = Vec::with_capacity(batch_size);

    while let (Some(p1_val), Some(p2_val)) =
        (frac_poly_stream.read_next(), frac_poly_stream.read_next())
    {
        p1_vals.push(p1_val);
        p2_vals.push(p2_val);

        if p1_vals.len() >= batch_size {
            for p1_val in p1_vals.drain(..) {
                p1_stream
                    .write_next_unchecked(p1_val)
                    .expect("Failed to write to p1 stream");
            }
            for p2_val in p2_vals.drain(..) {
                p2_stream
                    .write_next_unchecked(p2_val)
                    .expect("Failed to write to p2 stream");
            }
        }
    }

    while let (Some(p1_val), Some(p2_val)) = (prod_x_stream.read_next(), prod_x_stream.read_next())
    {
        p1_vals.push(p1_val);
        p2_vals.push(p2_val);

        if p1_vals.len() >= batch_size {
            for p1_val in p1_vals.drain(..) {
                p1_stream
                    .write_next_unchecked(p1_val)
                    .expect("Failed to write to p1 stream");
            }
            for p2_val in p2_vals.drain(..) {
                p2_stream
                    .write_next_unchecked(p2_val)
                    .expect("Failed to write to p2 stream");
            }
        }
    }

    // write the last batch
    for p1_val in p1_vals.drain(..) {
        p1_stream
            .write_next_unchecked(p1_val)
            .expect("Failed to write to p1 stream");
    }
    for p2_val in p2_vals.drain(..) {
        p2_stream
            .write_next_unchecked(p2_val)
            .expect("Failed to write to p2 stream");
    }

    p1_stream.swap_read_write();
    p2_stream.swap_read_write();
    frac_poly_stream.read_restart();
    prod_x_stream.read_restart();
    drop(frac_poly_stream);
    drop(prod_x_stream);

    // compute Q(x)
    // prod(x)
    let mut q_x = VirtualPolynomial::new_from_mle(prod_x, F::one());

    //   prod(x)
    // - p1(x) * p2(x)
    q_x.add_mle_list(
        [
            Arc::new(Mutex::new(p1_stream)),
            Arc::new(Mutex::new(p2_stream)),
        ],
        -F::one(),
    )?;

    //   prod(x)
    // - p1(x) * p2(x)
    // + alpha * frac(x) * g1(x) * ... * gk(x)
    let mut mle_list = gxs;
    mle_list.push(frac_poly.clone());
    q_x.add_mle_list(mle_list, *alpha)?;

    //   prod(x)
    // - p1(x) * p2(x)
    // + alpha * frac(x) * g1(x) * ... * gk(x)
    // - alpha * f1(x) * ... * fk(x)]
    q_x.add_mle_list(fxs, -*alpha)?;

    let iop_proof = <PolyIOP<F> as ZeroCheck<F>>::prove(&q_x, transcript)?;

    end_timer!(start);
    Ok((iop_proof, q_x))
}

#[cfg(test)]
mod test {
    use super::compute_product_poly;
    use super::*;

    use crate::streams::{DenseMLPolyStream, ReadWriteStream};
    use ark_bls12_381::Fr;

    use ark_std::rand::distributions::{Distribution, Standard};
    use ark_std::rand::rngs::StdRng;
    use ark_std::rand::SeedableRng;

    use std::sync::{Arc, Mutex};

    use std::vec::Vec;

    // in memory vector version of calculating the prod_poly from frac_poly
    fn compute_product_poly_in_memory<F: PrimeField>(frac_poly: Vec<F>, num_vars: usize) -> Vec<F> {
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
        let num_vars = 10;
        let mut frac_poly_vec = Vec::with_capacity(1 << num_vars);
        for _i in 0..(1 << num_vars) {
            frac_poly_vec.push(Standard.sample(&mut rng));
        }

        // Create a stream with 2^10 elements
        let mut frac_poly_stream: DenseMLPolyStream<Fr> =
            DenseMLPolyStream::new_single_stream(num_vars, None);
        for i in 0..(1 << num_vars) {
            frac_poly_stream
                .write_next_unchecked(frac_poly_vec[i])
                .expect("Failed to write to MLE stream");
        }
        // frac_poly_stream.write_pointer.flush().unwrap();
        frac_poly_stream.write_restart();

        let frac_poly = Arc::new(Mutex::new(frac_poly_stream));

        // Compute the product polynomial with buffer size 1 << 5
        let result = compute_product_poly(&frac_poly, 1 << 5).unwrap();

        // Verify the result
        let mut result_stream = result.lock().unwrap();
        result_stream.read_restart();

        // Compute expected
        let expected = compute_product_poly_in_memory(frac_poly_vec, num_vars);

        for i in 0..(1 << num_vars) {
            assert_eq!(
                result_stream.read_next().unwrap(),
                expected[i],
                "Product polynomial evaluation is incorrect"
            );
        }
    }

    // #[test]
    // fn test_prove_zero_check() {
    //     let nv = 2;
    //     let mut rng = StdRng::seed_from_u64(42); // Fixed seed for reproducibility
    //     let mut transcript = <PolyIOP<E::ScalarField> as ProductCheck<E, PCS>>::init_transcript();

    //     let srs = MultilinearKzgPCS::<Bls12_381>::gen_srs_for_testing(&mut rng, nv).unwrap();
    //     let (pcs_param, _) = MultilinearKzgPCS::<Bls12_381>::trim(&srs, None, Some(nv)).unwrap();

    //     // create fxs
    //     let f1 = vec![Fr::from(1u64), Fr::from(2u64), Fr::from(3u64), Fr::from(4u64)];
    //     let f2 = vec![Fr::from(5u64), Fr::from(6u64), Fr::from(7u64), Fr::from(8u64)];
    //     let fxs = vec![Arc::new(Mutex::new(DenseMLPolyStream::from_evaluations_vec(nv, f1, None, None))),
    //                       Arc::new(Mutex::new(DenseMLPolyStream::from_evaluations_vec(nv, f2, None, None)))];

    //     // create gxs
    //     let g1 = vec![Fr::from(1u64), Fr::from(3u64), Fr::from(5u64), Fr::from(7u64)];
    //     let g2 = vec![Fr::from(2u64), Fr::from(4u64), Fr::from(6u64), Fr::from(8u64)];
    //     let gxs = vec![Arc::new(Mutex::new(DenseMLPolyStream::from_evaluations_vec(nv, g1, None, None))),
    //                       Arc::new(Mutex::new(DenseMLPolyStream::from_evaluations_vec(nv, g2, None, None)))];

    //     // compute the fractional polynomial frac_p s.t.
    //     // frac_p(x) = f1(x) * ... * fk(x) / (g1(x) * ... * gk(x))
    //     let frac_poly = compute_frac_poly(fxs.clone(), gxs.clone()).unwrap();
    //     // compute the product polynomial
    //     let prod_x = compute_product_poly(&frac_poly, 1 << 20).unwrap();

    //     // generate challenge
    //     let frac_comm = PCS::commit(pcs_param, &frac_poly)?;
    //     let prod_x_comm = PCS::commit(pcs_param, &prod_x)?;
    //     let alpha = transcript.get_and_append_challenge(b"alpha")?;
    //     // build the zero-check proof
    //     let (zero_check_proof, _) =
    //         prove_zero_check(fxs, gxs, &frac_poly, &prod_x, &alpha, transcript, 1 << 20)?;

    // }

    #[test]
    fn test_prover_zero_check() {
        use ark_ff::Field;

        // frac_0: 44242769679012723217034031053781908675551403672320194412821837028073177874433
        // frac_1: 7490839310732312925635391501169423691098650357218233974657665528562654454931
        // frac_2: 13108968793781547619861935127046491459422638125131909455650914674984645296130
        // frac_3: 10487175035025238095889548101637193167538110500105527564520731739987716236909
        // prod_0: 2809064741524617347113271812938533884161993883956837740496624573210995420599
        // prod_1: 31461525105075714287668644304911579502614331500316582693562195219963148710719
        // prod_2: 1
        // prod_3: 1
        // neg_1: 52435875175126190479447740508185965837690552500527637822603658699938581184512
        // p1_0: 44242769679012723217034031053781908675551403672320194412821837028073177874433
        // p1_1: 13108968793781547619861935127046491459422638125131909455650914674984645296130
        // p1_2: 2809064741524617347113271812938533884161993883956837740496624573210995420599
        // p1_3: 1
        // p2_0: 7490839310732312925635391501169423691098650357218233974657665528562654454931
        // p2_1: 10487175035025238095889548101637193167538110500105527564520731739987716236909
        // p2_2: 31461525105075714287668644304911579502614331500316582693562195219963148710719
        // p2_3: 1

        let frac_0 = Fr::from(1)
            * Fr::from(5)
            * Fr::from(4).inverse().unwrap()
            * Fr::from(8).inverse().unwrap();
        println!("frac_0: {}", frac_0);

        let frac_1 = Fr::from(2)
            * Fr::from(6)
            * Fr::from(3).inverse().unwrap()
            * Fr::from(7).inverse().unwrap();
        println!("frac_1: {}", frac_1);

        let frac_2 = Fr::from(3)
            * Fr::from(7)
            * Fr::from(2).inverse().unwrap()
            * Fr::from(6).inverse().unwrap();
        println!("frac_2: {}", frac_2);

        let frac_3 = Fr::from(4)
            * Fr::from(8)
            * Fr::from(1).inverse().unwrap()
            * Fr::from(5).inverse().unwrap();
        println!("frac_3: {}", frac_3);

        let prod_0 = frac_0 * frac_1;
        println!("prod_0: {}", prod_0);

        let prod_1 = frac_2 * frac_3;
        println!("prod_1: {}", prod_1);

        let prod_2 = prod_0 * prod_1;
        println!("prod_2: {}", prod_2);

        let prod_3 = Fr::from(1);
        println!("prod_3: {}", prod_3);

        // [1, 2, 8] has coefficient of -1
        let neg_1 = -Fr::from(1);
        println!("neg_1: {}", neg_1);

        let p1_0 = frac_0;
        let p1_1 = frac_2;
        let p1_2 = prod_0;
        let p1_3 = prod_2;
        println!("p1_0: {}", p1_0);
        println!("p1_1: {}", p1_1);
        println!("p1_2: {}", p1_2);
        println!("p1_3: {}", p1_3);

        let p2_0 = frac_1;
        let p2_1 = frac_3;
        let p2_2 = prod_1;
        let p2_3 = prod_3;
        println!("p2_0: {}", p2_0);
        println!("p2_1: {}", p2_1);
        println!("p2_2: {}", p2_2);
        println!("p2_3: {}", p2_3);
    }
}
