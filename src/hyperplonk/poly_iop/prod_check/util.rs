use crate::hyperplonk::poly_iop::{errors::PolyIOPErrors, structs::IOPProof, zero_check::ZeroCheck, PolyIOP};
use crate::hyperplonk::arithmetic::util::get_index;
use crate::hyperplonk::arithmetic::virtual_polynomial::VirtualPolynomial;
use ark_ff::{batch_inversion, PrimeField};
use ark_serialize::Valid;
use crate::read_write::{DenseMLPoly, DenseMLPolyStream, ReadWriteStream};
use ark_std::{end_timer, start_timer};
use core::num;
use std::io::Seek;
use std::sync::{Arc, Mutex};
use crate::hyperplonk::transcript::IOPTranscript;
use ark_ff::Zero;

/// Compute multilinear fractional polynomial s.t. frac(x) = f1(x) * ... * fk(x)
/// / (g1(x) * ... * gk(x)) for all x \in {0,1}^n
///
/// The caller needs to sanity-check that the number of polynomials and
/// variables match in fxs and gxs; and gi(x) has no zero entries.
pub(super) fn compute_frac_poly<F: PrimeField>(
    fxs: Vec<Arc<Mutex<DenseMLPolyStream<F>>>>,
    gxs: Vec<Arc<Mutex<DenseMLPolyStream<F>>>>,
) -> Result<Arc<Mutex<DenseMLPolyStream<F>>>, PolyIOPErrors> {
    let start = start_timer!(|| "compute frac(x)");

    // TODO: might need to delete some of these to release disk space later
    let numerator = DenseMLPolyStream::prod_multi(fxs, None, None);
    let denominator = DenseMLPolyStream::prod_multi(gxs, None, None);
    let denominator_inverse = DenseMLPolyStream::batch_inversion_buffer(&denominator, 1 << 20, None, None);

    let result = DenseMLPolyStream::prod_multi(vec![numerator, denominator_inverse], None, None);

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
    frac_poly: &Arc<Mutex<DenseMLPolyStream<F>>>,
    buffer_size: usize,
) -> Result<Arc<Mutex<DenseMLPolyStream<F>>>, PolyIOPErrors> {
    let start = start_timer!(|| "compute evaluations of prod polynomial");
    let mut frac_poly_stream = frac_poly.lock().unwrap();
    frac_poly_stream.read_restart();
    let num_vars = frac_poly_stream.num_vars();
    #[cfg(debug_assertions)]
    {
        println!("frac_poly_stream read pointer: {}", frac_poly_stream.read_pointer.stream_position().unwrap());
        println!("frac_poly_stream write pointer: {}", frac_poly_stream.write_pointer.stream_position().unwrap());
    }

    // assert that num_vars is at least two
    assert!(num_vars >= 2);

    // single stream for read and write pointers
    let mut prod_stream = DenseMLPolyStream::new_single_stream(num_vars, None);

    let mut read_buffer = Vec::with_capacity(buffer_size);
    let mut write_buffer = Vec::with_capacity(buffer_size >> 1);

    // round 1
    // read frac_poly to read_buffer till it's full
    // note that this would fail if the frac_poly_stream has odd number of elements, but this shouldn't possibly happen
    while let Some(val) = frac_poly_stream.read_next_unchecked() {
        #[cfg(debug_assertions)]
        {
            println!("val: {}", val);
            println!("frac_poly_stream read pointer: {}", frac_poly_stream.read_pointer.stream_position().unwrap());
            println!("frac_poly_stream write pointer: {}", frac_poly_stream.write_pointer.stream_position().unwrap());
        }
        read_buffer.push(val);

        if read_buffer.len() >= buffer_size {
            (0..(buffer_size >> 1)).for_each(|i| write_buffer.push(read_buffer[2*i] * read_buffer[2*i+1]));

            for val in write_buffer.drain(..) {
                prod_stream
                    .write_next_unchecked(val)
                    .expect("Failed to write to prod stream");
            }
            
            read_buffer.clear();
        }
    }

    frac_poly_stream.read_restart();

    if !read_buffer.is_empty() {
        (0..(read_buffer.len() >> 1)).for_each(|i| write_buffer.push(read_buffer[2*i] * read_buffer[2*i+1]));

        for val in write_buffer.drain(..) {
            prod_stream
                .write_next_unchecked(val)
                .expect("Failed to write to prod stream");
        }

        read_buffer.clear();
    }

    for round in 2..=num_vars {
        for i in 0..(1 << (num_vars - round + 1)) {
            #[cfg(debug_assertions)]
            {
                println!("round: {}, i: {}", round, i);
                // print read pointer position
                println!("prod_stream read pointer: {}", prod_stream.read_pointer.stream_position().unwrap());
                // print write pointer position
                println!("prod_stream write pointer: {}", prod_stream.write_pointer.stream_position().unwrap());
            }
            // TODO:
            // the following line is required for the test to pass or it will error out "Failed to read from prod stream"
            // indeed bizarre as printing the write pointer position shouldn't affect whether read is successful
            prod_stream.write_pointer.stream_position().unwrap();
            if let Some(val) = prod_stream.read_next_unchecked() {
                read_buffer.push(val);
            } else {
                panic!("Failed to read from prod stream");
            }

            if read_buffer.len() >= buffer_size {
                (0..(buffer_size >> 1)).for_each(|i| write_buffer.push(read_buffer[2*i] * read_buffer[2*i+1]));

                for val in write_buffer.drain(..) {
                    prod_stream
                        .write_next_unchecked(val)
                        .expect("Failed to write to MLE stream");
                }
                
                read_buffer.clear();
            }
        }
    
        if !read_buffer.is_empty() {
            (0..(read_buffer.len() >> 1)).for_each(|i| write_buffer.push(read_buffer[2*i] * read_buffer[2*i+1]));
    
            for val in write_buffer.drain(..) {
                prod_stream
                    .write_next_unchecked(val)
                    .expect("Failed to write to MLE stream");
            }
    
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
) -> Result<(IOPProof<F>, VirtualPolynomial<F>), PolyIOPErrors> {
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
    let mut p1_stream = DenseMLPolyStream::new(num_vars, None, None);
    let mut p2_stream = DenseMLPolyStream::new(num_vars, None, None);
    
    let mut p1_vals = Vec::with_capacity(batch_size);
    let mut p2_vals = Vec::with_capacity(batch_size);
    
    while let (Some(p1_val), Some(p2_val)) = (frac_poly_stream.read_next(), frac_poly_stream.read_next()) {
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

    while let (Some(p1_val), Some(p2_val)) = (prod_x_stream.read_next(), prod_x_stream.read_next()) {
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
    q_x.add_mle_list([Arc::new(Mutex::new(p1_stream)), Arc::new(Mutex::new(p2_stream))], -F::one())?;

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
    use std::io::Seek;
    use std::sync::{Arc, Mutex};
    use crate::read_write::{DenseMLPolyStream, ReadWriteStream};
    use super::compute_product_poly;
    use super::*;
    use ark_bls12_381::Fr;
    use ark_serialize::Write;
    use ark_std::rand::distributions::{Distribution, Standard};
    use ark_std::rand::rngs::StdRng;
    use ark_std::rand::SeedableRng;
    use std::time::Instant;
    use std::vec::Vec;

    // in memory vector version of calculating the prod_poly from frac_poly
    fn compute_product_poly_in_memory<F: PrimeField>(
        frac_poly: Vec<F>,
        num_vars: usize,
    ) -> Vec<F> {
        assert!(frac_poly.len() == (1 << num_vars));
        
        let mut prod_poly = Vec::with_capacity(frac_poly.len());
        
        let mut offset = 0;

        for round in 1..=num_vars {
            if round == 1 {
                for i in 0..1 << (num_vars - round) {
                    prod_poly.push(frac_poly[2*i] * frac_poly[2*i+1]);
                }
            } else {
                for i in 0..1 << (num_vars - round) {
                    prod_poly.push(prod_poly[offset + 2*i] * prod_poly[offset + 2*i+1]);
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
        let frac_poly = vec![Fr::from(1u64), Fr::from(2u64), Fr::from(3u64), Fr::from(4u64)];
        let num_vars = 2;
        let prod_poly = compute_product_poly_in_memory(frac_poly, num_vars);
        assert_eq!(prod_poly, vec![Fr::from(2u64), Fr::from(12u64), Fr::from(24u64), Fr::from(1)]);
    }
    
    #[test]
    fn test_compute_product_poly() {
        let mut rng = StdRng::seed_from_u64(42); // Fixed seed for reproducibility

        // create vector to populate stream
        let num_vars = 10;
        let mut frac_poly_vec = Vec::with_capacity(1 << num_vars);
        for i in 0..(1 << num_vars) {
            frac_poly_vec.push(Standard.sample(&mut rng));
        }

        // Create a stream with 2^10 elements
        let mut frac_poly_stream: DenseMLPolyStream<Fr> = DenseMLPolyStream::new_single_stream(num_vars, None);
        for i in 0..(1 << num_vars) {
            frac_poly_stream
                .write_next_unchecked(frac_poly_vec[i])
                .expect("Failed to write to MLE stream");
        }
        // frac_poly_stream.write_pointer.flush().unwrap();
        frac_poly_stream.write_restart();

        let frac_poly = Arc::new(Mutex::new(frac_poly_stream));

        // Compute the product polynomial with buffer size 1 << 5
        let result = compute_product_poly(&frac_poly, 1<<5).unwrap();

        // Verify the result
        let mut result_stream = result.lock().unwrap();
        result_stream.read_restart();

        // Compute expected
        let expected = compute_product_poly_in_memory(
            frac_poly_vec,
            num_vars,
        );

        for i in 0..(1 << num_vars) {
            assert_eq!(
                result_stream.read_next().unwrap(),
                expected[i],
                "Product polynomial evaluation is incorrect"
            );
        }
    }
}
