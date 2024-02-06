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
    read_write::{DenseMLPoly, DenseMLPolyStream, ReadWriteStream},
};
// use arithmetic::{VPAuxInfo, VirtualPolynomial};
use ark_ff::PrimeField;
// use ark_poly::DenseMultilinearExtension;
use ark_std::{end_timer, start_timer, Zero};
use std::{
    fmt::Debug,
    io::Seek,
    ops::Mul,
    sync::{Arc, Mutex},
};

use crate::hyperplonk::poly_iop::zero_check::ZeroCheck;
// use transcript::IOPTranscript;

pub fn compute_frac_poly<F: PrimeField>(
    p: Arc<Mutex<DenseMLPolyStream<F>>>,
    q: Arc<Mutex<DenseMLPolyStream<F>>>,
    pi: Arc<Mutex<DenseMLPolyStream<F>>>,
    alpha: F,
) -> Result<
    (
        Arc<Mutex<DenseMLPolyStream<F>>>,
        Arc<Mutex<DenseMLPolyStream<F>>>,
    ),
    PolyIOPErrors,
> {
    // Initialize output streams for 1/(p + alpha * pi) and 1/(q + alpha)
    let output_hp = Arc::new(Mutex::new(DenseMLPolyStream::<F>::new_from_tempfile(
        p.lock().unwrap().num_vars(),
    )));
    let output_hq = Arc::new(Mutex::new(DenseMLPolyStream::<F>::new_from_tempfile(
        q.lock().unwrap().num_vars(),
    )));

    // Lock the input streams to ensure exclusive access during computation
    let mut p = p.lock().unwrap();
    let mut q = q.lock().unwrap();
    let mut pi = pi.lock().unwrap();

    // Lock the output streams
    let mut hp = output_hp.lock().unwrap();
    let mut hq = output_hq.lock().unwrap();

    // Stream processing for p and pi
    while let (Some(p_val), Some(pi_val)) = (p.read_next(), pi.read_next()) {
        let result = (p_val + alpha * pi_val)
            .inverse()
            .expect("Failed to compute inverse");
        hp.write_next_unchecked(result)
            .expect("Failed to write to output stream for p and pi");
    }

    // Stream processing for q
    while let Some(q_val) = q.read_next() {
        let result = (q_val + alpha)
            .inverse()
            .expect("Failed to compute inverse");
        hq.write_next_unchecked(result)
            .expect("Failed to write to output stream for q");
    }

    hp.swap_read_write();
    hq.swap_read_write();

    drop(p);
    drop(q);
    drop(pi);

    drop(hp);
    drop(hq);

    // Return the output streams
    Ok((output_hp, output_hq))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::Field;
    use ark_test_curves::bls12_381::Fr;
    use std::sync::{Arc, Mutex};

    #[test]
    fn test_compute_frac_poly() {
        let alpha = Fr::from(2);

        // Initialize p, q, pi with test values and alpha
        let p = Arc::new(Mutex::new(DenseMLPolyStream::<Fr>::from_evaluations_vec(
            1,
            vec![Fr::from(1), Fr::from(2)],
            None,
            None,
        )));
        let q = Arc::new(Mutex::new(DenseMLPolyStream::<Fr>::from_evaluations_vec(
            1,
            vec![Fr::from(3), Fr::from(4)],
            None,
            None,
        )));
        let pi = Arc::new(Mutex::new(DenseMLPolyStream::<Fr>::from_evaluations_vec(
            1,
            vec![Fr::from(5), Fr::from(6)],
            None,
            None,
        )));

        // Compute the fractional polynomials
        let (output_hp, output_hq) = compute_frac_poly(p, q, pi, alpha).unwrap();

        // Expected results based on manual calculations or desired outcomes
        let expected_hp = vec![
            (Fr::from(1) + Fr::from(5) * Fr::from(2)).inverse().unwrap(),
            (Fr::from(2) + Fr::from(6) * Fr::from(2)).inverse().unwrap(),
        ];
        let expected_hq = vec![
            (Fr::from(3) + Fr::from(2)).inverse().unwrap(),
            (Fr::from(4) + Fr::from(2)).inverse().unwrap(),
        ];

        // Convert output streams to vectors for easy comparison
        let mut result_hp = Vec::new();
        let mut result_hq = Vec::new();
        while let Some(hp_elem) = output_hp.lock().unwrap().read_next() {
            result_hp.push(hp_elem);
        }
        while let Some(hq_elem) = output_hq.lock().unwrap().read_next() {
            result_hq.push(hq_elem);
        }

        // Assert that the computed values match the expected values
        assert_eq!(result_hp, expected_hp);
        assert_eq!(result_hq, expected_hq);
    }
}
