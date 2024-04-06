use crate::hyperplonk::poly_iop::errors::PolyIOPErrors;
use crate::read_write::{identity_permutation_mles, DenseMLPolyStream, ReadWriteStream};
use ark_ff::PrimeField;

use ark_std::{end_timer, start_timer};
use std::sync::{Arc, Mutex};

/// Returns the evaluations of two list of MLEs:
/// - numerators = (a1, ..., ak)
/// - denominators = (b1, ..., bk)
///
///  where
///  - beta and gamma are challenges
///  - (f1, ..., fk), (g1, ..., gk),
///  - (s_id1, ..., s_idk), (perm1, ..., permk) are mle-s
///
/// - ai(x) is the MLE for `fi(x) + \beta s_id_i(x) + \gamma`
/// - bi(x) is the MLE for `gi(x) + \beta perm_i(x) + \gamma`
///
/// The caller is responsible for sanity-check
#[allow(clippy::type_complexity)]
pub(super) fn computer_nums_and_denoms<F: PrimeField>(
    beta: &F,
    gamma: &F,
    fxs: Vec<Arc<Mutex<DenseMLPolyStream<F>>>>,
    gxs: Vec<Arc<Mutex<DenseMLPolyStream<F>>>>,
    perms: Vec<Arc<Mutex<DenseMLPolyStream<F>>>>,
) -> Result<
    (
        Vec<Arc<Mutex<DenseMLPolyStream<F>>>>,
        Vec<Arc<Mutex<DenseMLPolyStream<F>>>>,
    ),
    PolyIOPErrors,
> {
    let start = start_timer!(|| "compute numerators and denominators");

    let num_vars = fxs[0].lock().unwrap().num_vars;
    let s_ids = identity_permutation_mles::<F>(num_vars, fxs.len());

    let batch_size = 1 << 20; // Maximum number of elements to process in a batch

    let mut numerators = Vec::with_capacity(fxs.len());
    let mut denominators = Vec::with_capacity(gxs.len());

    for (((fx, gx), s_id), perm) in fxs.into_iter().zip(gxs).zip(s_ids).zip(perms) {
        let numerator = Arc::new(Mutex::new(DenseMLPolyStream::<F>::new_from_tempfile(
            num_vars,
        )));
        let denominator = Arc::new(Mutex::new(DenseMLPolyStream::<F>::new_from_tempfile(
            num_vars,
        )));

        // Prepare vectors for batch processing
        let mut numerator_vals = Vec::with_capacity(batch_size);
        let mut denominator_vals = Vec::with_capacity(batch_size);

        let mut fx = fx.lock().unwrap();
        let mut gx = gx.lock().unwrap();
        let mut s_id = s_id.lock().unwrap();
        let mut perm = perm.lock().unwrap();

        // Write results to output streams
        let mut numerator_stream = numerator.lock().unwrap();
        let mut denominator_stream = denominator.lock().unwrap();

        while let (Some(fx_val), Some(gx_val), Some(s_id_val), Some(perm_val)) = (
            fx.read_next(),
            gx.read_next(),
            s_id.read_next(),
            perm.read_next(),
        ) {
            numerator_vals.push(fx_val + *beta * s_id_val + gamma);
            denominator_vals.push(gx_val + *beta * perm_val + gamma);
            // Check if we've reached the batch size
            if numerator_vals.len() >= batch_size {
                for (numerator_val, denominator_val) in
                    numerator_vals.drain(..).zip(denominator_vals.drain(..))
                {
                    numerator_stream
                        .write_next_unchecked(numerator_val)
                        .expect("Failed to write to hp stream");
                    denominator_stream
                        .write_next_unchecked(denominator_val)
                        .expect("Failed to write to hq stream");
                }
            }
        }

        // Handle any remaining values that didn't fill the last batch
        if !numerator_vals.is_empty() {
            for (numerator_val, denominator_val) in
                numerator_vals.drain(..).zip(denominator_vals.drain(..))
            {
                numerator_stream
                    .write_next_unchecked(numerator_val)
                    .expect("Failed to write remaining hp values");
                denominator_stream
                    .write_next_unchecked(denominator_val)
                    .expect("Failed to write remaining hq values");
            }
        }

        fx.read_restart();
        gx.read_restart();
        s_id.read_restart();
        perm.read_restart();

        numerator_stream.swap_read_write();
        denominator_stream.swap_read_write();

        drop(numerator_stream);
        drop(denominator_stream);

        numerators.push(numerator);
        denominators.push(denominator);
    }

    end_timer!(start);

    // Return the output streams
    Ok((numerators, denominators))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Fr;

    use std::sync::{Arc, Mutex};

    #[test]
    fn test_compute_nums_and_denoms() {
        let beta = Fr::from(2);
        let gamma = Fr::from(3);

        // Initialize fx, gx, s_id, perm with test values and alpha
        let fxs = vec![
            Arc::new(Mutex::new(DenseMLPolyStream::<Fr>::from_evaluations_vec(
                1,
                vec![Fr::from(1), Fr::from(2)],
                None,
                None,
            ))),
            Arc::new(Mutex::new(DenseMLPolyStream::<Fr>::from_evaluations_vec(
                1,
                vec![Fr::from(3), Fr::from(4)],
                None,
                None,
            ))),
        ];
        let gxs = vec![
            Arc::new(Mutex::new(DenseMLPolyStream::<Fr>::from_evaluations_vec(
                1,
                vec![Fr::from(5), Fr::from(6)],
                None,
                None,
            ))),
            Arc::new(Mutex::new(DenseMLPolyStream::<Fr>::from_evaluations_vec(
                1,
                vec![Fr::from(7), Fr::from(8)],
                None,
                None,
            ))),
        ];
        let perms = vec![
            Arc::new(Mutex::new(DenseMLPolyStream::<Fr>::from_evaluations_vec(
                1,
                vec![Fr::from(13), Fr::from(14)],
                None,
                None,
            ))),
            Arc::new(Mutex::new(DenseMLPolyStream::<Fr>::from_evaluations_vec(
                1,
                vec![Fr::from(15), Fr::from(16)],
                None,
                None,
            ))),
        ];

        // Compute the fractional polynomials
        let (numerators, denominators) =
            computer_nums_and_denoms(&beta, &gamma, fxs, gxs, perms).unwrap();

        // Expected results based on manual calculations or desired outcomes
        let expected_numerators = vec![
            vec![
                Fr::from(1) + Fr::from(0) * Fr::from(2) + Fr::from(3),
                Fr::from(2) + Fr::from(1) * Fr::from(2) + Fr::from(3),
            ],
            vec![
                Fr::from(3) + Fr::from(2) * Fr::from(2) + Fr::from(3),
                Fr::from(4) + Fr::from(3) * Fr::from(2) + Fr::from(3),
            ],
        ];

        let expected_denominators = vec![
            vec![
                Fr::from(5) + Fr::from(13) * Fr::from(2) + Fr::from(3),
                Fr::from(6) + Fr::from(14) * Fr::from(2) + Fr::from(3),
            ],
            vec![
                Fr::from(7) + Fr::from(15) * Fr::from(2) + Fr::from(3),
                Fr::from(8) + Fr::from(16) * Fr::from(2) + Fr::from(3),
            ],
        ];

        // Convert output streams to vectors for easy comparison
        let mut result_numerators = Vec::new();
        let mut result_denominators = Vec::new();
        for numerator in numerators {
            let mut result_numerator = Vec::new();
            let mut numerator_stream = numerator.lock().unwrap();
            while let Some(numerator_elem) = numerator_stream.read_next() {
                result_numerator.push(numerator_elem);
            }
            result_numerators.push(result_numerator);
        }
        for denominator in denominators {
            let mut result_denominator = Vec::new();
            let mut denominator_stream = denominator.lock().unwrap();
            while let Some(denominator_elem) = denominator_stream.read_next() {
                result_denominator.push(denominator_elem);
            }
            result_denominators.push(result_denominator);
        }

        // Assert that the computed values match the expected values
        assert_eq!(result_numerators, expected_numerators);
        assert_eq!(result_denominators, expected_denominators);
    }
}
