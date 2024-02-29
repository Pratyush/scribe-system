use crate::{
    hyperplonk::poly_iop::errors::PolyIOPErrors,
    read_write::{DenseMLPolyStream, ReadWriteStream},
};
use ark_ff::fields::batch_inversion;
use ark_ff::PrimeField;
use ark_std::{end_timer, start_timer};
use std::sync::{Arc, Mutex};

pub fn compute_frac_poly<F: PrimeField>(
    p: &Arc<Mutex<DenseMLPolyStream<F>>>,
    q: &Arc<Mutex<DenseMLPolyStream<F>>>,
    pi: &Arc<Mutex<DenseMLPolyStream<F>>>,
    index: &Arc<Mutex<DenseMLPolyStream<F>>>,
    alpha: F,
    gamma: F,
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
    let mut index = index.lock().unwrap();

    // Lock the output streams
    let mut hp = output_hp.lock().unwrap();
    let mut hq = output_hq.lock().unwrap();

    // Stream processing for p and pi
    while let (Some(p_val), Some(pi_val)) = (p.read_next(), pi.read_next()) {
        let result = (p_val + alpha * pi_val + gamma)
            .inverse()
            .expect("Failed to compute inverse");
        hp.write_next_unchecked(result)
            .expect("Failed to write to output stream for p and pi");
    }

    // Stream processing for q
    while let (Some(q_val), Some(index_val)) = (q.read_next(), index.read_next()) {
        let result = (q_val + alpha * index_val + gamma)
            .inverse()
            .expect("Failed to compute inverse");
        hq.write_next_unchecked(result)
            .expect("Failed to write to output stream for q");
    }

    p.read_restart();
    q.read_restart();
    pi.read_restart();

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

pub fn compute_frac_poly_plonk<F: PrimeField>(
    ps: Vec<Arc<Mutex<DenseMLPolyStream<F>>>>,
    pis: Vec<Arc<Mutex<DenseMLPolyStream<F>>>>,
    indices: Vec<Arc<Mutex<DenseMLPolyStream<F>>>>,
    alpha: F,
    gamma: F,
) -> Result<
    (
        Vec<Arc<Mutex<DenseMLPolyStream<F>>>>, // h_p's
        Vec<Arc<Mutex<DenseMLPolyStream<F>>>>, // h_q's
    ),
    PolyIOPErrors,
> {
    #[cfg(debug_assertions)]
    {
        // print the first element of each vector of polynomials
        let mut p_lock = ps[0].lock().unwrap();
        let mut pi_lock = pis[0].lock().unwrap();
        let mut index_lock = indices[0].lock().unwrap();

        while let (Some(p_val), Some(pi_val), Some(idx_val)) = (
            p_lock.read_next(),
            pi_lock.read_next(),
            index_lock.read_next(),
        ) {
            println!("p_val: {}", p_val);
            println!("alpha: {}", alpha);
            println!("pi_val: {}", pi_val);
            println!("idx_val: {}", idx_val);
        }

        p_lock.read_restart();
        pi_lock.read_restart();
        index_lock.read_restart();

        drop(p_lock);
        drop(pi_lock);
        drop(index_lock);
    }

    let start = start_timer!(|| "compute h_p h_q ");

    let batch_size = 1 << 20; // Maximum number of elements to process in a batch

    let mut outputs_hp = Vec::with_capacity(ps.len());
    let mut outputs_hq = Vec::with_capacity(ps.len());
    let num_vars = ps[0].lock().unwrap().num_vars();

    for ((p, pi), index) in ps.into_iter().zip(pis).zip(indices) {
        let output_hp = Arc::new(Mutex::new(DenseMLPolyStream::<F>::new_from_tempfile(
            num_vars,
        )));
        let output_hq = Arc::new(Mutex::new(DenseMLPolyStream::<F>::new_from_tempfile(
            num_vars,
        )));

        // Prepare vectors for batch processing
        let mut hp_vals = Vec::with_capacity(batch_size);
        let mut hq_vals = Vec::with_capacity(batch_size);

        let mut p = p.lock().unwrap();
        let mut pi = pi.lock().unwrap();
        let mut index = index.lock().unwrap();

        // Write results to output streams
        let mut hp = output_hp.lock().unwrap();
        let mut hq = output_hq.lock().unwrap();

        while let (Some(p_val), Some(pi_val), Some(idx_val)) =
            (p.read_next(), pi.read_next(), index.read_next())
        {
            hp_vals.push(p_val + alpha * pi_val + gamma);
            hq_vals.push(p_val + alpha * idx_val + gamma);
            // Check if we've reached the batch size
            if hp_vals.len() >= batch_size {
                // Perform batch inversion
                batch_inversion(&mut hp_vals);
                batch_inversion(&mut hq_vals);

                for (hp_val, hq_val) in hp_vals.drain(..).zip(hq_vals.drain(..)) {
                    hp.write_next_unchecked(hp_val)
                        .expect("Failed to write to hp stream");
                    hq.write_next_unchecked(hq_val)
                        .expect("Failed to write to hq stream");
                }
            }
        }

        // Handle any remaining values that didn't fill the last batch
        if !hp_vals.is_empty() {
            batch_inversion(&mut hp_vals);
            batch_inversion(&mut hq_vals);

            for (hp_val, hq_val) in hp_vals.iter().zip(hq_vals.iter()) {
                hp.write_next_unchecked(*hp_val)
                    .expect("Failed to write remaining hp values");
                hq.write_next_unchecked(*hq_val)
                    .expect("Failed to write remaining hq values");
            }
        }

        p.read_restart();
        pi.read_restart();
        index.read_restart();

        hp.swap_read_write();
        hq.swap_read_write();

        drop(hp);
        drop(hq);

        outputs_hp.push(output_hp);
        outputs_hq.push(output_hq);
    }

    end_timer!(start);

    // Return the output streams
    Ok((outputs_hp, outputs_hq))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Fr;
    use ark_ff::Field;
    use std::sync::{Arc, Mutex};

    #[test]
    fn test_compute_frac_poly() {
        let alpha = Fr::from(2);
        let gamma = Fr::from(3);

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
        let index = Arc::new(Mutex::new(DenseMLPolyStream::<Fr>::from_evaluations_vec(
            1,
            vec![Fr::from(7), Fr::from(8)],
            None,
            None,
        )));

        // Compute the fractional polynomials
        let (output_hp, output_hq) = compute_frac_poly(&p, &q, &pi, &index, alpha, gamma).unwrap();

        // Expected results based on manual calculations or desired outcomes
        let expected_hp = vec![
            (Fr::from(1) + Fr::from(5) * Fr::from(2) + Fr::from(3))
                .inverse()
                .unwrap(),
            (Fr::from(2) + Fr::from(6) * Fr::from(2) + Fr::from(3))
                .inverse()
                .unwrap(),
        ];
        let expected_hq = vec![
            (Fr::from(3) + Fr::from(7) * Fr::from(2) + Fr::from(3))
                .inverse()
                .unwrap(),
            (Fr::from(4) + Fr::from(8) * Fr::from(2) + Fr::from(3))
                .inverse()
                .unwrap(),
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
