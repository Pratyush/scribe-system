use ark_ff::PrimeField;
use ark_poly::DenseMultilinearExtension;
use ark_std::{end_timer, start_timer, vec::Vec};
use rayon::prelude::*;

/// Generate eq(t,x), a product of multilinear polynomials with fixed t.
/// eq(a,b) is takes extensions of a,b in {0,1}^num_vars such that if a and b in
/// {0,1}^num_vars are equal then this polynomial evaluates to 1.
pub(crate) fn eq_extension<F: PrimeField>(t: &[F]) -> Vec<DenseMultilinearExtension<F>> {
    let start = start_timer!(|| "eq extension");

    let dim = t.len();
    let mut result = Vec::new();
    for (i, &ti) in t.iter().enumerate().take(dim) {
        let poly = (0..(1 << dim))
            .into_par_iter()
            .map(|x| {
                let xi = if x >> i & 1 == 1 { F::one() } else { F::zero() };
                let ti_xi = ti * xi;
                ti_xi + ti_xi - xi - ti + F::one()
            })
            .collect();
        result.push(DenseMultilinearExtension::from_evaluations_vec(dim, poly));
    }

    end_timer!(start);
    result
}
