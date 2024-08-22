use crate::streams::iterator::BatchedIterator;
use crate::streams::MLE;
use crate::{piop::errors::PIOPError, streams::serialize::RawPrimeField};

use ark_std::{end_timer, start_timer};
use rayon::iter::{IntoParallelIterator, ParallelIterator};

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
pub(super) fn computer_nums_and_denoms<F: RawPrimeField>(
    beta: &F,
    gamma: &F,
    fxs: &[MLE<F>],
    gxs: &[MLE<F>],
    perms: &[MLE<F>],
) -> Result<(Vec<MLE<F>>, Vec<MLE<F>>), PIOPError> {
    let start = start_timer!(|| "compute numerators and denominators");

    let num_vars = fxs[0].num_vars();

    let s_ids = MLE::<F>::identity_permutation_mles(num_vars, fxs.len());

    let (numerators, denominators) = (fxs, gxs, &s_ids, perms)
        .into_par_iter()
        .map(|(fx, gx, s_id, perm)| {
            let (numerator, denominator) = fx
                .evals()
                .iter()
                .zip(gx.evals().iter())
                .zip(s_id.evals().iter())
                .zip(perm.evals().iter())
                .map(|(((f, g), s_id), perm)| {
                    let numerator = f + *beta * s_id + gamma;
                    let denominator = g + *beta * perm + gamma;
                    (numerator, denominator)
                })
                .unzip_faster();

            (
                MLE::from_evals(numerator, num_vars),
                MLE::from_evals(denominator, num_vars),
            )
        })
        .unzip();

    end_timer!(start);
    Ok((numerators, denominators))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::streams::iterator::zip_many;
    use ark_bls12_381::Fr;

    #[test]
    fn test_compute_nums_and_denoms() {
        let beta = Fr::from(2);
        let gamma = Fr::from(3);

        // Initialize fx, gx, s_id, perm with test values and alpha
        let fxs = vec![
            MLE::from_evals_vec(vec![Fr::from(1), Fr::from(2)], 1),
            MLE::from_evals_vec(vec![Fr::from(3), Fr::from(4)], 1),
        ];
        let gxs = vec![
            MLE::from_evals_vec(vec![Fr::from(5), Fr::from(6)], 1),
            MLE::from_evals_vec(vec![Fr::from(7), Fr::from(8)], 1),
        ];
        let perms = vec![
            MLE::from_evals_vec(vec![Fr::from(13), Fr::from(14)], 1),
            MLE::from_evals_vec(vec![Fr::from(15), Fr::from(16)], 1),
        ];

        // Compute the fractional polynomials
        let (numerators, denominators) =
            computer_nums_and_denoms(&beta, &gamma, &fxs, &gxs, &perms).unwrap();

        // Expected results based on manual calculations or desired outcomes
        let expected_numerators = vec![
            MLE::from_evals_vec(
                vec![
                    Fr::from(1) + Fr::from(0) * Fr::from(2) + Fr::from(3),
                    Fr::from(2) + Fr::from(1) * Fr::from(2) + Fr::from(3),
                ],
                1,
            ),
            MLE::from_evals_vec(
                vec![
                    Fr::from(3) + Fr::from(2) * Fr::from(2) + Fr::from(3),
                    Fr::from(4) + Fr::from(3) * Fr::from(2) + Fr::from(3),
                ],
                1,
            ),
        ];

        let expected_denominators = vec![
            MLE::from_evals_vec(
                vec![
                    Fr::from(5) + Fr::from(13) * Fr::from(2) + Fr::from(3),
                    Fr::from(6) + Fr::from(14) * Fr::from(2) + Fr::from(3),
                ],
                1,
            ),
            MLE::from_evals_vec(
                vec![
                    Fr::from(7) + Fr::from(15) * Fr::from(2) + Fr::from(3),
                    Fr::from(8) + Fr::from(16) * Fr::from(2) + Fr::from(3),
                ],
                1,
            ),
        ];

        // Convert output streams to vectors for easy comparison
        zip_many(
            numerators
                .iter()
                .chain(denominators.iter())
                .chain(expected_numerators.iter())
                .chain(expected_denominators.iter())
                .map(|mle| mle.evals().iter()),
        )
        .for_each(|vals| {
            assert_eq!(vals[0], vals[4]);
            assert_eq!(vals[1], vals[5]);
            assert_eq!(vals[2], vals[6]);
            assert_eq!(vals[3], vals[7]);
        });
    }
}
