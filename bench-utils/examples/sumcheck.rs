use std::time::Instant;

use ark_bls12_381::Fr;
use ark_ff::UniformRand;

/// Depending on your project organization, adjust these import paths.
/// Here we assume that the library exposes:
///   - `SumCheck` (with methods `init_transcript`, `prove`, `verify`, and `extract_sum`)
///   - `VirtualPolynomial` (and its auxiliary types)
///   - `MLE` for generating random multilinear extensions.
use mle::{virtual_polynomial::VirtualPolynomial, MLE};
use scribe::piop::{errors::PIOPError, sum_check::SumCheck};

fn main() -> Result<(), PIOPError> {
    // Initialize randomness.
    let mut rng = ark_std::test_rng();

    // Pick a random number of variables in the range [15, 25].
    for num_vars in 15..=25 {
        // Generate two random multilinear extensions (MLEs) over Fr.
        // (Assuming MLE::rand(num_vars, rng) returns a random MLE with the given number of variables.)
        let mle1 = MLE::<Fr>::rand(num_vars, &mut rng);
        let mle2 = MLE::<Fr>::rand(num_vars, &mut rng);

        // Create a virtual polynomial over Fr with the chosen number of variables.
        // We will add a single product consisting of the two MLEs multiplied together.
        let mut poly = VirtualPolynomial::<Fr>::new(num_vars);
        let coefficient = Fr::rand(&mut rng);
        poly.add_virtual_mles(vec![mle1.into(), mle2.into()], coefficient)
            .expect("Failed to add virtual MLEs to the polynomial");

        // Compute the claimed sum over the Boolean hypercube.
        let claimed_sum = poly.sum_over_hypercube();

        // --- SUMCHECK PROTOCOL ---

        // 1. Proving: Create a transcript and generate a sumcheck proof.
        let mut transcript = SumCheck::<Fr>::init_transcript();
        let start = Instant::now();
        let proof = SumCheck::<Fr>::prove(&poly, &mut transcript)?;
        for _ in 0..4 {
            SumCheck::<Fr>::prove(&poly, &mut transcript)?;
        }
        let elapsed = start.elapsed();

        println!(
            "Sumcheck: Proving for {num_vars} variables took: {:?} us",
            elapsed.as_micros() / 5
        );

        // 2. Verifying: Prepare a fresh transcript and verify the proof.
        let poly_info = poly.aux_info.clone();
        let mut transcript2 = SumCheck::<Fr>::init_transcript();
        let subclaim = SumCheck::<Fr>::verify(claimed_sum, &proof, &poly_info, &mut transcript2)?;

        // 3. (Optional) Check that the virtual polynomial evaluates at the subclaim point as expected.
        let evaluation = poly.evaluate(&subclaim.point)?;
        assert_eq!(evaluation, subclaim.expected_evaluation);
    }

    Ok(())
}
