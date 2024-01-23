use crate::error::{VerificationError, VerificationResult};
use crate::prover::Prover;
use crate::prover::RoundMsg;
use ark_ff::Field;
use ark_std::vec::Vec;

use merlin::Transcript;

#[derive(Debug, PartialEq, Eq)]
pub struct Sumcheck<F: Field> {
    /// The non-oracle messages sent througout the protocol.
    pub messages: Vec<RoundMsg<F>>,
    /// The challenges sent thropughout the protocol.
    pub challenges: Vec<F>,
    /// The number of rounds in the protocol.
    rounds: usize,
}

impl<F: Field> Sumcheck<F> {
    pub fn prove<P: Prover<F>>(transcript: &mut Transcript, mut prover: P) -> Self {
        let rounds = prover.rounds();
        let mut messages = Vec::with_capacity(rounds);
        let mut challenges = Vec::with_capacity(rounds);

        while let Some((message, challenge)) = prover.next_message(transcript) {
            // add the message and challenge to the final proof
            messages.push(message);
            challenges.push(challenge);
        }

        let rounds = prover.rounds();

        Sumcheck {
            messages,
            challenges,
            rounds,
        }
    }

    pub fn verify(&self, asserted_sum: F) -> VerificationResult {
        // Check if there are no messages or challenges
        if self.messages.is_empty() || self.challenges.is_empty() {
            eprint!("No messages or challenges to verify");
            return Err(VerificationError);
        }

        // Check the first round
        let first_msg = &self.messages[0];
        if first_msg.0 + first_msg.1 != asserted_sum {
            eprint!("Verification failed in the first round");
            return Err(VerificationError);
        }

        let one = F::one();

        // Check subsequent rounds
        for round in 1..self.rounds {
            let current_msg = &self.messages[round];
            let previous_msg = &self.messages[round - 1];
            let challenge = self.challenges[round - 1];

            let expected_sum = (one - challenge) * previous_msg.0 + challenge * previous_msg.1;
            if current_msg.0 + current_msg.1 != expected_sum {
                // println!("Expected sum: {}", expected_sum);
                // println!("Current sum: {}", current_msg.0 + current_msg.1);
                // println!("    Current message 0: {:?}", current_msg.0);
                // println!("    Current message 1: {:?}", current_msg.1);
                // eprintln!("Verification failed in round {}", round);
                return Err(VerificationError);
            }
        }

        // If all checks pass
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::read_write::{DenseMLPolyStream, ReadWriteStream};
    use crate::space_prover::SpaceProver;
    use ark_std::rand::distributions::{Distribution, Standard};
    use ark_std::rand::rngs::StdRng; // Using StdRng for reproducibility
    use ark_std::rand::SeedableRng;
    use ark_test_curves::bls12_381::Fr;
    use std::time::Instant;
    use tempfile::tempfile;

    #[test]
    fn benchmark_proof_creation() {
        let mut log_proof_times = Vec::new();
        let mut log_verification_times = Vec::new();

        for n in 1..=24 {
            let num_vars = n;
            let num_evals = 2usize.pow(n as u32);
            let mut rng = StdRng::seed_from_u64(42); // Seed for reproducibility

            // Generate random field elements
            let field_elements: Vec<Fr> =
                (0..num_evals).map(|_| Standard.sample(&mut rng)).collect();

            // Initialize asserted sum to zero
            let mut asserted_sum = Fr::from(0);

            // Initialize DenseMLPolyStream
            let mut stream = DenseMLPolyStream::new_from_tempfile(num_vars, num_evals);

            // Write the random field elements to the stream and update asserted_sum
            for elem in &field_elements {
                stream
                    .write_next_unchecked(*elem)
                    .expect("Failed to write to stream");
                asserted_sum += *elem; // Update the asserted_sum
            }

            stream.swap_read_write();

            // Create SpaceProver
            let prover = SpaceProver::new(stream);

            // Initialize a Transcript
            let label = b"benchmark";
            let mut transcript = Transcript::new(label);

            // Measure proof creation time
            let start = Instant::now();
            let proof = Sumcheck::prove(&mut transcript, prover);
            let duration = start.elapsed().as_secs_f64();
            log_proof_times.push(duration.ln());

            // println!("message: {:?}", proof.messages);
            // println!("challenge: {:?}", proof.challenges);

            // Measure verification time
            let start = Instant::now();
            let verification_result = proof.verify(asserted_sum);
            let verification_duration = start.elapsed().as_secs_f64();
            log_verification_times.push(verification_duration.ln());

            println!(
                "n = {}: Proof Creation Time: {:?}, Verification Time: {:?}",
                n, duration, verification_duration
            );

            // Assert that the verification was successful
            assert!(verification_result.is_ok(), "Verification failed");
        }

        // Further analysis of log_proof_times and log_verification_times can be done here if needed
    }
}
