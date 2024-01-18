use crate::prover::Prover;
use crate::prover::RoundMsg;
use crate::transcript::GeminiTranscript;
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

        let mut verifier_message = None;
        while let Some(message) = prover.next_message(verifier_message) {
            // add the message sent to the transcript
            transcript.append_serializable(b"evaluations", &message);
            // compute the challenge for the next round
            let challenge = transcript.get_challenge(b"challenge");
            verifier_message = Some(challenge);

            // add the message to the final proof
            messages.push(message);
            challenges.push(challenge);

            // update the stream
            prover.update_stream(challenge);
        }

        let rounds = prover.rounds();

        Sumcheck {
            messages,
            challenges,
            rounds,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::rand::distributions::{Distribution, Standard};
    use ark_std::rand::rngs::StdRng; // Using StdRng for reproducibility
    use ark_std::rand::SeedableRng;
    use ark_test_curves::bls12_381::Fr;
    use std::time::Instant;
    use tempfile::tempfile;
    use crate::read_write::{DenseMLPolyStream, ReadStream, WriteStream};
    use crate::space_prover::SpaceProver;

    #[test]
    fn benchmark_proof_creation() {
        let mut log_proof_times = Vec::new();

        for n in 1..=20 {
            let num_vars = n;
            let num_evals = 2usize.pow(n as u32);
            let mut rng = StdRng::seed_from_u64(42); // Seed for reproducibility

            // Generate random field elements
            let field_elements: Vec<Fr> = 
                (0..num_evals).map(|_| Standard.sample(&mut rng)).collect();

            // Initialize DenseMLPolyStream
            let mut stream = DenseMLPolyStream::new_from_tempfile(num_vars, num_evals);

            // Write the random field elements to the stream
            for elem in &field_elements {
                stream.write_next(*elem).expect("Failed to write to stream");
            }
            stream.swap_read_write();

            // Create SpaceProver
            let prover = SpaceProver::new(stream);

            // Initialize a Transcript
            let label = b"benchmark";
            let mut transcript = Transcript::new(label);

            // Measure proof creation time
            let start = Instant::now();
            let _ = Sumcheck::prove(&mut transcript, prover);
            let duration = start.elapsed().as_secs_f64();
            log_proof_times.push(duration.ln());

            println!("n = {}: Proof Creation Time: {:?}", n, duration);
        }

        // Further analysis of log_proof_times can be done here if needed
    }
}
