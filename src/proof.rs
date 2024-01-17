use ark_ff::Field;
use ark_std::borrow::Borrow;
use ark_std::boxed::Box;
use ark_std::vec::Vec;
use crate::prover::RoundMsg;
use crate::prover::Prover;
use crate::transcript::GeminiTranscript;

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
    /// Prove function for the scalar product.
    /// The input contains a randomness generator and a prover struct.
    /// The prover struct can be either time-efficient or space-efficient
    /// depending on the configuration.
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