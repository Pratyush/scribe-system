use ark_ff::Field;
use ark_std::vec::Vec;
use merlin::Transcript;

use crate::prover::Prover;
use crate::prover::RoundMsg;
use crate::read_write::{DenseMLPolyStream, ReadStream, WriteStream};
use crate::transcript::GeminiTranscript;

pub struct SpaceProver<F: Field> {
    // Randomness given by the verifier
    challenges: Vec<F>,
    // Stream of evaluations
    stream: DenseMLPolyStream<F>,
    // Round counter.
    round: usize,
    // Total number of rounds.
    tot_rounds: usize,
}

impl<F: Field> SpaceProver<F> {
    pub fn new(stream: DenseMLPolyStream<F>) -> Self {
        let tot_rounds = stream.num_vars;
        let challenges = Vec::with_capacity(tot_rounds);
        let round = 0;
        SpaceProver {
            challenges,
            stream,
            round,
            tot_rounds,
        }
    }
}

impl<F: Field> Prover<F> for SpaceProver<F> {
    fn next_message(&mut self, transcript: &mut Transcript) -> Option<(RoundMsg<F>, F)> {
        assert!(self.round <= self.tot_rounds, "More rounds than needed.");

        if self.round == self.tot_rounds {
            return None;
        }

        let one = F::ONE;
        let mut a_i0 = F::zero();
        let mut a_i1 = F::zero();
        // Previous round's update
        while let (Some(a_even_0), Some(a_odd_0), Some(a_even_1), Some(a_odd_1)) = (
            self.stream.read_next(),
            self.stream.read_next(),
            self.stream.read_next(),
            self.stream.read_next(),
        ) {
            if let Some(challenge) = self.challenges.last() {
                let temp_0 = a_even_0 * (one - challenge) + a_odd_0 * challenge;
                let temp_1 = a_even_1 * (one - challenge) + a_odd_1 * challenge;
                self.stream.write_next(temp_0);
                self.stream.write_next(temp_1);
                a_i0 += temp_0;
                a_i1 += temp_1;
                self.stream.swap_read_write();
            } else {
                // Handle first round
                a_i0 += a_even_0 + a_even_1;
                a_i1 += a_odd_0 + a_odd_1;
            }
        }

        let message = RoundMsg(a_i0, a_i1);

        // add the message sent to the transcript
        transcript.append_serializable(b"evaluations", &message);
        // compute the challenge for the next round
        let challenge = transcript.get_challenge(b"challenge");
        self.challenges.push(challenge);
        self.round += 1;

        Some((message, challenge))
    }

    fn round(&self) -> usize {
        self.round
    }

    fn rounds(&self) -> usize {
        self.tot_rounds
    }
}
