use ark_ff::Field;
use ark_std::borrow::Borrow;
use ark_std::cmp::Ordering;
use ark_std::log2;
use ark_std::vec::Vec;

use crate::prover::RoundMsg;
use crate::read_write::{DenseMLPolyStream, ReadStream, WriteStream};
use crate::prover::Prover;

pub struct SpaceProver<F: Field> {
    /// Randomness given by the verifier, used to fold the right-hand side.
    challenges: Vec<F>,
    /// Batched sumcheck instance.
    witness: DenseMLPolyStream<F>,
    /// Round counter.
    round: usize,
    /// Total number of rounds.
    tot_rounds: usize,
}

impl<F: Field> SpaceProver<F> {
    pub fn new(witness: DenseMLPolyStream<F>) -> Self {
        let tot_rounds = witness.num_vars;
        let challenges = Vec::with_capacity(tot_rounds);
        let round = 0;
        SpaceProver {
            challenges,
            witness,
            round,
            tot_rounds,
        }
    }
}

impl<F: Field> Prover<F> for SpaceProver<F> {
    fn next_message(&mut self, verifier_message: Option<F>) -> Option<RoundMsg<F>> {
        assert!(self.round <= self.tot_rounds, "More rounds than needed.");

        if let Some(challenge) = verifier_message {
            self.challenges.push(challenge);
        }

        if self.round == self.tot_rounds {
            return None;
        }

        let mut a_i0 = F::zero();
        let mut a_i1 = F::zero();

        while let (Some(a_even), Some(a_odd)) = (self.witness.read_next(), self.witness.read_next()) {
            a_i0 += a_even;
            a_i1 += a_odd;
        }

        self.witness.read_restart();

        Some(RoundMsg(a_i0, a_i1))
    }

    fn update_stream(&mut self, challenge: F) {
        while let (Some(a_even), Some(a_odd)) = (self.witness.read_next(), self.witness.read_next()) {
            self.witness.write_next(a_even * (F::one() - challenge) + a_odd * challenge);
        }

        self.witness.read_restart();
        self.witness.write_restart();

        self.round += 1;
    }

    fn round(&self) -> usize {
        self.round
    }

    fn rounds(&self) -> usize {
        self.tot_rounds
    }

}