use ark_ff::Field;
use ark_serialize::CanonicalSerialize;
use ark_std::boxed::Box;
use ark_std::iter::Sum;
use ark_std::vec::Vec;

/// Each message from the prover in a sumcheck protocol is a pair of FF-elements.
#[derive(CanonicalSerialize, Copy, Clone, Debug, PartialEq, Eq)]
pub struct RoundMsg<F: Field>(pub(crate) F, pub(crate) F);


/// Prover trait interface for both time-efficient and space-efficient prover.
pub trait Prover<F>: Send + Sync
where
    F: Field,
{
    /// Return the next prover message (if any).
    fn next_message(&mut self, verifier_message: Option<F>) -> Option<RoundMsg<F>>;
    // update stream
    fn update_stream(&mut self, challenge: F);
    // Return the total number of rouds in the protocol.
    fn rounds(&self) -> usize;
    /// Current round number.
    fn round(&self) -> usize;
}
