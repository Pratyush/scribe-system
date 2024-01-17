use ark_ff::Field;
use ark_serialize::CanonicalSerialize;

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
    /// Update the stream to half of its prior length.
    fn update_stream(&mut self, challenge: F);
    /// Return the total number of rouds in the protocol.
    fn rounds(&self) -> usize;
    /// Current round number.
    fn round(&self) -> usize;
}
