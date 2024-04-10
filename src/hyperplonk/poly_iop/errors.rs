// use crate::pcs::prelude::PCSError;
// use arithmetic::ArithErrors;
use ark_std::string::String;
use displaydoc::Display;
// use transcript::TranscriptError;
use crate::arithmetic::errors::ArithError;
use crate::hyperplonk::pcs::prelude::PCSError;
use crate::hyperplonk::transcript::TranscriptError;

/// A `enum` specifying the possible failure modes of the PolyIOP.
#[derive(Display, Debug)]
pub enum PIOPError {
    /// Invalid Prover: {0}
    InvalidProver(String),
    /// Invalid Verifier: {0}
    InvalidVerifier(String),
    /// Invalid Proof: {0}
    InvalidProof(String),
    /// Invalid parameters: {0}
    InvalidParameters(String),
    /// Invalid challenge: {0}
    InvalidChallenge(String),
    /// Should not arrive to this point
    ShouldNotArrive,
    /// An error during (de)serialization: {0}
    SerializationError(ark_serialize::SerializationError),
    /// Transcript Error: {0}
    TranscriptError(TranscriptError),
    /// Arithmetic Error: {0}
    ArithmeticError(ArithError),
    ///PCS error {0}
    PCSError(PCSError),
}

impl From<ark_serialize::SerializationError> for PIOPError {
    fn from(e: ark_serialize::SerializationError) -> Self {
        Self::SerializationError(e)
    }
}

impl From<TranscriptError> for PIOPError {
    fn from(e: TranscriptError) -> Self {
        Self::TranscriptError(e)
    }
}

impl From<ArithError> for PIOPError {
    fn from(e: ArithError) -> Self {
        Self::ArithmeticError(e)
    }
}

impl From<PCSError> for PIOPError {
    fn from(e: PCSError) -> Self {
        Self::PCSError(e)
    }
}
