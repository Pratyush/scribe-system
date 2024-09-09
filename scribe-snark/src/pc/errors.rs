use crate::arithmetic::errors::ArithError;
use crate::transcript::TranscriptError;
use ark_serialize::SerializationError;
use ark_std::string::String;
use displaydoc::Display;

/// A `enum` specifying the possible failure modes of the PC.
#[derive(Display, Debug)]
pub enum PCSError {
    /// Invalid Prover: {0}
    InvalidProver(String),
    /// Invalid Verifier: {0}
    InvalidVerifier(String),
    /// Invalid Proof: {0}
    InvalidProof(String),
    /// Invalid parameters: {0}
    InvalidParameters(String),
    /// An error during (de)serialization: {0}
    SerializationError(SerializationError),
    /// Transcript error {0}
    TranscriptError(TranscriptError),
    /// ArithErrors error {0}
    ArithErrors(ArithError),
}

impl From<SerializationError> for PCSError {
    fn from(e: ark_serialize::SerializationError) -> Self {
        Self::SerializationError(e)
    }
}

impl From<TranscriptError> for PCSError {
    fn from(e: TranscriptError) -> Self {
        Self::TranscriptError(e)
    }
}

impl From<ArithError> for PCSError {
    fn from(e: ArithError) -> Self {
        Self::ArithErrors(e)
    }
}
