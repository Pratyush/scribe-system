use crate::arithmetic::errors::ArithError;
use crate::pcs::errors::PCSError;
use crate::poly_iop::errors::PIOPError;
use crate::transcript::TranscriptError;
use ark_serialize::SerializationError;
use ark_std::string::String;
use displaydoc::Display;

/// A `enum` specifying the possible failure modes of hyperplonk.
#[derive(Display, Debug)]
pub enum HyperPlonkErrors {
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
    /// PolyIOP error {0}
    PolyIOPErrors(PIOPError),
    /// PCS error {0}
    PCSErrors(PCSError),
    /// Transcript error {0}
    TranscriptError(TranscriptError),
    /// Arithmetic Error: {0}
    ArithmeticErrors(ArithError),
}

impl From<SerializationError> for HyperPlonkErrors {
    fn from(e: ark_serialize::SerializationError) -> Self {
        Self::SerializationError(e)
    }
}

impl From<PIOPError> for HyperPlonkErrors {
    fn from(e: PIOPError) -> Self {
        Self::PolyIOPErrors(e)
    }
}

impl From<PCSError> for HyperPlonkErrors {
    fn from(e: PCSError) -> Self {
        Self::PCSErrors(e)
    }
}

impl From<TranscriptError> for HyperPlonkErrors {
    fn from(e: TranscriptError) -> Self {
        Self::TranscriptError(e)
    }
}

impl From<ArithError> for HyperPlonkErrors {
    fn from(e: ArithError) -> Self {
        Self::ArithmeticErrors(e)
    }
}
