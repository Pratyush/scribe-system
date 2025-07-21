use crate::pc::errors::PCError;
use crate::piop::errors::PIOPError;
use crate::transcript::TranscriptError;
use ark_serialize::SerializationError;
use ark_std::string::String;
use mle::errors::ArithError;

/// A `enum` specifying the possible failure modes of scribe.
#[derive(Debug)]
pub enum ScribeErrors {
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
    /// PC error {0}
    PCSErrors(PCError),
    /// Transcript error {0}
    TranscriptError(TranscriptError),
    /// Arithmetic Error: {0}
    ArithmeticErrors(ArithError),
}

impl From<SerializationError> for ScribeErrors {
    fn from(e: ark_serialize::SerializationError) -> Self {
        Self::SerializationError(e)
    }
}

impl From<PIOPError> for ScribeErrors {
    fn from(e: PIOPError) -> Self {
        Self::PolyIOPErrors(e)
    }
}

impl From<PCError> for ScribeErrors {
    fn from(e: PCError) -> Self {
        Self::PCSErrors(e)
    }
}

impl From<TranscriptError> for ScribeErrors {
    fn from(e: TranscriptError) -> Self {
        Self::TranscriptError(e)
    }
}

impl From<ArithError> for ScribeErrors {
    fn from(e: ArithError) -> Self {
        Self::ArithmeticErrors(e)
    }
}
