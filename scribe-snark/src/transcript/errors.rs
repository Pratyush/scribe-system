use ark_std::string::String;

/// A `enum` specifying the possible failure modes of the Transcript.
#[derive(Debug)]
pub enum TranscriptError {
    /// Invalid Transcript: {0}
    InvalidTranscript(String),
    /// An error during (de)serialization: {0}
    SerializationError(ark_serialize::SerializationError),
}

impl From<ark_serialize::SerializationError> for TranscriptError {
    fn from(e: ark_serialize::SerializationError) -> Self {
        Self::SerializationError(e)
    }
}
