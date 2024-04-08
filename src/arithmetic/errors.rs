use ark_std::string::String;
use displaydoc::Display;

/// A `enum` specifying the possible failure modes of the arithmetics.
#[derive(Display, Debug)]
pub enum ArithError {
    /// Invalid parameters: {0}
    InvalidParameters(String),
    /// Should not arrive to this point
    ShouldNotArrive,
    /// An error during (de)serialization: {0}
    SerializationErrors(ark_serialize::SerializationError),
}

impl From<ark_serialize::SerializationError> for ArithError {
    fn from(e: ark_serialize::SerializationError) -> Self {
        Self::SerializationErrors(e)
    }
}
