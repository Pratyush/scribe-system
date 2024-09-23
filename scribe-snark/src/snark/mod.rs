use crate::streams::serialize::RawPrimeField;
use ark_ec::pairing::Pairing;

use super::pc::PCScheme;

pub mod custom_gate;
pub mod errors;
pub mod mock;
pub mod prelude;
mod selectors;
mod snark;
pub mod structs;
pub mod utils;
mod witness;

/// Marker struct for the Scribe SNARK
pub struct Scribe<E, PC>
where
    E: Pairing,
    E::ScalarField: RawPrimeField,
    PC: PCScheme<E>,
{
    _pairing: std::marker::PhantomData<E>,
    _pcs: std::marker::PhantomData<PC>,
}
