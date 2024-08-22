use crate::streams::serialize::RawPrimeField;
use ark_ec::pairing::Pairing;

use super::pc::PolynomialCommitmentScheme;

pub mod custom_gate;
pub mod errors;
pub mod mock;
pub mod prelude;
mod selectors;
mod snark;
pub mod structs;
pub mod utils;
mod witness;

/// A trait for HyperPlonk SNARKs.
/// A HyperPlonk is derived from SumCheck
pub struct HyperPlonkSNARK<E, PC>
where
    E: Pairing,
    E::ScalarField: RawPrimeField,
    PC: PolynomialCommitmentScheme<E>,
{
    _pairing: std::marker::PhantomData<E>,
    _pcs: std::marker::PhantomData<PC>,
}
