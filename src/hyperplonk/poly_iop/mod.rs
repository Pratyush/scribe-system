use ark_ff::PrimeField;
use std::marker::PhantomData;

pub mod errors;
pub mod structs;
pub mod sum_check;

#[derive(Clone, Debug, Default, Copy, PartialEq, Eq)]
/// Struct for PolyIOP protocol.
/// It has an associated type `F` that defines the prime field the multi-variate
/// polynomial operates on.
///
/// An PolyIOP may be instantiated with one of the following:
/// - SumCheck protocol.
/// - ZeroCheck protocol.
/// - PermutationCheck protocol.
///
/// Those individual protocol may have similar or identical APIs.
/// The systematic way to invoke specific protocol is, for example
///     `<PolyIOP<F> as SumCheck<F>>::prove()`
pub struct PolyIOP<F: PrimeField> {
    /// Associated field
    #[doc(hidden)]
    phantom: PhantomData<F>,
}
