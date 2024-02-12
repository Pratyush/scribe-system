// Copyright (c) 2023 Espresso Systems (espressosys.com)
// This file is part of the HyperPlonk library.

// You should have received a copy of the MIT License
// along with the HyperPlonk library. If not, see <https://mit-license.org/>.

//! Main module for the HyperPlonk SNARK.

use std::sync::{Arc, Mutex};

use ark_ff::PrimeField;
// use ark_ec::pairing::Pairing;
use errors::HyperPlonkErrors;
// use subroutines::{pcs::prelude::PolynomialCommitmentScheme, poly_iop::prelude::PermutationCheck};
use crate::{hyperplonk::poly_iop::prelude::PermutationCheck, read_write::DenseMLPolyStream};
// use crate::hyperplonk::poly_iop::perm_check::PermutationCheck;
use witness::WitnessColumn;

mod custom_gate;
mod errors;
mod mock;
pub mod prelude;
mod selectors;
mod snark;
mod structs;
mod utils;
mod witness;

/// A trait for HyperPlonk SNARKs.
/// A HyperPlonk is derived from ZeroChecks and PermutationChecks.
// pub trait HyperPlonkSNARK<E, PCS>: PermutationCheck<E, PCS>
// where
//     E: Pairing,
//     PCS: PolynomialCommitmentScheme<E>,
pub trait HyperPlonkSNARK<F: PrimeField>: PermutationCheck<F> {
    type Index;
    type ProvingKey;
    type VerifyingKey;
    type Proof;

    /// Generate the preprocessed polynomials output by the indexer.
    ///
    /// Inputs:
    /// - `index`: HyperPlonk index
    /// - `pcs_srs`: Polynomial commitment structured reference string
    /// Outputs:
    /// - The HyperPlonk proving key, which includes the preprocessed
    ///   polynomials.
    /// - The HyperPlonk verifying key, which includes the preprocessed
    ///   polynomial commitments
    fn preprocess(
        index: &Self::Index,
        // pcs_srs: &PCS::SRS,
    ) -> Result<(Self::ProvingKey, Self::VerifyingKey), HyperPlonkErrors>;

    /// Generate HyperPlonk SNARK proof.
    ///
    /// Inputs:
    /// - `pk`: circuit proving key
    /// - `pub_input`: online public input
    /// - `witness`: witness assignment
    /// Outputs:
    /// - The HyperPlonk SNARK proof.
    fn prove(
        pk: &Self::ProvingKey,
        // pub_input: &[E::ScalarField],
        pub_input: &[F],
        // witnesses: &[WitnessColumn<E::ScalarField>],
        witnesses: Vec<Arc<Mutex<DenseMLPolyStream<F>>>>,
    ) -> Result<Self::Proof, HyperPlonkErrors>;

    /// Verify the HyperPlonk proof.
    ///
    /// Inputs:
    /// - `vk`: verifying key
    /// - `pub_input`: online public input
    /// - `proof`: HyperPlonk SNARK proof challenges
    /// Outputs:
    /// - Return a boolean on whether the verification is successful
    fn verify(
        vk: &Self::VerifyingKey,
        // pub_input: &[E::ScalarField],
        pub_input: &[F],
        proof: &Self::Proof,
    ) -> Result<bool, HyperPlonkErrors>;
}
