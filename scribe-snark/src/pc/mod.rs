pub mod errors;
pub mod pst13;
pub mod structs;

use crate::transcript::IOPTranscript;
use ark_ec::pairing::Pairing;
use ark_ff::Field;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::Rng;
use errors::PCError;
use std::{borrow::Borrow, fmt::Debug, hash::Hash};

/// This trait defines APIs for polynomial commitment schemes.
/// Note that for our usage of PC, we do not require the hiding property.
pub trait PCScheme<E: Pairing> {
    /// Prover parameters
    type CommitterKey: Sync + CanonicalDeserialize + CanonicalSerialize;
    /// Verifier parameters
    type VerifierKey: Debug + Clone + CanonicalSerialize + CanonicalDeserialize;
    /// Structured reference string
    type SRS;
    /// Polynomial and its associated types
    type Polynomial: Clone + Debug;
    /// Polynomial input domain
    type Point: Clone + Ord + Debug + Sync + Hash + PartialEq + Eq;
    /// Polynomial Evaluation
    type Evaluation: Field;
    /// Commitments
    type Commitment: Copy
        + CanonicalSerialize
        + CanonicalDeserialize
        + Debug
        + PartialEq
        + Eq
        + Send;
    /// Proofs
    type Proof: Clone + CanonicalSerialize + CanonicalDeserialize + Debug + PartialEq + Eq;
    /// Batch proofs
    type BatchProof;

    /// Build SRS for testing.
    ///
    /// - For univariate polynomials, `supported_size` is the maximum degree.
    /// - For multilinear polynomials, `supported_size` is the number of
    ///   variables.
    ///
    /// WARNING: THIS FUNCTION IS FOR TESTING PURPOSE ONLY.
    /// THE OUTPUT SRS SHOULD NOT BE USED IN PRODUCTION.
    fn gen_srs_for_testing<R: Rng>(
        rng: &mut R,
        supported_size: usize,
    ) -> Result<Self::SRS, PCError>;

    fn gen_fake_srs_for_testing<R: Rng>(
        rng: &mut R,
        supported_size: usize,
    ) -> Result<Self::SRS, PCError>;

    /// Trim the universal parameters to specialize the public parameters.
    /// Input both `supported_degree` for univariate and
    /// `supported_num_vars` for multilinear.
    /// ## Note on function signature
    /// Usually, data structure like SRS and ProverParam are huge and users
    /// might wish to keep them in heap using different kinds of smart pointers
    /// (instead of only in stack) therefore our `impl Borrow<_>` interface
    /// allows for passing in any pointer type, e.g.: `trim(srs: &Self::SRS,
    /// ..)` or `trim(srs: Box<Self::SRS>, ..)` or `trim(srs: Arc<Self::SRS>,
    /// ..)` etc.
    fn trim(
        srs: impl Borrow<Self::SRS>,
        supported_num_vars: usize,
    ) -> Result<(Self::CommitterKey, Self::VerifierKey), PCError>;

    /// Generate a commitment for a polynomial
    /// ## Note on function signature
    /// Usually, data structure like SRS and ProverParam are huge and users
    /// might wish to keep them in heap using different kinds of smart pointers
    /// (instead of only in stack) therefore our `impl Borrow<_>` interface
    /// allows for passing in any pointer type, e.g.: `commit(prover_param:
    /// &Self::ProverParam, ..)` or `commit(prover_param:
    /// Box<Self::ProverParam>, ..)` or `commit(prover_param:
    /// Arc<Self::ProverParam>, ..)` etc.
    fn commit(
        ck: impl Borrow<Self::CommitterKey>,
        poly: &Self::Polynomial,
    ) -> Result<Self::Commitment, PCError>;

    fn batch_commit(
        ck: impl Borrow<Self::CommitterKey>,
        polys: &[Self::Polynomial],
    ) -> Result<Vec<Self::Commitment>, PCError>; 

    /// On input a polynomial `p` and a point `point`, outputs a proof for the
    /// same.
    fn open(
        ck: impl Borrow<Self::CommitterKey>,
        polynomial: &Self::Polynomial,
        point: &Self::Point,
    ) -> Result<(Self::Proof, Self::Evaluation), PCError>;

    // this is the multi poly multi point version
    /// Input a list of multilinear extensions, and a same number of points, and
    /// a transcript, compute a multi-opening for all the polynomials.
    fn multi_open(
        ck: impl Borrow<Self::CommitterKey>,
        polynomials: &[Self::Polynomial],
        points: &[Self::Point],
        evals: &[Self::Evaluation],
        transcript: &mut IOPTranscript<E::ScalarField>,
    ) -> Result<Self::BatchProof, PCError>;

    /// Verifies that `value` is the evaluation at `x` of the polynomial
    /// committed inside `comm`.
    fn verify(
        vk: &Self::VerifierKey,
        commitment: &Self::Commitment,
        point: &Self::Point,
        value: &E::ScalarField,
        proof: &Self::Proof,
    ) -> Result<bool, PCError>;

    /// Verifies that `value_i` is the evaluation at `x_i` of the polynomial
    /// `poly_i` committed inside `comm`.
    fn batch_verify(
        vk: &Self::VerifierKey,
        commitments: &[Self::Commitment],
        points: &[Self::Point],
        batch_proof: &Self::BatchProof,
        transcript: &mut IOPTranscript<E::ScalarField>,
    ) -> Result<bool, PCError>;
}

/// API definitions for structured reference string
pub trait StructuredReferenceString<E: Pairing>: Sized {
    /// Prover parameters
    type CommitterKey;
    /// Verifier parameters
    type VerifierKey;

    /// Extract the prover parameters from the public parameters.
    fn extract_ck(&self, supported_size: usize) -> Self::CommitterKey;
    /// Extract the verifier parameters from the public parameters.
    fn extract_vk(&self, supported_size: usize) -> Self::VerifierKey;

    /// Trim the universal parameters to specialize the public parameters
    /// for polynomials to the given `supported_size`, and
    /// returns committer key and verifier key.
    ///
    /// - For univariate polynomials, `supported_size` is the maximum degree.
    /// - For multilinear polynomials, `supported_size` is 2 to the number of
    ///   variables.
    ///
    /// `supported_log_size` should be in range `1..=params.log_size`
    fn trim(
        &self,
        supported_size: usize,
    ) -> Result<(Self::CommitterKey, Self::VerifierKey), PCError>;

    /// Build SRS for testing.
    ///
    /// - For univariate polynomials, `supported_size` is the maximum degree.
    /// - For multilinear polynomials, `supported_size` is the number of
    ///   variables.
    ///
    /// WARNING: THIS FUNCTION IS FOR TESTING PURPOSE ONLY.
    /// THE OUTPUT SRS SHOULD NOT BE USED IN PRODUCTION.
    fn gen_srs_for_testing<R: Rng>(rng: &mut R, supported_size: usize) -> Result<Self, PCError>;

    fn gen_fake_srs_for_testing<R: Rng>(
        rng: &mut R,
        supported_degree: usize,
    ) -> Result<Self, PCError>;
}
