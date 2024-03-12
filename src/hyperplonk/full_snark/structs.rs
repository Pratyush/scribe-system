use crate::hyperplonk::pcs::multilinear_kzg::batching::BatchProofSinglePoint;
use crate::{
    hyperplonk::{
        full_snark::custom_gate::CustomizedGates, pcs::PolynomialCommitmentScheme,
        poly_iop::prelude::SumCheck,
    },
    read_write::DenseMLPolyStream,
};
use ark_ec::pairing::Pairing;
use ark_ff::PrimeField;
use ark_std::log2;
use std::sync::{Arc, Mutex};

/// The proof for the HyperPlonk PolyIOP, consists of the following:
///   - the commitments to all witness MLEs
///   - a batch opening to all the MLEs at certain index
///   - the batch sum check proof
#[derive(Clone)]
pub struct HyperPlonkProof<E, SC, PCS>
where
    E: Pairing,
    SC: SumCheck<E::ScalarField>,
    PCS: PolynomialCommitmentScheme<E>,
{
    pub witness_commits: Vec<PCS::Commitment>,
    pub opening: BatchProofSinglePoint<E, PCS>,
    pub sum_check_proof: SC::SumCheckProof,
    pub h_comm: PCS::Commitment,
    pub h_prime_comm: PCS::Commitment,
}

/// The HyperPlonk instance parameters, consists of the following:
///   - the number of constraints
///   - number of public input columns
///   - the customized gate function
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HyperPlonkParams {
    /// the number of constraints
    pub num_constraints: usize,
    /// number of public input
    // public input is only 1 column and is implicitly the first witness column.
    // this size must not exceed number of constraints.
    pub num_pub_input: usize,
    /// customized gate function
    pub gate_func: CustomizedGates,
}

impl HyperPlonkParams {
    /// Number of variables in a multilinear system
    pub fn num_variables(&self) -> usize {
        log2(self.num_constraints) as usize
    }

    /// number of selector columns
    pub fn num_selector_columns(&self) -> usize {
        self.gate_func.num_selector_columns()
    }

    /// number of witness columns
    pub fn num_witness_columns(&self) -> usize {
        self.gate_func.num_witness_columns()
    }
}

/// The HyperPlonk index, consists of the following:
///   - HyperPlonk parameters
///   - the wire permutation
///   - the selector vectors
#[derive(Clone, Debug)]
pub struct HyperPlonkIndex<F: PrimeField> {
    pub params: HyperPlonkParams,
    pub permutation: Vec<Arc<Mutex<DenseMLPolyStream<F>>>>,
    pub permutation_index: Vec<Arc<Mutex<DenseMLPolyStream<F>>>>,
    pub selectors: Vec<Arc<Mutex<DenseMLPolyStream<F>>>>,
}

impl<F: PrimeField> HyperPlonkIndex<F> {
    /// Number of variables in a multilinear system
    pub fn num_variables(&self) -> usize {
        self.params.num_variables()
    }

    /// number of selector columns
    pub fn num_selector_columns(&self) -> usize {
        self.params.num_selector_columns()
    }

    /// number of witness columns
    pub fn num_witness_columns(&self) -> usize {
        self.params.num_witness_columns()
    }
}

/// The HyperPlonk proving key, consists of the following:
///   - the hyperplonk instance parameters
///   - the preprocessed polynomials output by the indexer
///   - the commitment to the selectors and permutations
///   - the parameters for polynomial commitment
#[derive(Clone, Debug)]
// pub struct HyperPlonkProvingKey<E: Pairing, PCS: PolynomialCommitmentScheme<E>> {
pub struct HyperPlonkProvingKey<E: Pairing, PCS: PolynomialCommitmentScheme<E>> {
    /// Hyperplonk instance parameters
    pub params: HyperPlonkParams,
    /// The preprocessed selector polynomials
    pub selector_oracles: Vec<Arc<Mutex<DenseMLPolyStream<E::ScalarField>>>>,
    /// The preprocessed permutation polynomials
    pub permutation_oracles: (
        Vec<Arc<Mutex<DenseMLPolyStream<E::ScalarField>>>>,
        Vec<Arc<Mutex<DenseMLPolyStream<E::ScalarField>>>>,
    ), // (perm, index)
    /// Commitments to the preprocessed selector polynomials
    pub selector_commitments: Vec<PCS::Commitment>,
    /// Commitments to the preprocessed permutation polynomials
    pub permutation_commitments: (Vec<PCS::Commitment>, Vec<PCS::Commitment>),
    /// The parameters for PCS commitment
    pub pcs_param: PCS::ProverParam,
}

/// The HyperPlonk verifying key, consists of the following:
///   - the hyperplonk instance parameters
///   - the commitments to the preprocessed polynomials output by the indexer
///   - the parameters for polynomial commitment
#[derive(Clone, Debug)]
// pub struct HyperPlonkVerifyingKey<E: Pairing, PCS: PolynomialCommitmentScheme<E>> {
pub struct HyperPlonkVerifyingKey<E: Pairing, PCS: PolynomialCommitmentScheme<E>> {
    /// Hyperplonk instance parameters
    pub params: HyperPlonkParams,
    /// A commitment to the preprocessed selector polynomials
    pub selector_commitments: Vec<PCS::Commitment>,
    // pub selector: Vec<Arc<Mutex<DenseMLPolyStream<F>>>>,
    /// Permutation oracles' commitments
    pub perm_commitments: (Vec<PCS::Commitment>, Vec<PCS::Commitment>), // (perm, index)
    /// The parameters for PCS commitment
    pub pcs_param: PCS::VerifierParam,
}
