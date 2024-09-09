use crate::piop::{perm_check_original::PermutationProof, zero_check::ZeroCheckProof};
use crate::streams::serialize::RawPrimeField;
use crate::streams::MLE;
use crate::{pc::PolynomialCommitmentScheme, snark::custom_gate::CustomizedGates};
use ark_ec::pairing::Pairing;
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::log2;

use super::prelude::ScribeErrors;

/// The proof for the Scribe PolyIOP, consists of the following:
///   - the commitments to all witness MLEs
///   - a batch opening to all the MLEs at certain index
///   - the zero-check proof for checking custom gate-satisfiability
///   - the permutation-check proof for checking the copy constraints
#[derive(Clone, Debug, PartialEq)]
pub struct Proof<E, PC>
where
    E: Pairing,
    E::ScalarField: RawPrimeField,
    PC: PolynomialCommitmentScheme<E>,
{
    // PC commit for witnesses
    pub witness_commits: Vec<PC::Commitment>,
    pub batch_openings: PC::BatchProof,
    // =======================================================================
    // IOP proofs
    // =======================================================================
    // the custom gate zerocheck proof
    pub zero_check_proof: ZeroCheckProof<E::ScalarField>,
    // the permutation check proof for copy constraints
    pub perm_check_proof: PermutationProof<E, PC>,
}

/// The Scribe instance parameters, consists of the following:
///   - the number of constraints
///   - number of public input columns
///   - the customized gate function
#[derive(Clone, Debug, Default, PartialEq, Eq, CanonicalDeserialize, CanonicalSerialize)]
pub struct ScribeParams {
    /// the number of constraints
    pub num_constraints: usize,
    /// number of public input
    // public input is only 1 column and is implicitly the first witness column.
    // this size must not exceed number of constraints.
    pub num_pub_input: usize,
    /// customized gate function
    pub gate_func: CustomizedGates,
}

impl ScribeParams {
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

    /// evaluate the identical polynomial
    pub fn eval_id_oracle<F: PrimeField>(&self, point: &[F]) -> Result<F, ScribeErrors> {
        let len = self.num_variables() + (log2(self.num_witness_columns()) as usize);
        if point.len() != len {
            return Err(ScribeErrors::InvalidParameters(format!(
                "ID oracle point length = {}, expected {}",
                point.len(),
                len,
            )));
        }

        let mut res = F::zero();
        let mut base = F::one();
        for &v in point.iter() {
            res += base * v;
            base += base;
        }
        Ok(res)
    }
}

/// The Scribe index, consists of the following:
///   - Scribe parameters
///   - the wire permutation
///   - the selector vectors
#[derive(Clone, Debug, Default, Eq, PartialEq, CanonicalDeserialize, CanonicalSerialize)]
pub struct Index<F: RawPrimeField> {
    pub params: ScribeParams,
    pub permutation: Vec<MLE<F>>,
    pub selectors: Vec<MLE<F>>,
}

impl<F: RawPrimeField> Index<F> {
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

/// The Scribe proving key, consists of the following:
///   - the scribe instance parameters
///   - the preprocessed polynomials output by the indexer
///   - the commitment to the selectors and permutations
///   - the parameters for polynomial commitment
#[derive(Clone, Debug, Default, PartialEq, CanonicalDeserialize, CanonicalSerialize)]
pub struct ProvingKey<E: Pairing, PC: PolynomialCommitmentScheme<E>>
where
    E::ScalarField: RawPrimeField,
{
    /// scribe instance parameters
    pub params: ScribeParams,
    /// The preprocessed permutation polynomials
    pub permutation_oracles: Vec<MLE<E::ScalarField>>,
    /// The preprocessed selector polynomials
    pub selector_oracles: Vec<MLE<E::ScalarField>>,
    /// Commitments to the preprocessed selector polynomials
    pub selector_commitments: Vec<PC::Commitment>,
    /// Commitments to the preprocessed permutation polynomials
    pub permutation_commitments: Vec<PC::Commitment>,
    /// The parameters for PC commitment
    pub pcs_param: PC::ProverParam,
}

/// The Scribe verifying key, consists of the following:
///   - the scribe instance parameters
///   - the commitments to the preprocessed polynomials output by the indexer
///   - the parameters for polynomial commitment
#[derive(Clone, Debug, Default, PartialEq, CanonicalDeserialize, CanonicalSerialize)]
pub struct VerifyingKey<E: Pairing, PC: PolynomialCommitmentScheme<E>> {
    /// scribe instance parameters
    pub params: ScribeParams,
    /// The parameters for PC commitment
    pub pcs_param: PC::VerifierParam,
    /// A commitment to the preprocessed selector polynomials
    pub selector_commitments: Vec<PC::Commitment>,
    // pub selector: Vec<Arc<Mutex<DenseMLPolyStream<F>>>>,
    /// Permutation oracles' commitments
    pub perm_commitments: Vec<PC::Commitment>,
}

#[cfg(test)]
mod test {
    use std::fs::File;

    use super::*;
    use crate::snark::mock::MockCircuit;

    use crate::snark::{errors::ScribeErrors, Scribe};

    use crate::pc::multilinear_kzg::PST13;
    use crate::pc::PolynomialCommitmentScheme;
    use ark_bls12_381::Bls12_381;
    use ark_bls12_381::Fr;
    use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
    use ark_std::test_rng;

    #[test]
    fn test_pk_serialization() -> Result<(), ScribeErrors> {
        let mut rng = test_rng();
        let srs = PST13::<Bls12_381>::gen_fake_srs_for_testing(&mut rng, 6).unwrap();

        let vanilla_gate = CustomizedGates::vanilla_plonk_gate();
        let circuit = MockCircuit::<Fr>::new(1 << 6, &vanilla_gate);

        let index = circuit.index;
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(8)
            .build()
            .unwrap();

        let (pk, _): (ProvingKey<_, PST13<Bls12_381>>, _) =
            pool.install(|| Scribe::preprocess(&index, &srs)).unwrap();

        let file = File::create("pk.serialization.test").unwrap();
        pk.serialize_uncompressed(&file).unwrap();

        let file_2 = File::open("pk.serialization.test").unwrap();
        let pk_2 =
            ProvingKey::<Bls12_381, PST13<Bls12_381>>::deserialize_uncompressed_unchecked(&file_2)
                .unwrap();
        pk_2.permutation_oracles
            .iter()
            .for_each(|p| println!("perm oracle: {p}"));
        pk_2.selector_oracles
            .iter()
            .for_each(|s| println!("selector oracle: {s}"));

        Ok(())
    }
}
