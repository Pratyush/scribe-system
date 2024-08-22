use crate::hyperplonk::poly_iop::prelude::ZeroCheck;
use crate::hyperplonk::{
    full_snark::custom_gate::CustomizedGates, pcs::PolynomialCommitmentScheme,
};
use crate::streams::MLE;
use crate::{
    hyperplonk::poly_iop::perm_check_original::PermutationCheck, streams::serialize::RawPrimeField,
};
use ark_ec::pairing::Pairing;
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Valid};
use ark_std::log2;

use super::prelude::HyperPlonkErrors;

/// The proof for the HyperPlonk PolyIOP, consists of the following:
///   - the commitments to all witness MLEs
///   - a batch opening to all the MLEs at certain index
///   - the zero-check proof for checking custom gate-satisfiability
///   - the permutation-check proof for checking the copy constraints
#[derive(Clone, Debug, PartialEq)]
pub struct HyperPlonkProof<E, PC, PCS>
where
    E: Pairing,
    E::ScalarField: RawPrimeField,
    PC: PermutationCheck<E, PCS>,
    PCS: PolynomialCommitmentScheme<E>,
{
    // PCS commit for witnesses
    pub witness_commits: Vec<PCS::Commitment>,
    pub batch_openings: PCS::BatchProof,
    // =======================================================================
    // IOP proofs
    // =======================================================================
    // the custom gate zerocheck proof
    pub zero_check_proof: <PC as ZeroCheck<E::ScalarField>>::ZeroCheckProof,
    // the permutation check proof for copy constraints
    pub perm_check_proof: PC::PermutationProof,
}

/// The HyperPlonk instance parameters, consists of the following:
///   - the number of constraints
///   - number of public input columns
///   - the customized gate function
#[derive(Clone, Debug, Default, PartialEq, Eq, CanonicalDeserialize, CanonicalSerialize)]
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

    /// evaluate the identical polynomial
    pub fn eval_id_oracle<F: PrimeField>(&self, point: &[F]) -> Result<F, HyperPlonkErrors> {
        let len = self.num_variables() + (log2(self.num_witness_columns()) as usize);
        if point.len() != len {
            return Err(HyperPlonkErrors::InvalidParameters(format!(
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

/// The HyperPlonk index, consists of the following:
///   - HyperPlonk parameters
///   - the wire permutation
///   - the selector vectors
#[derive(Clone, Debug, Default, Eq, PartialEq, CanonicalDeserialize, CanonicalSerialize)]
pub struct HyperPlonkIndex<F: RawPrimeField> {
    pub params: HyperPlonkParams,
    pub permutation: Vec<MLE<F>>,
    pub selectors: Vec<MLE<F>>,
}

impl<F: RawPrimeField> HyperPlonkIndex<F> {
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
#[derive(Clone, Debug, Default, PartialEq)]
pub struct HyperPlonkProvingKey<E: Pairing, PCS: PolynomialCommitmentScheme<E>>
where
    E::ScalarField: RawPrimeField,
{
    /// Hyperplonk instance parameters
    pub params: HyperPlonkParams,
    /// The preprocessed permutation polynomials
    pub permutation_oracles: Vec<MLE<E::ScalarField>>,
    /// The preprocessed selector polynomials
    pub selector_oracles: Vec<MLE<E::ScalarField>>,
    /// Commitments to the preprocessed selector polynomials
    pub selector_commitments: Vec<PCS::Commitment>,
    /// Commitments to the preprocessed permutation polynomials
    pub permutation_commitments: Vec<PCS::Commitment>,
    /// The parameters for PCS commitment
    pub pcs_param: PCS::ProverParam,
}

impl<E: Pairing, PCS: PolynomialCommitmentScheme<E>> CanonicalDeserialize for HyperPlonkProvingKey<E, PCS>
where
    E::ScalarField: RawPrimeField,
{
    fn deserialize_with_mode<R: std::io::Read>(
        mut reader: R,
        compress: ark_serialize::Compress,
        validate: ark_serialize::Validate,
    ) -> Result<Self, ark_serialize::SerializationError> {
        let params = HyperPlonkParams::deserialize_with_mode(&mut reader, compress, validate)?;
        let permutation_oracles = Vec::<MLE<E::ScalarField>>::deserialize_with_mode(&mut reader, compress, validate)?;
        let selector_oracles = Vec::<MLE<E::ScalarField>>::deserialize_with_mode(&mut reader, compress, validate)?;
        let selector_commitments = Vec::<PCS::Commitment>::deserialize_with_mode(&mut reader, compress, validate)?;
        let permutation_commitments = Vec::<PCS::Commitment>::deserialize_with_mode(&mut reader, compress, validate)?;
        let pcs_param = PCS::ProverParam::deserialize_with_mode(&mut reader, compress, validate)?;
        Ok(Self {
            params,
            permutation_oracles,
            selector_oracles,
            selector_commitments,
            permutation_commitments,
            pcs_param,
        })
    }
}

impl<E: Pairing, PCS: PolynomialCommitmentScheme<E>> Valid for HyperPlonkProvingKey<E, PCS>
where
    E::ScalarField: RawPrimeField,
{
    fn batch_check<'a>(
        _batch: impl Iterator<Item = &'a Self> + Send,
    ) -> Result<(), ark_serialize::SerializationError>
    where
        Self: 'a, 
    {
        unimplemented!()
    }

    fn check(&self) -> Result<(), ark_serialize::SerializationError> {
        unimplemented!()
    }
}

impl<E: Pairing, PCS: PolynomialCommitmentScheme<E>> CanonicalSerialize for HyperPlonkProvingKey<E, PCS>
where
    E::ScalarField: RawPrimeField,
{
    fn serialize_with_mode<W: std::io::Write>(
        &self,
        mut writer: W,
        compress: ark_serialize::Compress,
    ) -> Result<(), ark_serialize::SerializationError> {
        self.params.serialize_with_mode(&mut writer, compress)?;
        self.permutation_oracles.serialize_with_mode(&mut writer, compress)?;
        self.selector_oracles.serialize_with_mode(&mut writer, compress)?;
        self.selector_commitments.serialize_with_mode(&mut writer, compress)?;
        self.permutation_commitments.serialize_with_mode(&mut writer, compress)?;
        self.pcs_param.serialize_with_mode(&mut writer, compress)?;
        Ok(())
    }

    fn serialized_size(&self, compress: ark_serialize::Compress) -> usize {
        unimplemented!()
    }
}

/// The HyperPlonk verifying key, consists of the following:
///   - the hyperplonk instance parameters
///   - the commitments to the preprocessed polynomials output by the indexer
///   - the parameters for polynomial commitment
#[derive(Clone, Debug, Default, PartialEq, CanonicalDeserialize, CanonicalSerialize)]
pub struct HyperPlonkVerifyingKey<E: Pairing, PCS: PolynomialCommitmentScheme<E>> {
    /// Hyperplonk instance parameters
    pub params: HyperPlonkParams,
    /// The parameters for PCS commitment
    pub pcs_param: PCS::VerifierParam,
    /// A commitment to the preprocessed selector polynomials
    pub selector_commitments: Vec<PCS::Commitment>,
    // pub selector: Vec<Arc<Mutex<DenseMLPolyStream<F>>>>,
    /// Permutation oracles' commitments
    pub perm_commitments: Vec<PCS::Commitment>,
}


#[cfg(test)]
mod test {
    use std::fs::File;

    use super::*;
    use crate::hyperplonk::full_snark::mock::MockCircuit;
    use crate::hyperplonk::full_snark::utils::memory_traces;
    use crate::hyperplonk::full_snark::{errors::HyperPlonkErrors, HyperPlonkSNARK};
    use crate::hyperplonk::pcs::multilinear_kzg::srs::MultilinearUniversalParams;
    use crate::hyperplonk::pcs::multilinear_kzg::MultilinearKzgPCS;
    use crate::hyperplonk::pcs::PolynomialCommitmentScheme;
    use crate::hyperplonk::poly_iop::PolyIOP;
    use ark_bls12_381::Bls12_381;
    use ark_bls12_381::Fr;
    use ark_std::test_rng;
    use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Write};
    use crate::streams::iterator::BatchedIterator;

    const SUPPORTED_SIZE: usize = 22;
    const MIN_NUM_VARS: usize = 10;
    const MAX_NUM_VARS: usize = 22;
    const CUSTOM_DEGREE: [usize; 4] = [1, 2, 4, 8];

    #[test]
    fn test_pk_serialization() -> Result<(), HyperPlonkErrors> {
        let mut rng = test_rng();
        let srs = MultilinearKzgPCS::<Bls12_381>::gen_fake_srs_for_testing(&mut rng, 6).unwrap();

        let vanilla_gate = CustomizedGates::vanilla_plonk_gate();
        let circuit = MockCircuit::<Fr>::new(1 << 6, &vanilla_gate);

        let index = circuit.index;
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(8)
            .build()
            .unwrap();

        let (pk, vk) = pool.install(|| {
            <PolyIOP<Fr> as HyperPlonkSNARK<Bls12_381, MultilinearKzgPCS<_>>>::preprocess(
                &index, &srs,
            )
        }).unwrap();

        let file = File::create("pk.serialization.test").unwrap();
        pk.serialize_uncompressed(&file).unwrap();

        let file_2 = File::open("pk.serialization.test").unwrap();
        let pk_2 = HyperPlonkProvingKey::<Bls12_381, MultilinearKzgPCS<Bls12_381>>::deserialize_uncompressed_unchecked(&file_2).unwrap();
        println!("{:?}", pk_2.params);
        pk_2.permutation_oracles.iter().for_each(|perm| println!("perm oracle: {:?}", perm.evals().iter().to_vec()));
        pk_2.selector_oracles.iter().for_each(|perm| println!("selector oracle: {:?}", perm.evals().iter().to_vec()));    

        Ok(())
    }
}