use crate::hyperplonk::pcs::PolynomialCommitmentScheme;
use ark_ec::pairing::Pairing;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BatchProofSinglePoint<E, PCS>
where
    E: Pairing,
    PCS: PolynomialCommitmentScheme<E>,
{
    pub rlc_eval: E::ScalarField, // rlc of f_i(point_i)
    pub(crate) proof: PCS::Proof, // proof for rlc of polynomials
    pub perm_evals: Vec<E::ScalarField>,
    pub perm_index_evals: Vec<E::ScalarField>,
    pub selector_evals: Vec<E::ScalarField>,
    pub witness_evals: Vec<E::ScalarField>,
    pub hp_evals: Vec<E::ScalarField>,
    pub hq_evals: Vec<E::ScalarField>,
}
