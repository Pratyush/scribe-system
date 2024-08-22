use crate::{
    full_snark::errors::HyperPlonkErrors,
    streams::{serialize::RawPrimeField, MLE},
};
use ark_ff::PrimeField;
use ark_std::log2;

/// A row of witnesses of width `#wires`
#[derive(Debug, Clone)]
pub struct WitnessRow<F: PrimeField>(pub(crate) Vec<F>);

/// A column of witnesses of length `#constraints`
#[derive(Debug, Clone, Default)]
pub struct WitnessColumn<F: PrimeField>(pub(crate) Vec<F>);

impl<F: PrimeField> WitnessColumn<F> {
    /// the number of variables of the multilinear polynomial that presents a
    /// column.
    pub fn get_nv(&self) -> usize {
        log2(self.0.len()) as usize
    }

    /// Append a new element to the witness column
    pub fn append(&mut self, new_element: F) {
        self.0.push(new_element)
    }

    /// Build witness columns from rows
    pub fn from_witness_rows(
        witness_rows: &[WitnessRow<F>],
    ) -> Result<Vec<Self>, HyperPlonkErrors> {
        if witness_rows.is_empty() {
            return Err(HyperPlonkErrors::InvalidParameters(
                "empty witness rows".to_string(),
            ));
        }

        let mut res = Vec::with_capacity(witness_rows.len());
        let num_columns = witness_rows[0].0.len();

        for i in 0..num_columns {
            let mut cur_column = Vec::new();
            for row in witness_rows.iter() {
                cur_column.push(row.0[i])
            }
            res.push(Self(cur_column))
        }

        Ok(res)
    }

    pub fn coeff_ref(&self) -> &[F] {
        self.0.as_ref()
    }
}

impl<F: RawPrimeField> From<&WitnessColumn<F>> for MLE<F> {
    fn from(witness: &WitnessColumn<F>) -> Self {
        let nv = witness.get_nv();
        Self::from_evals_vec(witness.0.clone(), nv)
    }
}
