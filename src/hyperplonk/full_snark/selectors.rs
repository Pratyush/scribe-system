use crate::{hyperplonk::full_snark::errors::HyperPlonkErrors, streams::{serialize::RawPrimeField, MLE}};
use ark_ff::PrimeField;
use ark_std::log2;

/// A row of selector of width `#selectors`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectorRow<F: PrimeField>(pub(crate) Vec<F>);

/// A column of selectors of length `#constraints`
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SelectorColumn<F: PrimeField>(pub(crate) Vec<F>);

impl<F: PrimeField> SelectorColumn<F> {
    /// the number of variables of the multilinear polynomial that presents a
    /// column.
    pub fn get_nv(&self) -> usize {
        log2(self.0.len()) as usize
    }

    /// Append a new element to the selector column
    pub fn append(&mut self, new_element: F) {
        self.0.push(new_element)
    }

    /// Build selector columns from rows
    pub fn from_selector_rows(
        selector_rows: &[SelectorRow<F>],
    ) -> Result<Vec<Self>, HyperPlonkErrors> {
        if selector_rows.is_empty() {
            return Err(HyperPlonkErrors::InvalidParameters(
                "empty witness rows".to_string(),
            ));
        }

        let mut res = Vec::with_capacity(selector_rows.len());
        let num_colnumns = selector_rows[0].0.len();

        for i in 0..num_colnumns {
            let mut cur_column = Vec::new();
            for row in selector_rows.iter() {
                cur_column.push(row.0[i])
            }
            res.push(Self(cur_column))
        }

        Ok(res)
    }
}

impl<F: RawPrimeField> From<&SelectorColumn<F>> for MLE<F> {
    fn from(witness: &SelectorColumn<F>) -> Self {
        let nv = witness.get_nv();
        Self::from_evals_vec(witness.0.clone(), nv)
    }
}
