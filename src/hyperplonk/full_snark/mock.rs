use std::{ops::{AddAssign, MulAssign}, sync::{Arc, Mutex}};

use crate::streams::{iterator::BatchedIterator, MLE};
use ark_ff::PrimeField;
use ark_std::{
    end_timer, log2,
    rand::{rngs::StdRng, SeedableRng},
    start_timer, test_rng,
};

use crate::hyperplonk::full_snark::{
    custom_gate::CustomizedGates,
    structs::{HyperPlonkIndex, HyperPlonkParams},
};

pub struct MockCircuit<F: PrimeField> {
    pub public_inputs: Vec<F>,
    pub witnesses: Vec<MLE<F>>,
    pub index: HyperPlonkIndex<F>,
}

impl<F: PrimeField> MockCircuit<F> {
    /// Number of variables in a multilinear system
    pub fn num_variables(&self) -> usize {
        self.index.num_variables()
    }

    /// number of selector columns
    pub fn num_selector_columns(&self) -> usize {
        self.index.num_selector_columns()
    }

    /// number of witness columns
    pub fn num_witness_columns(&self) -> usize {
        self.index.num_witness_columns()
    }
}

impl<F: PrimeField + Clone> MockCircuit<F> {
    /// Generate a mock plonk circuit for the input constraint size.
    pub fn new(num_constraints: usize, gate: &CustomizedGates) -> MockCircuit<F> {
        let mut rng = test_rng();
        let nv = log2(num_constraints) as usize;
        let num_selectors = gate.num_selector_columns();
        let num_witnesses = gate.num_witness_columns();
        let log_n_wires = log2(num_witnesses) as usize;
        let merged_nv = nv + log_n_wires;

        let selectors: Vec<MLE<F>> = (0..num_selectors - 1)
            .map(|_| MLE::rand(nv, &mut rng))
            .collect();

        let witnesses: Vec<MLE<F>> = (0..num_witnesses)
            .map(|_| MLE::rand(nv, &mut rng))
            .collect();

        // for all test cases in this repo, there's one and only one selector for each monomial
        let mut last_selector = MLE::constant(F::zero(), nv);

        gate.gates.iter().enumerate().for_each(|(index, (coeff, q, wit))| {
            let mut cur_monomial = MLE::constant(if *coeff < 0 {
                -F::from((-coeff) as u64)
            } else {
                F::from(*coeff as u64)
            }, nv);

            for wit_index in wit.iter() {
                cur_monomial.mul_assign(witnesses[*wit_index]);
            }

            if index != num_selectors - 1 {
                match q {
                    Some(p) => cur_monomial.mul_assign(selectors[*p]),
                    _ => (),
                };
                last_selector.add_assign(cur_monomial);
            } else {
                cur_monomial.invert_in_place();
                last_selector.mul_assign((-F::one(), cur_monomial));
            }
        });

        let pub_input_len = ark_std::cmp::min(4, num_constraints);
        let mut public_inputs = witnesses[0].evals().iter().to_vec();
        public_inputs.truncate(pub_input_len);

        let params = HyperPlonkParams {
            num_constraints,
            num_pub_input: pub_input_len,
            gate_func: gate.clone(),
        };

        let permutation = MLE::identity_permutation_mles(merged_nv as usize, 1);
        let index = HyperPlonkIndex {
            params,
            permutation,
            selectors,
        };

        Self {
            public_inputs,
            witnesses,
            index,
        }
    }

    pub fn is_satisfied(&self) -> bool {
        for _current_row in 0..self.num_variables() {
            let mut cur = F::zero();
            // create selectors_val and witnesses_val vectors, with the same length as self.index.selectors and self.witnesses
            let mut selectors_val: Vec<F> = Vec::with_capacity(self.num_selector_columns());
            let mut witnesses_val: Vec<F> = Vec::with_capacity(self.num_witness_columns());
            for i in 0..self.num_selector_columns() {
                selectors_val.push(self.index.selectors[i].lock().unwrap().read_next().unwrap());
            }
            for i in 0..self.num_witness_columns() {
                witnesses_val.push(self.witnesses[i].lock().unwrap().read_next().unwrap());
            }
            for (coeff, q, wit) in self.index.params.gate_func.gates.iter() {
                let mut cur_monomial = if *coeff < 0 {
                    -F::from((-coeff) as u64)
                } else {
                    F::from(*coeff as u64)
                };
                cur_monomial = match q {
                    Some(p) => cur_monomial * selectors_val[*p],
                    None => cur_monomial,
                };
                for wit_index in wit.iter() {
                    cur_monomial *= witnesses_val[*wit_index];
                }
                cur += cur_monomial;
            }
            if !cur.is_zero() {
                return false;
            }
        }

        // restart all streams
        for i in 0..self.num_selector_columns() {
            self.index.selectors[i].lock().unwrap().read_restart();
        }
        for i in 0..self.num_witness_columns() {
            self.witnesses[i].lock().unwrap().read_restart();
        }

        true
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::hyperplonk::full_snark::utils::memory_traces;
    use crate::hyperplonk::full_snark::{errors::HyperPlonkErrors, HyperPlonkSNARK};
    use crate::hyperplonk::pcs::multilinear_kzg::srs::MultilinearUniversalParams;
    use crate::hyperplonk::pcs::multilinear_kzg::MultilinearKzgPCS;
    use crate::hyperplonk::pcs::PolynomialCommitmentScheme;
    use crate::hyperplonk::poly_iop::PolyIOP;
    use ark_bls12_381::Bls12_381;
    use ark_bls12_381::Fr;
    use ark_std::test_rng;

    const SUPPORTED_SIZE: usize = 20;
    const MIN_NUM_VARS: usize = 10;
    const MAX_NUM_VARS: usize = 21;
    const CUSTOM_DEGREE: [usize; 4] = [1, 2, 4, 8];

    #[test]
    fn test_mock_circuit_sat() {
        for i in 1..10 {
            let vanilla_gate = CustomizedGates::vanilla_plonk_gate();
            let circuit = MockCircuit::<Fr>::new(1 << i, &vanilla_gate);
            assert!(circuit.is_satisfied());

            let jf_gate = CustomizedGates::jellyfish_turbo_plonk_gate();
            let circuit = MockCircuit::<Fr>::new(1 << i, &jf_gate);
            assert!(circuit.is_satisfied());

            for num_witness in 2..10 {
                for degree in CUSTOM_DEGREE {
                    let mock_gate = CustomizedGates::mock_gate(num_witness, degree);
                    let circuit = MockCircuit::<Fr>::new(1 << i, &mock_gate);
                    assert!(circuit.is_satisfied());
                }
            }
        }
    }

    fn test_mock_circuit_zkp_helper(
        nv: usize,
        gate: &CustomizedGates,
        pcs_srs: &MultilinearUniversalParams<Bls12_381>,
    ) -> Result<(), HyperPlonkErrors> {
        let circuit = MockCircuit::<Fr>::new(1 << nv, gate);
        assert!(circuit.is_satisfied());

        let index = circuit.index;
        // generate pk and vks
        let (pk, vk) =
            <PolyIOP<Fr> as HyperPlonkSNARK<Bls12_381, MultilinearKzgPCS<Bls12_381>>>::preprocess(
                &index, pcs_srs,
            )?;
        // generate a proof and verify
        let proof =
            <PolyIOP<Fr> as HyperPlonkSNARK<Bls12_381, MultilinearKzgPCS<Bls12_381>>>::prove(
                &pk,
                &circuit.public_inputs,
                circuit.witnesses.clone(),
            )?;

        let verify =
            <PolyIOP<Fr> as HyperPlonkSNARK<Bls12_381, MultilinearKzgPCS<Bls12_381>>>::verify(
                &vk,
                &circuit.public_inputs,
                &proof,
            )?;
        assert!(verify);
        Ok(())
    }

    #[test]
    fn test_mock_circuit_zkp() -> Result<(), HyperPlonkErrors> {
        env_logger::init();
        memory_traces();

        let mut rng = test_rng();
        let pcs_srs =
            MultilinearKzgPCS::<Bls12_381>::gen_srs_for_testing(&mut rng, SUPPORTED_SIZE)?;
        for nv in MIN_NUM_VARS..MAX_NUM_VARS {
            let vanilla_gate = CustomizedGates::vanilla_plonk_gate();
            test_mock_circuit_zkp_helper(nv, &vanilla_gate, &pcs_srs)?;
        }
        // for nv in MIN_NUM_VARS..MAX_NUM_VARS {
        //     let tubro_gate = CustomizedGates::jellyfish_turbo_plonk_gate();
        //     test_mock_circuit_zkp_helper(nv, &tubro_gate, &pcs_srs)?;
        // }
        // let nv = ;
        // for num_witness in 2..5 {
        //     for degree in CUSTOM_DEGREE {
        //         let mock_gate = CustomizedGates::mock_gate(num_witness, degree);
        //         test_mock_circuit_zkp_helper(nv, &mock_gate, &pcs_srs)?;
        //     }
        // }

        Ok(())
    }

    #[test]
    fn test_mock_circuit_e2e() -> Result<(), HyperPlonkErrors> {
        let mut rng = test_rng();
        let pcs_srs =
            MultilinearKzgPCS::<Bls12_381>::gen_srs_for_testing(&mut rng, SUPPORTED_SIZE)?;
        let nv = MAX_NUM_VARS;

        let turboplonk_gate = CustomizedGates::jellyfish_turbo_plonk_gate();
        test_mock_circuit_zkp_helper(nv, &turboplonk_gate, &pcs_srs)?;

        Ok(())
    }

    #[test]
    fn test_mock_long_selector_e2e() -> Result<(), HyperPlonkErrors> {
        let mut rng = test_rng();
        let pcs_srs =
            MultilinearKzgPCS::<Bls12_381>::gen_srs_for_testing(&mut rng, SUPPORTED_SIZE)?;
        let nv = MAX_NUM_VARS;

        let long_selector_gate = CustomizedGates::super_long_selector_gate();
        test_mock_circuit_zkp_helper(nv, &long_selector_gate, &pcs_srs)?;

        Ok(())
    }
}
