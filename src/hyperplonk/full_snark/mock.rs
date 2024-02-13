// Copyright (c) 2023 Espresso Systems (espressosys.com)
// This file is part of the HyperPlonk library.

// You should have received a copy of the MIT License
// along with the HyperPlonk library. If not, see <https://mit-license.org/>.

use std::sync::{Arc, Mutex};

use crate::{
    hyperplonk::arithmetic::virtual_polynomial::identity_permutation,
    read_write::{identity_permutation_mles, identity_permutation_mle, DenseMLPolyStream, ReadWriteStream},
};
use ark_ff::Field;
use ark_ff::PrimeField;
use ark_std::{
    log2,
    rand::{rngs::StdRng, SeedableRng},
    test_rng,
};

use crate::hyperplonk::full_snark::{
    custom_gate::CustomizedGates,
    selectors::SelectorColumn,
    structs::{HyperPlonkIndex, HyperPlonkParams},
    witness::WitnessColumn,
};

pub struct MockCircuit<F: PrimeField> {
    pub public_inputs: Vec<F>,
    pub witnesses: Vec<Arc<Mutex<DenseMLPolyStream<F>>>>,
    // pub merged_witness: Arc<Mutex<DenseMLPolyStream<F>>>,
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

impl<F: PrimeField> MockCircuit<F> {
    /// Generate a mock plonk circuit for the input constraint size.
    pub fn new(num_constraints: usize, gate: &CustomizedGates) -> MockCircuit<F> {
        let seed = [
            1, 0, 0, 0, 23, 0, 0, 0, 200, 1, 0, 0, 210, 30, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0,
        ];
        let mut rng = StdRng::from_seed(seed);
        let nv = log2(num_constraints) as usize;
        let num_selectors = gate.num_selector_columns();
        let num_witnesses = gate.num_witness_columns();
        let log_n_wires = log2(num_witnesses);
        let merged_nv = nv + log_n_wires as usize;

        // create a Vec<Arc<Mutex<DenseMLPolyStream<F>>>> for selectors and witnesses
        let mut selectors: Vec<Arc<Mutex<DenseMLPolyStream<F>>>> = (0..num_selectors)
            .map(|_| Arc::new(Mutex::new(DenseMLPolyStream::new(nv, None, None))))
            .collect();

        let mut witnesses: Vec<Arc<Mutex<DenseMLPolyStream<F>>>> = (0..num_witnesses)
            .map(|_| Arc::new(Mutex::new(DenseMLPolyStream::new(nv, None, None))))
            .collect();

        for _cs_counter in 0..num_constraints {
            // println!("mock new constraint index: {}", _cs_counter);
            let mut cur_selectors: Vec<F> = (0..(num_selectors - 1))
                .map(|_| F::rand(&mut rng))
                .collect();
            let cur_witness: Vec<F> = (0..num_witnesses).map(|_| F::rand(&mut rng)).collect();
            let mut last_selector = F::zero();
            for (index, (coeff, q, wit)) in gate.gates.iter().enumerate() {
                // println!("mock new coeff: {}, q index: {:?}, wit index: {:?}", coeff, q, wit);
                if index != num_selectors - 1 {
                    let mut cur_monomial = if *coeff < 0 {
                        -F::from((-coeff) as u64)
                    } else {
                        F::from(*coeff as u64)
                    };
                    cur_monomial = match q {
                        Some(p) => cur_monomial * cur_selectors[*p],
                        None => cur_monomial,
                    };
                    for wit_index in wit.iter() {
                        cur_monomial *= cur_witness[*wit_index];
                    }
                    last_selector += cur_monomial;
                } else {
                    let mut cur_monomial = if *coeff < 0 {
                        -F::from((-coeff) as u64)
                    } else {
                        F::from(*coeff as u64)
                    };
                    for wit_index in wit.iter() {
                        cur_monomial *= cur_witness[*wit_index];
                    }
                    last_selector /= -cur_monomial;
                }
            }
            cur_selectors.push(last_selector);

            // // print all selectors and witnesses
            // (0..num_selectors).for_each( |i| {
            //     println!("selector [{}]: {}", i, cur_selectors[i]);
            // });
            // (0..num_witnesses).for_each(|i| {
            //     println!("witness [{}]: {}", i, cur_witness[i]);
            // });

            for i in 0..num_selectors {
                selectors[i]
                    .lock()
                    .unwrap()
                    .write_next_unchecked(cur_selectors[i]);
            }
            for i in 0..num_witnesses {
                witnesses[i]
                    .lock()
                    .unwrap()
                    .write_next_unchecked(cur_witness[i]);
            }
        }
        // swap read and write for each stream
        for i in 0..num_selectors {
            selectors[i].lock().unwrap().swap_read_write();
        }
        for i in 0..num_witnesses {
            witnesses[i].lock().unwrap().swap_read_write();
        }

        let pub_input_len = ark_std::cmp::min(4, num_constraints);

        // read the stream up to pub_input_len and restart it
        let mut pub_stream = witnesses[0].lock().unwrap();
        let public_inputs: Vec<F> = (0..pub_input_len)
            .map(|i| pub_stream.read_next_unchecked().unwrap())
            .collect();
        pub_stream.read_restart();
        drop(pub_stream);
        // let public_inputs = witnesses[0].0[0..pub_input_len].to_vec();

        let params = HyperPlonkParams {
            num_constraints,
            num_pub_input: public_inputs.len(),
            gate_func: gate.clone(),
        };

        let permutation = identity_permutation_mles(nv as usize, num_witnesses);
        let permutation_index = identity_permutation_mles(nv as usize, num_witnesses);
        let index = HyperPlonkIndex {
            params,
            permutation,
            permutation_index,
            selectors,
        };

        Self {
            public_inputs,
            witnesses: witnesses.clone(),
            index,
        }
    }

    pub fn is_satisfied(&self) -> bool {
        for current_row in 0..self.num_variables() {
            // println!("Checking constraint at row {}", current_row);
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
                // println!("coeff_val: {}, q_index: {}, wit_index: {:?}", coeff, q.unwrap(), wit);
                let mut cur_monomial = if *coeff < 0 {
                    -F::from((-coeff) as u64)
                } else {
                    F::from(*coeff as u64)
                };
                cur_monomial = match q {
                    Some(p) => {
                        // let selector_val = self.index.selectors[*p].lock().unwrap().read_next().unwrap();
                        // println!("selector_val: {}", selector_val);
                        cur_monomial * selectors_val[*p]
                    }
                    None => cur_monomial,
                };
                for wit_index in wit.iter() {
                    // let witness_val = self.witnesses[*wit_index].lock().unwrap().read_next().unwrap();
                    // println!("witness_val: {}", witness_val);
                    cur_monomial *= witnesses_val[*wit_index];
                }
                cur += cur_monomial;
            }
            if !cur.is_zero() {
                // println!("Constraint not satisfied at row {}, value is {}", current_row, cur);
                return false;
            }
            // println!("Constraint satisfied at row {}", current_row);
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
    // use ark_test_curves::{Bls12_381, Fr};
    use crate::hyperplonk::{
        // pcs::{
        //     prelude::{MultilinearKzgPCS, MultilinearUniversalParams},
        //     PolynomialCommitmentScheme,
        // },
        poly_iop::PolyIOP,
    };
    use ark_test_curves::bls12_381::Fr;
    use std::str::FromStr;

    const SUPPORTED_SIZE: usize = 20;
    const MIN_NUM_VARS: usize = 10;
    const MAX_NUM_VARS: usize = 21;
    const CUSTOM_DEGREE: [usize; 6] = [1, 2, 4, 8, 16, 32];

    #[test]
    fn circuit_sat_field() {
        let selector_0 = Fr::from_str(
            "46726240763639862128214388288720131204625575015731614850157206947646262134152",
        )
        .unwrap();
        let selector_1 = Fr::from_str(
            "43289727388036023252294560744145593863815462211184144675663927741862919848062",
        )
        .unwrap();
        let selector_2 = Fr::from_str(
            "39501668311652398015059542738513304275791575876079526402636504204504656633375",
        )
        .unwrap();
        let selector_3 = Fr::from_str(
            "34763583743636203473074462483868705922641433856784185249917108425163964991725",
        )
        .unwrap();
        let selector_4 = Fr::from_str(
            "38814851719591852580002997851819245360505047896716344419102416560422514746482",
        )
        .unwrap();
        let witness_0 = Fr::from_str(
            "26743119887860762667945227136888888599495004134692860427559527073545191989603",
        )
        .unwrap();
        let witness_1 = Fr::from_str(
            "2775224388108984800443087948010676219211324659355359054938565343431233528246",
        )
        .unwrap();
        let witness_2 = Fr::from_str(
            "404212352771553385428541523100674996752089838536533648869527977520925505862",
        )
        .unwrap();

        assert!(
            selector_0 * witness_0
                + selector_1 * witness_1
                + selector_2 * witness_2
                + selector_3 * witness_0 * witness_1
                + selector_4
                == Fr::from_str("0").unwrap()
        );
    }

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
        // pcs_srs: &MultilinearUniversalParams<Bls12_381>,
    ) -> Result<(), HyperPlonkErrors> {
        let circuit = MockCircuit::<Fr>::new(1 << nv, gate);
        assert!(circuit.is_satisfied());

        let index = circuit.index;
        // generate pk and vks
        let (pk, vk) = <PolyIOP<Fr> as HyperPlonkSNARK<Fr>>::preprocess(&index)?;
        // generate a proof and verify
        let proof = <PolyIOP<Fr> as HyperPlonkSNARK<Fr>>::prove(
            &pk,
            &circuit.public_inputs,
            circuit.witnesses.clone(),
        )?;

        // let verify =
        //     <PolyIOP<Fr> as HyperPlonkSNARK<Fr>>::verify(&vk, &circuit.public_inputs, &proof)?;
        // assert!(verify);
        Ok(())
    }

    #[test]
    fn test_mock_circuit_zkp() -> Result<(), HyperPlonkErrors> {
        env_logger::init();
        memory_traces();

        let mut rng = test_rng();
        // let pcs_srs =
        //     MultilinearKzgPCS::<Bls12_381>::gen_srs_for_testing(&mut rng, SUPPORTED_SIZE)?;
        for nv in MIN_NUM_VARS..MAX_NUM_VARS {
            let vanilla_gate = CustomizedGates::vanilla_plonk_gate();
            test_mock_circuit_zkp_helper(nv, &vanilla_gate)?;
        }
        // for nv in MIN_NUM_VARS..MAX_NUM_VARS {
        //     let tubro_gate = CustomizedGates::jellyfish_turbo_plonk_gate();
        //     test_mock_circuit_zkp_helper(nv, &tubro_gate)?;
        // }
        // let nv = 5;
        // for num_witness in 2..10 {
        //     for degree in CUSTOM_DEGREE {
        //         let mock_gate = CustomizedGates::mock_gate(num_witness, degree);
        //         test_mock_circuit_zkp_helper(nv, &mock_gate)?;
        //     }
        // }

        Ok(())
    }

    #[test]
    fn test_mock_circuit_e2e() -> Result<(), HyperPlonkErrors> {
        let mut rng = test_rng();
        // let pcs_srs =
        //     MultilinearKzgPCS::<Bls12_381>::gen_srs_for_testing(&mut rng, SUPPORTED_SIZE)?;
        let nv = MAX_NUM_VARS;

        let turboplonk_gate = CustomizedGates::jellyfish_turbo_plonk_gate();
        test_mock_circuit_zkp_helper(nv, &turboplonk_gate)?;

        Ok(())
    }

    #[test]
    fn test_mock_long_selector_e2e() -> Result<(), HyperPlonkErrors> {
        let mut rng = test_rng();
        // let pcs_srs =
        //     MultilinearKzgPCS::<Bls12_381>::gen_srs_for_testing(&mut rng, SUPPORTED_SIZE)?;
        let nv = MAX_NUM_VARS;

        let long_selector_gate = CustomizedGates::super_long_selector_gate();
        test_mock_circuit_zkp_helper(nv, &long_selector_gate)?;

        Ok(())
    }
}
