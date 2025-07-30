use std::ops::{AddAssign, MulAssign};

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{
    end_timer, log2,
    rand::{SeedableRng, rngs::StdRng},
    start_timer,
};
use mle::MLE;
use scribe_streams::{iterator::BatchedIterator, serialize::RawPrimeField};

use crate::snark::{
    custom_gate::CustomizedGates,
    structs::{Index, ScribeConfig},
};

#[derive(CanonicalDeserialize, CanonicalSerialize)]
pub struct MockCircuit<F: RawPrimeField> {
    pub public_inputs: Vec<F>,
    pub witnesses: Vec<MLE<F>>,
    pub index: Index<F>,
}

impl<F: RawPrimeField> MockCircuit<F> {
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

impl<F: RawPrimeField> MockCircuit<F> {
    pub fn new_index(num_constraints: usize, gate: &CustomizedGates) -> Index<F> {
        let mut rng = StdRng::seed_from_u64(0u64);
        let nv = log2(num_constraints) as usize;
        let num_selectors = gate.num_selector_columns();
        let num_witnesses = gate.num_witness_columns();

        let witness_time = start_timer!(|| "witnesses");
        let witnesses: Vec<MLE<F>> = (0..num_witnesses)
            .map(|_| MLE::rand(nv, &mut rng))
            .collect();
        end_timer!(witness_time);

        let selector_time = start_timer!(|| "selectors");
        let mut selectors: Vec<MLE<F>> = (0..num_selectors - 1)
            .map(|_| MLE::rand(nv, &mut rng))
            .collect();
        end_timer!(selector_time);

        // for all test cases in this repo, there's one and only one selector for each monomial
        let last_selector_time = start_timer!(|| "last selector");
        let mut last_selector = MLE::constant(F::zero(), nv);

        gate.gates
            .iter()
            .enumerate()
            .for_each(|(index, (coeff, q, wit))| {
                let mut cur_monomial = MLE::constant(coeff.into_fp(), nv);

                for wit_index in wit.iter() {
                    cur_monomial *= &witnesses[*wit_index];
                }

                if index != num_selectors - 1 {
                    if let Some(p) = q {
                        cur_monomial *= &selectors[*p];
                    }
                    last_selector += cur_monomial;
                } else {
                    cur_monomial.invert_in_place();
                    last_selector *= (-F::one(), cur_monomial);
                }
            });

        selectors.push(last_selector);

        end_timer!(last_selector_time);
        let num_pub_input = ark_std::cmp::min(4, num_constraints);

        let config = ScribeConfig {
            num_constraints,
            num_pub_input,
            gate_func: gate.clone(),
        };

        let identity_time = start_timer!(|| "identity permutation");
        let permutation = MLE::identity_permutation_mles(nv as usize, num_witnesses);
        end_timer!(identity_time);
        Index {
            config,
            permutation,
            selectors,
        }
    }

    pub fn wire_values_for_index(index: &Index<F>) -> (Vec<F>, Vec<MLE<F>>) {
        let mut rng = StdRng::seed_from_u64(0u64);
        let witness_time = start_timer!(|| "witnesses");
        let num_witnesses = index.config.gate_func.num_witness_columns();
        let num_constraints = index.config.num_constraints;
        let nv = log2(num_constraints) as usize;
        let witnesses: Vec<_> = (0..num_witnesses)
            .map(|_| MLE::rand(nv, &mut rng))
            .collect();
        end_timer!(witness_time);
        let num_pub_inputs = ark_std::cmp::min(4, num_constraints);
        let public_inputs = witnesses[0].evals().iter().take(num_pub_inputs).to_vec();
        (public_inputs, witnesses)
    }

    pub fn new(num_constraints: usize, gate: &CustomizedGates) -> Self {
        let index = Self::new_index(num_constraints, gate);
        let (public_inputs, witnesses) = Self::wire_values_for_index(&index);
        Self {
            public_inputs,
            witnesses,
            index,
        }
    }

    pub fn is_satisfied(&self) -> bool {
        let nv = self.num_variables();
        let mut cur = MLE::constant(F::zero(), nv);
        for (coeff, q, wit) in self.index.config.gate_func.gates.iter() {
            let mut cur_monomial = MLE::constant(coeff.into_fp(), nv);
            if let Some(p) = q {
                cur_monomial.mul_assign(&self.index.selectors[*p])
            }
            for wit_index in wit.iter() {
                cur_monomial.mul_assign(&self.witnesses[*wit_index]);
            }
            cur.add_assign(cur_monomial);
        }
        // must borrow as mutable
        cur.evals_mut().for_each(|x| assert!(x.is_zero()));

        true
    }
}

#[cfg(test)]
mod test {
    use std::io::{Seek, Write};

    use super::*;
    use crate::pc::PCScheme;
    use crate::pc::pst13::PST13;
    use crate::pc::pst13::srs::SRS;
    use crate::snark::{Scribe, errors::ScribeErrors};
    use ark_bls12_381::Bls12_381;
    use ark_bls12_381::Fr;
    use ark_std::test_rng;
    use tempfile::tempfile;

    const SUPPORTED_SIZE: usize = 19;
    const MIN_NUM_VARS: usize = 10;
    const MAX_NUM_VARS: usize = SUPPORTED_SIZE;
    const CUSTOM_DEGREE: [usize; 4] = [1, 2, 4, 8];

    #[test]
    fn test_mock_circuit_sat() {
        for i in 10..22 {
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
        pcs_srs: &SRS<Bls12_381>,
    ) -> Result<(), ScribeErrors> {
        let circuit = MockCircuit::<Fr>::new(1 << nv, gate);
        assert!(circuit.is_satisfied());

        let index = circuit.index;
        // generate pk and vks
        let (pk, vk) = <Scribe<Bls12_381, PST13<Bls12_381>>>::preprocess(&index, pcs_srs)?;
        // generate a proof and verify
        let proof = <Scribe<Bls12_381, PST13<Bls12_381>>>::prove(
            &pk,
            &circuit.public_inputs,
            &circuit.witnesses,
        )?;

        let verify =
            <Scribe<Bls12_381, PST13<Bls12_381>>>::verify(&vk, &circuit.public_inputs, &proof)?;
        assert!(verify);
        Ok(())
    }

    #[test]
    fn test_mock_circuit_zkp() -> Result<(), ScribeErrors> {
        let mut rng = test_rng();
        let pcs_srs = PST13::<Bls12_381>::gen_srs_for_testing(&mut rng, SUPPORTED_SIZE)?;
        for nv in MIN_NUM_VARS..MAX_NUM_VARS {
            println!("\n\n\n test_mock_circuit_zkp for nv = {nv} \n\n\n");
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
    fn test_mock_circuit_e2e() -> Result<(), ScribeErrors> {
        let mut rng = test_rng();
        let pcs_srs = PST13::<Bls12_381>::gen_srs_for_testing(&mut rng, SUPPORTED_SIZE)?;
        let nv = MAX_NUM_VARS;

        let turboplonk_gate = CustomizedGates::jellyfish_turbo_plonk_gate();
        test_mock_circuit_zkp_helper(nv, &turboplonk_gate, &pcs_srs)?;

        Ok(())
    }

    #[test]
    fn test_mock_long_selector_e2e() -> Result<(), ScribeErrors> {
        let mut rng = test_rng();
        let pcs_srs = PST13::<Bls12_381>::gen_srs_for_testing(&mut rng, SUPPORTED_SIZE)?;
        let nv = MAX_NUM_VARS;

        let long_selector_gate = CustomizedGates::super_long_selector_gate();
        test_mock_circuit_zkp_helper(nv, &long_selector_gate, &pcs_srs)?;

        Ok(())
    }

    #[test]
    fn test_mock_circuit_serialization() -> Result<(), ScribeErrors> {
        let vanilla_gate = CustomizedGates::vanilla_plonk_gate();
        let circuit = MockCircuit::<Fr>::new(1 << 6, &vanilla_gate);
        let mut buf = tempfile().unwrap();
        circuit.serialize_uncompressed(&mut buf).unwrap();
        buf.flush().unwrap();
        buf.seek(std::io::SeekFrom::Start(0)).unwrap();
        let circuit_2 = MockCircuit::<Fr>::deserialize_uncompressed_unchecked(&buf).unwrap();

        assert_eq!(circuit.public_inputs, circuit_2.public_inputs);
        assert_eq!(circuit.witnesses.len(), circuit_2.witnesses.len());
        for (a, b) in circuit.witnesses.iter().zip(&circuit_2.witnesses) {
            let a = a.evals().iter().to_vec();
            let b = b.evals().iter().to_vec();
            assert_eq!(a.len(), b.len());
            a.iter().zip(b.iter()).for_each(|(a, b)| assert_eq!(a, b));
        }
        let index_1 = circuit.index;
        let index_2 = circuit_2.index;
        for (a, b) in index_1.selectors.iter().zip(&index_2.selectors) {
            let a = a.evals().iter().to_vec();
            let b = b.evals().iter().to_vec();
            assert_eq!(a.len(), b.len());
            a.iter().zip(b.iter()).for_each(|(a, b)| assert_eq!(a, b));
        }

        for (a, b) in index_1.permutation.iter().zip(&index_2.permutation) {
            let a = a.evals().iter().to_vec();
            let b = b.evals().iter().to_vec();
            assert_eq!(a.len(), b.len());
            a.iter().zip(b.iter()).for_each(|(a, b)| assert_eq!(a, b));
        }

        Ok(())
    }

    #[test]
    fn index_witness_gen_consistency() {
        let vanilla_gate = CustomizedGates::vanilla_plonk_gate();
        for i in 10..22 {
            let circuit = MockCircuit::<Fr>::new(1 << i, &vanilla_gate);
            let (public_inputs, witnesses) =
                MockCircuit::<Fr>::wire_values_for_index(&circuit.index);
            let circuit2 = MockCircuit::<Fr> {
                public_inputs,
                witnesses,
                index: circuit.index.clone(),
            };
            for (a, b) in circuit.witnesses.iter().zip(&circuit2.witnesses) {
                let a = a.evals().iter().to_vec();
                let b = b.evals().iter().to_vec();
                assert_eq!(a.len(), b.len());
                a.iter().zip(b.iter()).for_each(|(a, b)| assert_eq!(a, b));
            }
            assert!(circuit2.is_satisfied());
        }
    }
}
