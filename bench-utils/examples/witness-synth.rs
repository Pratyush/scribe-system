use ark_std::rand::Rng;
use ark_bls12_381::Fr;
use ark_ff::PrimeField;
use jf_relation::{Circuit, CircuitError, PlonkCircuit, Variable};

pub fn add_random_gates<F: PrimeField, C: Circuit<F>>(
    circuit: &mut C,
    n: usize,
    working_set_size: usize,
    new_var_prob: f64,
) -> Result<(), CircuitError> {
    assert!(new_var_prob > 0.0 && new_var_prob <= 1.0);

    let mut rng = ark_std::test_rng();
    let (mut working_vars, mut values): (Vec<_>, Vec<_>) = (0..working_set_size)
        .map(|_| {
            let value = F::rand(&mut rng);
            let var = circuit.create_variable(value).unwrap();
            (var, value)
        })
        .unzip();

    for _ in 0..n {
        // Randomly select two distinct working variables
        let a_idx = rng.gen_range(0..working_set_size);
        let b_idx = rng.gen_range(0..working_set_size);
        let a = working_vars[a_idx];
        let b = working_vars[b_idx];
        let a_val = values[a_idx];
        let b_val = values[b_idx];

        // Randomly choose to add or multiply
        let (result, result_val) = if rng.gen_bool(0.5) {
            let result_val = a_val + b_val;
            let result = circuit.create_variable(result_val)?;
            circuit.add_gate(a, b, result)?;
            (result, result_val)
        } else {
            let result_val = a_val * b_val;
            let result = circuit.create_variable(result_val)?;
            circuit.mul_gate(a, b, result)?;
            (result, result_val)
        };

        // Optionally replace one of the working variables with a new one
        if rng.gen_bool(new_var_prob) {
            let replacement_idx = rng.gen_range(0..working_set_size);
            working_vars[replacement_idx] = result;
            values[replacement_idx] = result_val;
        }
    }

    Ok(())
}

fn main() {
    let args = std::env::args().skip(1).collect::<Vec<String>>();
    let num_constraints: usize = args[0].parse().unwrap();
    let working_set_size: usize = args[1].parse().unwrap();
    let new_var_prob: f64 = args[2].parse().unwrap();
    let mut circuit = PlonkCircuit::<Fr>::new_in_prove_mode(false);
    add_random_gates(&mut circuit, 1 << num_constraints, 1 << working_set_size, new_var_prob).unwrap();
}
