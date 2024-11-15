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

    let mut rng = ark_std::rand::thread_rng();
    let mut working_vars: Vec<Variable> = (0..working_set_size)
        .map(|_| circuit.create_variable(F::rand(&mut rng)))
        .collect::<Result<Vec<_>, _>>()?;

    for _ in 0..n {
        // Randomly select two distinct working variables
        let a_idx = rng.gen_range(0..working_set_size);
        let b_idx = (a_idx + 1 + rng.gen_range(0..(working_set_size - 1))) % working_set_size;
        let a = working_vars[a_idx];
        let b = working_vars[b_idx];

        // Randomly choose to add or multiply
        let new_var = if rng.gen_bool(0.5) {
            circuit.add(a, b)?
        } else {
            circuit.mul(a, b)?
        };

        // Optionally replace one of the working variables with a new one
        if rng.gen_bool(new_var_prob) {
            let replacement_idx = rng.gen_range(0..working_set_size);
            working_vars[replacement_idx] = circuit.create_variable(F::rand(&mut rng))?;
        } else {
            // Otherwise replace the result in the working set
            working_vars[a_idx] = new_var;
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
    add_random_gates(&mut circuit, num_constraints, working_set_size, new_var_prob).unwrap();
}
