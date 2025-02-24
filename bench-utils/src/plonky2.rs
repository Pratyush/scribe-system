use plonky2::field::types::Field;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};

type C = PoseidonGoldilocksConfig;
const D: usize = 2;
type F = <C as GenericConfig<D>>::F;

fn build_circuit(size: usize) -> (CircuitBuilder<F, D>, PartialWitness<F>) {
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    // The arithmetic circuit.
    let initial_a = builder.add_virtual_target();
    let initial_b = builder.add_virtual_target();
    let mut prev_target = initial_a;
    let mut cur_target = initial_b;
    for _ in 0..size {
        let temp = builder.mul(prev_target, cur_target);
        prev_target = cur_target;
        cur_target = temp;
    }

    // Public inputs are the two initial values (provided below) and the result (which is generated).
    builder.register_public_input(initial_a);
    builder.register_public_input(initial_b);
    builder.register_public_input(cur_target);
    //
    // Provide initial values.
    let mut pw = PartialWitness::new();
    pw.set_target(initial_a, F::TWO).unwrap();
    pw.set_target(initial_b, F::ONE).unwrap();

    (builder, pw)
}

/// An example of using Plonky2 to prove a statement of the form
/// "I know the 100th element of the Fibonacci sequence, starting with constants a and b."
/// When a == 0 and b == 1, this is proving knowledge of the 100th (standard) Fibonacci number.
pub fn prover(min_size: usize, max_size: usize) {
    for size in min_size..=max_size {
        let (builder, pw) = timed!(
            format!("Plonky2: Generating circuit for {size}",),
            build_circuit(1 << size)
        );

        let _num_gates = builder.num_gates();
        let (data, proof) = timed!(format!("Plonky2: Proving for {size}"), {
            let data = builder.build::<C>();
            let proof = data.prove(pw).unwrap();
            (data, proof)
        });
        data.verify(proof).unwrap();
    }
}
