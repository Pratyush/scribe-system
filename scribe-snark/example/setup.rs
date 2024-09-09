use std::fs::OpenOptions;

use ark_bls12_381::Bls12_381;
use ark_bls12_381::Fr;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::test_rng;
use scribe::pc::{multilinear_kzg::PST13, PolynomialCommitmentScheme};
use scribe::snark::custom_gate::CustomizedGates;
use scribe::snark::structs::{ProvingKey, VerifyingKey};
use scribe::snark::{mock::MockCircuit, Scribe};

fn main() {
    let [min_num_vars, max_num_vars] = std::env::args()
        .skip(1)
        .map(|arg| arg.parse().unwrap())
        .take(2)
        .collect::<Vec<usize>>()[..]
    else {
        panic!("Please provide min_num_vars and max_num_vars as arguments")
    };

    // generate and serialize srs
    let mut rng = test_rng();
    let pc_srs = PST13::<Bls12_381>::gen_fake_srs_for_testing(&mut rng, max_num_vars).unwrap();

    let srs_filename = format!("srs_{}.params", max_num_vars);
    let mut srs_file = OpenOptions::new()
        .write(true)
        .create(true)
        .open(&srs_filename)
        .unwrap();
    pc_srs.serialize_uncompressed(&mut srs_file).unwrap();

    // println!("srs powers of g: {}", pcs_srs.prover_param.powers_g.len());

    // generate and serialize circuit, pk, vk
    let circuit_filename = format!("circuit_{}_to_{}.params", min_num_vars, max_num_vars);
    let pk_filename = format!("pk_{}_to_{}.params", min_num_vars, max_num_vars);
    let vk_filename = format!("vk_{}_to_{}.params", min_num_vars, max_num_vars);
    let circuit_file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&circuit_filename)
        .unwrap();
    let pk_file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&pk_filename)
        .unwrap();
    let vk_file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&vk_filename)
        .unwrap();

    let vanilla_gate = CustomizedGates::vanilla_plonk_gate();
    for nv in min_num_vars..=max_num_vars {
        println!("nv = {}", nv);
        let circuit = MockCircuit::<Fr>::new(1 << nv, &vanilla_gate);

        circuit.serialize_uncompressed(&circuit_file).unwrap();
        let index = circuit.index;
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(8)
            .build()
            .unwrap();

        let (pk, vk) = pool
            .install(|| Scribe::preprocess(&index, &pc_srs))
            .unwrap();

        ProvingKey::<_, PST13<_>>::serialize_uncompressed(&pk, &pk_file).unwrap();
        VerifyingKey::<_, PST13<_>>::serialize_uncompressed(&vk, &vk_file).unwrap();
    }

    println!("Serializing Circuit");
    let mut circuit_file = OpenOptions::new()
        .read(true)
        .open(&circuit_filename)
        .unwrap();
    println!("Serializing PK");
    let mut pk_file = OpenOptions::new().read(true).open(&pk_filename).unwrap();
    println!("Serializing VK");
    let _vk_file = OpenOptions::new().read(true).open(&vk_filename).unwrap();

    let circuit_2 =
        MockCircuit::<Fr>::deserialize_uncompressed_unchecked(&mut circuit_file).unwrap();

    println!("circuit");
    println!("pub inputs: {:?}", circuit_2.public_inputs);
    circuit_2
        .witnesses
        .iter()
        .for_each(|witness| println!("witness: {witness}"));
    println!("params: {:?}", circuit_2.index.params);
    circuit_2
        .index
        .permutation
        .iter()
        .for_each(|perm| println!("permutation: {perm}"));
    circuit_2
        .index
        .selectors
        .iter()
        .for_each(|selector| println!("selector: {selector}"));

    println!("pk 2");
    let pk_2 = ProvingKey::<_, PST13<Bls12_381>>::deserialize_uncompressed_unchecked(&mut pk_file)
        .unwrap();
    println!("{:?}", pk_2.params);
    assert_eq!(pk_2.params, circuit_2.index.params);
    pk_2.permutation_oracles
        .iter()
        .for_each(|perm| println!("permutation: {perm}"));
    pk_2.selector_oracles
        .iter()
        .for_each(|selector| println!("selector: {selector}"));
}
