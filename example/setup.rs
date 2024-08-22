use std::{f32::MIN, fs::OpenOptions};
use std::{fs::File, io, time::Instant};

use ark_bls12_381::Bls12_381;
use ark_bls12_381::Fr;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Write};
use ark_std::test_rng;
use scribe::hyperplonk::full_snark::custom_gate::CustomizedGates;
use scribe::hyperplonk::full_snark::structs::{HyperPlonkProvingKey, HyperPlonkVerifyingKey};
use scribe::hyperplonk::full_snark::{
    errors::HyperPlonkErrors, mock::MockCircuit, HyperPlonkSNARK,
};
use scribe::hyperplonk::pcs::multilinear_kzg::srs;
use scribe::hyperplonk::{
    pcs::{
        multilinear_kzg::{srs::MultilinearUniversalParams, MultilinearKzgPCS},
        PolynomialCommitmentScheme,
    },
    poly_iop::PolyIOP,
};
use scribe::streams::iterator::BatchedIterator;
use scribe::streams::LOG_BUFFER_SIZE;

const SUPPORTED_SIZE: usize = 6;
const MIN_NUM_VARS: usize = 4;
const MAX_NUM_VARS: usize = 6;

fn main() {
    // generate and serialize srs
    let mut rng = test_rng();
    let pc_srs =
        MultilinearKzgPCS::<Bls12_381>::gen_fake_srs_for_testing(&mut rng, SUPPORTED_SIZE).unwrap();

    let srs_filename = format!("srs_{}.params", SUPPORTED_SIZE);
    let mut srs_file = OpenOptions::new()
        .write(true)
        .create(true)
        .open(&srs_filename)
        .unwrap();
    pc_srs.serialize_uncompressed(&mut srs_file).unwrap();

    // println!("srs powers of g: {}", pcs_srs.prover_param.powers_g.len());

    // generate and serialize circuit, pk, vk
    let circuit_filename = format!("circuit_{}_to_{}.params", MIN_NUM_VARS, MAX_NUM_VARS);
    let pk_filename = format!("pk_{}_to_{}.params", MIN_NUM_VARS, MAX_NUM_VARS);
    let vk_filename = format!("vk_{}_to_{}.params", MIN_NUM_VARS, MAX_NUM_VARS);
    if MAX_NUM_VARS > SUPPORTED_SIZE {
        panic!("MAX_NUM_VARS must be less than or equal to SUPPORTED_SIZE");
    }
    let circuit_file = OpenOptions::new()
        .write(true)
        .create(true)
        .open(&circuit_filename)
        .unwrap();
    let pk_file = OpenOptions::new()
        .write(true)
        .create(true)
        .open(&pk_filename)
        .unwrap();
    let vk_file = OpenOptions::new()
        .write(true)
        .create(true)
        .open(&vk_filename)
        .unwrap();

    let vanilla_gate = CustomizedGates::vanilla_plonk_gate();
    for nv in MIN_NUM_VARS..=MAX_NUM_VARS {
        println!("nv = {}", nv);
        let circuit = MockCircuit::<Fr>::new(1 << nv, &vanilla_gate);

        circuit.serialize_uncompressed(&circuit_file).unwrap();
        let index = circuit.index;
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(8)
            .build()
            .unwrap();

        let (pk, vk) = pool
            .install(|| <PolyIOP<Fr>>::preprocess(&index, &pc_srs))
            .unwrap();

        HyperPlonkProvingKey::<_, MultilinearKzgPCS<_>>::serialize_uncompressed(&pk, &pk_file)
            .unwrap();
        HyperPlonkVerifyingKey::<_, MultilinearKzgPCS<_>>::serialize_uncompressed(&vk, &vk_file)
            .unwrap();
    }

    println!("Serializing Circuit");
    let mut circuit_file = OpenOptions::new()
        .read(true)
        .open(&circuit_filename)
        .unwrap();
    println!("Serializing PK");
    let mut pk_file = OpenOptions::new().read(true).open(&pk_filename).unwrap();
    println!("Serializing VK");
    let vk_file = OpenOptions::new().read(true).open(&vk_filename).unwrap();

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
    let pk_2 = HyperPlonkProvingKey::<_, MultilinearKzgPCS<Bls12_381>>::deserialize_uncompressed_unchecked(&mut pk_file).unwrap();
    println!("{:?}", pk_2.params);
    assert_eq!(pk_2.params, circuit_2.index.params);
    pk_2.permutation_oracles
        .iter()
        .for_each(|perm| println!("permutation: {perm}"));
    pk_2.selector_oracles
        .iter()
        .for_each(|selector| println!("selector: {selector}"));
}
