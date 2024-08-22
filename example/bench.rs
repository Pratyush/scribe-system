use std::{fs::File, time::Instant};

use ark_bls12_381::Bls12_381;
use ark_bls12_381::Fr;
use ark_serialize::{CanonicalDeserialize, Write};
use scribe::hyperplonk::full_snark::structs::{HyperPlonkProvingKey, HyperPlonkVerifyingKey};
use scribe::hyperplonk::full_snark::{
    errors::HyperPlonkErrors, mock::MockCircuit, HyperPlonkSNARK,
};
use scribe::hyperplonk::{
    pcs::{multilinear_kzg::MultilinearKzgPCS, PolynomialCommitmentScheme},
    poly_iop::PolyIOP,
};
use scribe::streams::iterator::BatchedIterator;
use scribe::streams::LOG_BUFFER_SIZE;

const SUPPORTED_SIZE: usize = 6;
const MIN_NUM_VARS: usize = 4;
const MAX_NUM_VARS: usize = 6;
const MIN_CUSTOM_DEGREE: usize = 1;
const MAX_CUSTOM_DEGREE: usize = 32;
const HIGH_DEGREE_TEST_NV: usize = 15;

pub fn main() {
    let thread = rayon::current_num_threads();
    // run benchmark
    bench_vanilla_plonk(thread).unwrap();
    println!();
}

fn bench_vanilla_plonk(thread: usize) -> Result<(), HyperPlonkErrors> {
    let filename = format!(
        "vanilla threads {} log buffer {}.txt",
        thread, LOG_BUFFER_SIZE
    );
    let log_file = File::create(filename).unwrap();
    let param_file = File::open(format!(
        "circuit_pk_vk_{}_to_{}.params",
        MIN_NUM_VARS, MAX_NUM_VARS
    ))
    .unwrap();

    let circuit = MockCircuit::<Fr>::deserialize_uncompressed_unchecked(&param_file).unwrap();
    let pk = HyperPlonkProvingKey::<Bls12_381, MultilinearKzgPCS<Bls12_381>>::deserialize_uncompressed_unchecked(&param_file).unwrap();
    println!("print pk");
    println!("{:?}", pk.params);
    println!(
        "perm oracles: {:?}",
        pk.permutation_oracles
            .iter()
            .for_each(|perm| println!("perm {:?}", perm.evals().iter().to_vec()))
    );
    println!("selector oracles: {:?}", pk.selector_oracles);

    // for nv in MIN_NUM_VARS..=MAX_NUM_VARS {
    //     let circuit = MockCircuit::<Fr>::deserialize_uncompressed_unchecked(&mut param_file).unwrap();
    //     assert_eq!(circuit.index.num_variables(), nv);
    //     assert!(circuit.is_satisfied());
    //     let pk = HyperPlonkProvingKey::<Bls12_381, MultilinearKzgPCS<Bls12_381>>::deserialize_uncompressed_unchecked(&mut param_file).unwrap();
    //     println!("print pk");
    //     println!("{:?}", pk.params);
    //     println!("perm oracles: {:?}", pk.permutation_oracles.iter().for_each(|perm| println!("perm {:?}", perm.evals().iter().to_vec())));
    //     println!("selector oracles: {:?}", pk.selector_oracles);
    //     assert_eq!(pk.params.num_variables(), nv);
    //     let vk = HyperPlonkVerifyingKey::<Bls12_381, MultilinearKzgPCS<Bls12_381>>::deserialize_uncompressed_unchecked(&mut param_file).unwrap();
    //     assert_eq!(vk.params.num_variables(), nv);

    //     println!("=== START BENCHMARK WITH {} THREADS {} NV ===", thread, nv);
    //     bench_mock_circuit_zkp_helper(&mut log_file, circuit, pk, vk)?;
    // }

    Ok(())
}

fn bench_mock_circuit_zkp_helper(
    file: &mut File,
    circuit: MockCircuit<Fr>,
    pk: HyperPlonkProvingKey<Bls12_381, MultilinearKzgPCS<Bls12_381>>,
    vk: HyperPlonkVerifyingKey<Bls12_381, MultilinearKzgPCS<Bls12_381>>,
) -> Result<(), HyperPlonkErrors> {
    let nv = circuit.index.num_variables();
    let repetition = if nv < 10 {
        5
    // } else if nv < 20 {
    //     2
    } else {
        1
    };
    //==========================================================
    // generate a proof
    let start = Instant::now();
    let proof = <PolyIOP<Fr> as HyperPlonkSNARK<Bls12_381, MultilinearKzgPCS<Bls12_381>>>::prove(
        &pk,
        &circuit.public_inputs,
        &circuit.witnesses,
    )?;
    let t = start.elapsed().as_micros();
    println!("proving for {nv} variables: {t} us",);
    file.write_all(format!("{nv} {t}\n").as_ref()).unwrap();

    // Currently verifier doesn't work as we are using fake SRS

    // //==========================================================
    // // verify a proof
    // let start = Instant::now();
    // let verify = <PolyIOP<Fr> as HyperPlonkSNARK<Bls12_381, MultilinearKzgPCS<Bls12_381>>>::verify(
    //     &vk,
    //     &circuit.public_inputs,
    //     &proof,
    // )?;
    // assert!(verify);
    // println!(
    //     "verifying for {} variables: {} us",
    //     nv,
    //     start.elapsed().as_micros() / repetition as u128
    // );

    // println!();
    Ok(())
}
