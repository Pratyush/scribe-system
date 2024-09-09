use std::fs::OpenOptions;
use std::{fs::File, time::Instant};

use ark_bls12_381::Bls12_381;
use ark_bls12_381::Fr;
use ark_serialize::CanonicalDeserialize;
use ark_serialize::CanonicalSerialize;
use ark_std::test_rng;
use libc::size_t;
use scribe::pc::multilinear_kzg::PST13;
use scribe::pc::PolynomialCommitmentScheme;
use scribe::snark::custom_gate::CustomizedGates;
use scribe::snark::structs::{ProvingKey, VerifyingKey};
use scribe::snark::{errors::ScribeErrors, mock::MockCircuit, Scribe};

pub fn setup(min_num_vars: usize, max_num_vars: usize) {
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

pub fn prover(min_num_vars: usize, max_num_vars: usize) -> Result<(), ScribeErrors> {
    let mut params = File::open(format!(
        "circuit_pk_vk_{min_num_vars}_to_{max_num_vars}.params"
    ))
    .unwrap();

    for nv in min_num_vars..=max_num_vars {
        let circuit = MockCircuit::<Fr>::deserialize_uncompressed_unchecked(&mut params).unwrap();
        assert_eq!(circuit.index.num_variables(), nv);
        assert!(circuit.is_satisfied());

        let pk = ProvingKey::<Bls12_381, PST13<_>>::deserialize_uncompressed_unchecked(&mut params)
            .unwrap();
        let vk =
            VerifyingKey::<Bls12_381, PST13<_>>::deserialize_uncompressed_unchecked(&mut params)
                .unwrap();
        assert_eq!(vk.params.num_variables(), nv);

        println!("=== START BENCHMARK WITH {nv} variables ===");

        let nv = circuit.index.num_variables();

        //==========================================================
        // generate a proof
        let start = Instant::now();
        let proof = Scribe::prove(&pk, &circuit.public_inputs, &circuit.witnesses)?;
        let t = start.elapsed().as_micros();
        println!("proving for {nv} variables: {t} us",);
        // Currently verifier doesn't work as we are using fake SRS

        //==========================================================
        // verify a proof
        let start = Instant::now();
        Scribe::verify(&vk, &circuit.public_inputs, &proof)?;
        let t = start.elapsed().as_micros();
        println!("verifying for {nv} variables: {t} us");
    }
    Ok(())
}

#[no_mangle]
pub extern "C" fn bench_prover(min_num_vars: size_t, max_num_vars: size_t) -> size_t {
    match prover(min_num_vars, max_num_vars) {
        Ok(_) => 0,
        Err(_) => 1,
    }
}
