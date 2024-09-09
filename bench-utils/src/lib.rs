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

    let srs_filename = format!("srs_{max_num_vars}.params");
    let mut srs_file = OpenOptions::new()
        .write(true)
        .create(true)
        .open(&srs_filename)
        .unwrap();
    pc_srs.serialize_uncompressed(&mut srs_file).unwrap();

    // generate and serialize circuit, pk, vk
    let circuit_filename = format!("circuit_{min_num_vars}_to_{max_num_vars}.params");
    let pk_filename = format!("pk_{min_num_vars}_to_{max_num_vars}.params");
    let vk_filename = format!("vk_{min_num_vars}_to_{max_num_vars}.params");
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
