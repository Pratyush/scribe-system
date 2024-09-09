use std::{fs::File, time::Instant};

use ark_bls12_381::Bls12_381;
use ark_bls12_381::Fr;
use ark_serialize::CanonicalDeserialize;
use libc::size_t;
use scribe::pc::multilinear_kzg::PST13;
use scribe::snark::structs::{ProvingKey, VerifyingKey};
use scribe::snark::{errors::ScribeErrors, mock::MockCircuit, Scribe};


fn bench_prover(min_num_vars: usize, max_num_vars: usize) -> Result<(), ScribeErrors> {
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
pub extern "C" fn prover(min_num_vars: size_t, max_num_vars: size_t) -> size_t {
    match bench_prover(min_num_vars, max_num_vars) {
        Ok(_) => 0,
        Err(_) => 1,
    }
}