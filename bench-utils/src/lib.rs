use std::fs::{File, OpenOptions};
use std::time::Instant;

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

macro_rules! timed {
    ($name:expr, $block:expr) => {{
        let start = Instant::now();
        let result = { $block };
        let elapsed = start.elapsed().as_micros();
        println!("{} took: {:?} us", $name, elapsed);
        result
    }};
}

pub fn setup(min_num_vars: usize, max_num_vars: usize) {
    // generate and serialize srs
    let mut rng = test_rng();
    let pc_srs = timed!(
        "Generating SRS",
        PST13::<Bls12_381>::gen_fake_srs_for_testing(&mut rng, max_num_vars).unwrap()
    );

    let srs_filename = format!("srs_{max_num_vars}.params");
    let srs_file = OpenOptions::new()
        .write(true)
        .create(true)
        .open(&srs_filename)
        .unwrap();
    let mut srs_file = std::io::BufWriter::new(srs_file);
    timed!(
        "Serializing SRS",
        pc_srs.serialize_uncompressed(&mut srs_file).unwrap()
    );

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
    let mut circuit_file = std::io::BufWriter::new(circuit_file);
    let mut pk_file = std::io::BufWriter::new(pk_file);
    let mut vk_file = std::io::BufWriter::new(vk_file);

    let vanilla_gate = CustomizedGates::vanilla_plonk_gate();
    for nv in min_num_vars..=max_num_vars {
        let circuit = timed!(
            format!("Generating circuit for {nv}"),
            MockCircuit::<Fr>::new(1 << nv, &vanilla_gate)
        );

        timed!(
            format!("Serializing circuit for {nv}"),
            circuit.serialize_uncompressed(&mut circuit_file)
        )
        .unwrap();

        let index = circuit.index;
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(8)
            .build()
            .unwrap();

        let (pk, vk): (
            ProvingKey<_, PST13<Bls12_381>>,
            VerifyingKey<_, PST13<Bls12_381>>,
        ) = pool
            .install(|| {
                timed!(
                    format!("Generating pk/vk for {nv}",),
                    Scribe::preprocess(&index, &pc_srs)
                )
            })
            .unwrap();

        timed!(format!("Serializing pk/vk for {nv}"), {
            pk.serialize_uncompressed(&mut pk_file).unwrap();
            vk.serialize_uncompressed(&mut vk_file).unwrap();
        });
    }
}

pub fn prover(min_num_vars: usize, max_num_vars: usize) -> Result<(), ScribeErrors> {
    let circuit_filename = format!("circuit_{min_num_vars}_to_{max_num_vars}.params");
    let pk_filename = format!("pk_{min_num_vars}_to_{max_num_vars}.params");
    let vk_filename = format!("vk_{min_num_vars}_to_{max_num_vars}.params");
    let circuit_file = File::open(&circuit_filename).unwrap();
    let pk_file = File::open(&pk_filename).unwrap();
    let vk_file = File::open(&vk_filename).unwrap();

    let mut circuit_file = std::io::BufReader::new(circuit_file);
    let mut pk_file = std::io::BufReader::new(pk_file);
    let mut vk_file = std::io::BufReader::new(vk_file);

    for nv in min_num_vars..=max_num_vars {
        let circuit = MockCircuit::deserialize_uncompressed_unchecked(&mut circuit_file).unwrap();
        assert_eq!(circuit.index.num_variables(), nv);
        assert!(circuit.is_satisfied());

        let pk =
            ProvingKey::<_, PST13<Bls12_381>>::deserialize_uncompressed_unchecked(&mut pk_file)
                .unwrap();
        let vk =
            VerifyingKey::<_, PST13<Bls12_381>>::deserialize_uncompressed_unchecked(&mut vk_file)
                .unwrap();
        assert_eq!(vk.params.num_variables(), nv);

        println!("=== START BENCHMARK WITH {nv} variables ===");

        let nv = circuit.index.num_variables();

        //==========================================================
        // generate a proof
        let proof = timed!(
            format!("Proving for {nv} variables",),
            Scribe::prove(&pk, &circuit.public_inputs, &circuit.witnesses)?
        );
        // Currently verifier doesn't work as we are using fake SRS

        //==========================================================
        // verify a proof
        timed!(
            format!("Verifying for {nv} variables"),
            Scribe::verify(&vk, &circuit.public_inputs, &proof)?
        );
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
