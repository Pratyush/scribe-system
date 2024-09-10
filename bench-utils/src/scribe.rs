use std::time::Instant;
use std::{
    fs::{File, OpenOptions},
    path::Path,
};

use ark_bls12_381::Bls12_381;
use ark_bls12_381::Fr;
use ark_serialize::CanonicalDeserialize;
use ark_serialize::CanonicalSerialize;
use ark_std::test_rng;
use scribe::pc::multilinear_kzg::PST13;
use scribe::pc::PolynomialCommitmentScheme;
use scribe::snark::custom_gate::CustomizedGates;
use scribe::snark::structs::{ProvingKey as _ProvingKey, VerifyingKey as _VerifyingKey};
use scribe::snark::{errors::ScribeErrors, mock::MockCircuit, Scribe};

type ProvingKey = _ProvingKey<Bls12_381, PST13<Bls12_381>>;
type VerifyingKey = _VerifyingKey<Bls12_381, PST13<Bls12_381>>;

pub fn scribe_setup(min_num_vars: usize, max_num_vars: usize, file_dir_path: &Path) {
    // generate and serialize srs
    let mut rng = test_rng();
    let pc_srs = timed!(
        "Scribe: Generating SRS",
        PST13::<Bls12_381>::gen_fake_srs_for_testing(&mut rng, max_num_vars).unwrap()
    );

    let srs_filename = file_dir_path.join(format!("scribe_srs_{max_num_vars}.params"));
    let srs_file = OpenOptions::new()
        .write(true)
        .create(true)
        .open(&srs_filename)
        .unwrap();
    let mut srs_file = std::io::BufWriter::new(srs_file);
    timed!(
        "Scribe: Serializing SRS",
        pc_srs.serialize_uncompressed(&mut srs_file).unwrap()
    );

    // generate and serialize circuit, pk, vk
    let circuit_filename = format!("scribe_circuit_{min_num_vars}_to_{max_num_vars}.params");
    let pk_filename = format!("scribe_pk_{min_num_vars}_to_{max_num_vars}.params");
    let vk_filename = format!("scribe_vk_{min_num_vars}_to_{max_num_vars}.params");
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
            format!("Scribe: Generating circuit for {nv}"),
            MockCircuit::<Fr>::new(1 << nv, &vanilla_gate)
        );

        timed!(
            format!("Scribe: Serializing circuit for {nv}"),
            circuit.serialize_uncompressed(&mut circuit_file)
        )
        .unwrap();

        let index = circuit.index;
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(8)
            .build()
            .unwrap();

        let (pk, vk): (ProvingKey, VerifyingKey) = pool
            .install(|| {
                timed!(
                    format!("Scribe: Generating pk/vk for {nv}",),
                    Scribe::preprocess(&index, &pc_srs)
                )
            })
            .unwrap();

        timed!(format!("Scribe: Serializing pk/vk for {nv}"), {
            pk.serialize_uncompressed(&mut pk_file).unwrap();
            vk.serialize_uncompressed(&mut vk_file).unwrap();
        });
    }
}

pub fn scribe_prover(
    min_num_vars: usize,
    max_num_vars: usize,
    file_dir_path: &Path,
) -> Result<(), ScribeErrors> {
    let circuit_filename = file_dir_path.join(format!(
        "scribe_circuit_{min_num_vars}_to_{max_num_vars}.params"
    ));
    let pk_filename =
        file_dir_path.join(format!("scribe_pk_{min_num_vars}_to_{max_num_vars}.params"));
    let vk_filename =
        file_dir_path.join(format!("scribe_vk_{min_num_vars}_to_{max_num_vars}.params"));
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

        let pk = ProvingKey::deserialize_uncompressed_unchecked(&mut pk_file).unwrap();
        let vk = VerifyingKey::deserialize_uncompressed_unchecked(&mut vk_file).unwrap();
        assert_eq!(vk.params.num_variables(), nv);

        let nv = circuit.index.num_variables();

        //==========================================================
        // generate a proof
        let proof = timed!(
            format!("Scribe: Proving for {nv} variables",),
            Scribe::prove(&pk, &circuit.public_inputs, &circuit.witnesses)?
        );
        // Currently verifier doesn't work as we are using fake SRS

        //==========================================================
        // verify a proof
        timed!(
            format!("Scribe: Verifying for {nv} variables"),
            Scribe::verify(&vk, &circuit.public_inputs, &proof)?
        );
    }
    Ok(())
}
