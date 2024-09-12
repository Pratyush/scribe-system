use std::{io::BufReader, time::Instant};
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

pub fn setup(min_num_vars: usize, max_num_vars: usize, file_dir_path: &Path) {
    // generate and serialize srs
    let mut rng = test_rng();
    let pc_srs = timed!(
        "Scribe: Generating SRS",
        PST13::<Bls12_381>::gen_fake_srs_for_testing(&mut rng, max_num_vars).unwrap()
    );

    let srs_path = file_dir_path.join(format!("scribe_srs_{max_num_vars}.params"));
    let srs_file = OpenOptions::new()
        .write(true)
        .create(true)
        .open(&srs_path)
        .unwrap();
    let mut srs_file = std::io::BufWriter::new(srs_file);
    timed!(
        "Scribe: Serializing SRS",
        pc_srs.serialize_uncompressed(&mut srs_file).unwrap()
    );

    // generate and serialize circuit, pk, vk
    let public_input_path = file_dir_path.join(format!("scribe_pubinput_{min_num_vars}_to_{max_num_vars}.params"));
    let witness_path = file_dir_path.join(format!("scribe_witness_{min_num_vars}_to_{max_num_vars}.params"));
    let pk_path = file_dir_path.join(format!("scribe_pk_{min_num_vars}_to_{max_num_vars}.params"));
    let vk_path = file_dir_path.join(format!("scribe_vk_{min_num_vars}_to_{max_num_vars}.params"));
    
    
    let public_input_file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&public_input_path)
        .unwrap();
    let witness_file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&witness_path)
        .unwrap();

    let pk_file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&pk_path)
        .unwrap();
    let vk_file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&vk_path)
        .unwrap();
    let mut public_input_file = std::io::BufWriter::new(public_input_file);
    let mut witness_file = std::io::BufWriter::new(witness_file);
    let mut pk_file = std::io::BufWriter::new(pk_file);
    let mut vk_file = std::io::BufWriter::new(vk_file);

    let vanilla_gate = CustomizedGates::vanilla_plonk_gate();
    for nv in min_num_vars..=max_num_vars {
        let circuit = timed!(
            format!("Scribe: Generating circuit for {nv}"),
            MockCircuit::<Fr>::new(1 << nv, &vanilla_gate)
        );

        timed!(
            format!("Scribe: Serializing witness for {nv}"),
            circuit.witnesses.serialize_uncompressed(&mut witness_file)
        )
        .unwrap();
        
        timed!(
            format!("Scribe: Serializing public input for {nv}"),
            circuit.public_inputs.serialize_uncompressed(&mut public_input_file)
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

pub fn prover(
    min_nv: usize,
    max_nv: usize,
    file_dir_path: &Path,
) -> Result<(), ScribeErrors> {

    let witness_path = file_dir_path.join(format!(
        "scribe_witness_{min_nv}_to_{max_nv}.params"));

    let public_input_path = file_dir_path.join(format!(
        "scribe_pubinput_{min_nv}_to_{max_nv}.params"));
    let pk_path =
        file_dir_path.join(format!("scribe_pk_{min_nv}_to_{max_nv}.params"));
    let vk_path =
        file_dir_path.join(format!("scribe_vk_{min_nv}_to_{max_nv}.params"));

    let mut public_input_file = BufReader::new(File::open(&public_input_path).unwrap());
    let mut witness_file = BufReader::new(File::open(&witness_path).unwrap());
    let mut pk_file = BufReader::new(File::open(&pk_path).unwrap());
    let mut vk_file = BufReader::new(File::open(&vk_path).unwrap());

    let tmp_dir = std::env::temp_dir();
    for nv in min_nv..=max_nv {
        // Remove temporary files
        std::fs::read_dir(&tmp_dir).unwrap()
            .for_each(|entry| std::fs::remove_file(entry.unwrap().path()).unwrap());

        let public_inputs = Vec::<Fr>::deserialize_uncompressed_unchecked(&mut public_input_file).unwrap();
        let witnesses = Vec::deserialize_uncompressed_unchecked(&mut witness_file).unwrap();

        let pk = ProvingKey::deserialize_uncompressed_unchecked(&mut pk_file).unwrap();
        let vk = VerifyingKey::deserialize_uncompressed_unchecked(&mut vk_file).unwrap();
        assert_eq!(vk.params.num_variables(), nv);

        //==========================================================
        // generate a proof
        let proof = timed!(
            format!("Scribe: Proving for {nv} variables",),
            Scribe::prove(&pk, &public_inputs, &witnesses)?
        );
        // Currently verifier doesn't work as we are using fake SRS

        //==========================================================
        // verify a proof
        timed!(
            format!("Scribe: Verifying for {nv} variables"),
            Scribe::verify(&vk, &public_inputs, &proof)?
        );
    }
    Ok(())
}
