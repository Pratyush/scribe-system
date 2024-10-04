use std::{
    fs::{File, OpenOptions},
    path::Path,
};
use std::{io::BufReader, time::Instant};

use ark_bls12_381::Bls12_381;
use ark_bls12_381::Fr;
use ark_serialize::CanonicalDeserialize;
use ark_serialize::CanonicalSerialize;
use ark_std::test_rng;
use scribe::pc::PCScheme;
use scribe::snark::custom_gate::CustomizedGates;
use scribe::snark::structs::{ProvingKey as _ProvingKey, VerifyingKey as _VerifyingKey};
use scribe::snark::{errors::ScribeErrors, mock::MockCircuit, Scribe};
use scribe::{
    pc::{
        pst13::{srs::SRS, PST13},
        StructuredReferenceString,
    },
    snark::structs::ProvingKeyWithoutCk,
};

type ProvingKey = _ProvingKey<Bls12_381, PST13<Bls12_381>>;
type VerifyingKey = _VerifyingKey<Bls12_381, PST13<Bls12_381>>;

pub fn setup(min_num_vars: usize, max_num_vars: usize, file_dir_path: &Path) {
    // generate and serialize srs
    let mut rng = test_rng();
    let pc_srs = timed!(
        "Scribe: Generating SRS",
        PST13::<Bls12_381>::gen_srs_for_testing(&mut rng, max_num_vars).unwrap()
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

    let vanilla_gate = CustomizedGates::vanilla_plonk_gate();
    for nv in min_num_vars..=max_num_vars {
        // generate and serialize circuit, pk, vk
        let pk_path = file_dir_path.join(format!("scribe_pk_{nv}.params"));

        let pk_file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&pk_path)
            .unwrap();
        let mut pk_file = std::io::BufWriter::new(pk_file);

        let circuit = timed!(
            format!("Scribe: Generating circuit for {nv}"),
            MockCircuit::<Fr>::new(1 << nv, &vanilla_gate)
        );

        let index = circuit.index;
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(8)
            .build()
            .unwrap();

        let (pk, _vk): (ProvingKey, VerifyingKey) = pool
            .install(|| {
                timed!(
                    format!("Scribe: Generating pk/vk for {nv}",),
                    Scribe::preprocess(&index, &pc_srs)
                )
            })
            .unwrap();

        timed!(
            format!("Scribe: Serializing pk for {nv}"),
            pk.inner.serialize_uncompressed(&mut pk_file).unwrap()
        );
    }
}

pub fn prover(
    min_nv: usize,
    max_nv: usize,
    supported_size: impl Into<Option<usize>>,
    file_dir_path: &Path,
    remove_files: bool,
) -> Result<(), ScribeErrors> {
    let supported_size = supported_size.into().unwrap_or(max_nv);
    assert!(max_nv >= min_nv);
    assert!(max_nv <= supported_size);

    let srs: SRS<_> = {
        let srs_path = file_dir_path.join(format!("scribe_srs_{supported_size}.params"));
        let srs_file = File::open(&srs_path).unwrap();
        let mut srs_file = std::io::BufReader::new(srs_file);
        CanonicalDeserialize::deserialize_uncompressed_unchecked(&mut srs_file).unwrap()
    };

    let tmp_dir = std::env::temp_dir();
    for nv in min_nv..=max_nv {
        // Remove temporary files
        if remove_files {
            std::fs::read_dir(&tmp_dir).unwrap().for_each(|entry| {
                let entry = entry.unwrap();
                if !entry.file_name().to_string_lossy().contains("ck_") {
                    println!("Removing entry: {}", entry.path().to_string_lossy());
                    std::fs::remove_file(entry.path()).unwrap()
                }
            });
        }

        let pk = {
            let pk_path = file_dir_path.join(format!("scribe_pk_{nv}.params"));
            let pk_file = BufReader::new(File::open(&pk_path).unwrap());
            let inner = ProvingKeyWithoutCk::deserialize_uncompressed_unchecked(pk_file).unwrap();
            let (pc_ck, _) = srs.trim(nv).unwrap();
            ProvingKey { inner, pc_ck }
        };

        let (public_inputs, witnesses) = timed!(
            format!("Scribe: Generating witness for {nv} variables"),
            MockCircuit::wire_values_for_index(&pk.index())
        );

        let proof = timed!(
            format!("Scribe: Proving for {nv} variables",),
            Scribe::prove(&pk, &public_inputs, &witnesses).unwrap()
        );
        // Currently verifier doesn't work as we are using fake SRS
        //==========================================================
        // verify a proof
        let result = timed!(
            format!("Scribe: Verifying for {nv} variables"),
            Scribe::verify(&pk.vk(), &public_inputs, &proof).unwrap()
        );
        assert!(result);
    }
    Ok(())
}
