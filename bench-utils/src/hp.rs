use std::{
    fs::{File, OpenOptions},
    path::Path,
};

use ark_bls12_381_04::{Bls12_381, Fr};
use ark_serialize_04::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::test_rng;
use hp::{
    prelude::{CustomizedGates, HyperPlonkErrors, MockCircuit},
    HyperPlonkSNARK,
};
use hp_subroutines::{
    pcs::{
        prelude::{MultilinearKzgPCS, MultilinearUniversalParams},
        PolynomialCommitmentScheme,
    },
    poly_iop::PolyIOP,
};

type ProvingKey =
    <PolyIOP<Fr> as HyperPlonkSNARK<Bls12_381, MultilinearKzgPCS<Bls12_381>>>::ProvingKey;
type VerifyingKey =
    <PolyIOP<Fr> as HyperPlonkSNARK<Bls12_381, MultilinearKzgPCS<Bls12_381>>>::VerifyingKey;
type HyperPlonk = PolyIOP<Fr>;

pub fn setup(_min_num_vars: usize, max_num_vars: usize, file_dir_path: &Path) {
    // generate and serialize srs
    let mut rng = test_rng();
    let pc_srs = timed!(
        "HyperPlonk: Generating SRS for HyperPlonk",
        MultilinearKzgPCS::<Bls12_381>::gen_srs_for_testing(&mut rng, max_num_vars).unwrap()
    );

    let srs_filename = file_dir_path.join(format!("hp_srs_{max_num_vars}.params"));
    let srs_file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&srs_filename)
        .unwrap();
    let mut srs_file = std::io::BufWriter::new(srs_file);
    timed!(
        "HyperPlonk: Serializing SRS",
        pc_srs.serialize_uncompressed(&mut srs_file).unwrap()
    );
}

pub fn prover(
    min_num_vars: usize,
    max_num_vars: usize,
    supported_size: impl Into<Option<usize>>,
    file_dir_path: &Path,
) -> Result<(), HyperPlonkErrors> {
    let supported_size = supported_size.into().unwrap_or(max_num_vars);
    let srs_filename = file_dir_path.join(format!("hp_srs_{supported_size}.params"));
    let srs_file = File::open(&srs_filename).unwrap();
    let mut srs_file = std::io::BufReader::new(srs_file);
    let pc_srs =
        MultilinearUniversalParams::<Bls12_381>::deserialize_uncompressed_unchecked(&mut srs_file)
            .unwrap();

    let vanilla_gate = CustomizedGates::vanilla_plonk_gate();
    for nv in min_num_vars..=max_num_vars {
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(8)
            .build()
            .unwrap();
        let circuit = pool.install(|| {
            timed!(
                format!("HyperPlonk: Generating circuit for {nv}"),
                MockCircuit::<Fr>::new(1 << nv, &vanilla_gate)
            )
        });

        let index = circuit.index;

        let (pk, vk): (ProvingKey, VerifyingKey) = pool.install(|| {
            timed!(
                format!("HyperPlonk: Generating pk/vk for {nv}",),
                HyperPlonk::preprocess(&index, &pc_srs).unwrap()
            )
        });

        // generate a proof
        let proof = timed!(
            format!("HyperPlonk: Proving for {nv}",),
            HyperPlonk::prove(&pk, &circuit.public_inputs, &circuit.witnesses)?
        );
        // Currently verifier doesn't work as we are using fake SRS

        //==========================================================
        // verify a proof
        timed!(
            format!("HyperPlonk: Verifying for {nv}"),
            HyperPlonk::verify(&vk, &circuit.public_inputs, &proof)?
        );
    }
    Ok(())
}
