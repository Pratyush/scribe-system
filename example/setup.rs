use std::f32::MIN;
use std::{fs::File, io, time::Instant};

use ark_bls12_381::Bls12_381;
use ark_bls12_381::Fr;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Write};
use ark_std::test_rng;
use scribe::hyperplonk::full_snark::custom_gate::CustomizedGates;
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
use scribe::streams::LOG_BUFFER_SIZE;

const SUPPORTED_SIZE: usize = 12;
const MIN_NUM_VARS: usize = 8;
const MAX_NUM_VARS: usize = 12;

fn main() {
    // generate and serialize srs
    let srs_filename = format!("srs_{}.params", SUPPORTED_SIZE);
    let pcs_srs = match File::open(srs_filename.clone()) {
        Ok(mut p) => {
            println!("SRS already exists, please clear {} to reset", srs_filename.clone());
            MultilinearUniversalParams::<Bls12_381>::deserialize_uncompressed_unchecked(&mut p).unwrap()
        },
        Err(_) => {
            let mut rng = test_rng();
            let srs = MultilinearKzgPCS::<Bls12_381>::gen_fake_srs_for_testing(&mut rng, SUPPORTED_SIZE).unwrap();
            let mut f = File::create(srs_filename).unwrap();
            srs.serialize_uncompressed(&mut f).unwrap();
            srs
        }
    };

    // println!("srs powers of g: {}", pcs_srs.prover_param.powers_g.len());

    // generate and serialize circuit, pk, vk
    let circuit_filename = format!("circuit_pk_vk_{}_to_{}.params", MIN_NUM_VARS, MAX_NUM_VARS);
    if MAX_NUM_VARS > SUPPORTED_SIZE {
        panic!("MAX_NUM_VARS must be less than or equal to SUPPORTED_SIZE");
    }
    match File::open(circuit_filename.clone()) {
        Ok(mut p) => {
            println!("Circuit already exists, please clear {} to reset", circuit_filename.clone());
        },
        Err(_) => {
            let file = File::create(circuit_filename).unwrap();
            let vanilla_gate = CustomizedGates::vanilla_plonk_gate();
            for nv in MIN_NUM_VARS..=MAX_NUM_VARS {
                println!("nv = {}", nv);
                let circuit = MockCircuit::<Fr>::new(1 << nv, &vanilla_gate);
                circuit.serialize_uncompressed(&file).unwrap();
                let index = circuit.index;
                let pool = rayon::ThreadPoolBuilder::new()
                    .num_threads(8)
                    .build()
                    .unwrap();

                let (pk, vk) = pool.install(|| {
                    <PolyIOP<Fr> as HyperPlonkSNARK<Bls12_381, MultilinearKzgPCS<_>>>::preprocess(
                        &index, &pcs_srs,
                    )
                }).unwrap();
                pk.serialize_uncompressed(&file).unwrap();
                vk.serialize_uncompressed(&file).unwrap();
            }
        }
    };
}
