use std::{fs::File, io, time::Instant};

use ark_bls12_381::Bls12_381;
use ark_bls12_381::Fr;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Write};
use ark_std::test_rng;
use scribe::hyperplonk::full_snark::custom_gate::CustomizedGates;
use scribe::hyperplonk::full_snark::{
    errors::HyperPlonkErrors, mock::MockCircuit, HyperPlonkSNARK,
};
use scribe::hyperplonk::{
    pcs::{
        multilinear_kzg::{srs::MultilinearUniversalParams, MultilinearKzgPCS},
        PolynomialCommitmentScheme,
    },
    poly_iop::PolyIOP,
};
use scribe::streams::LOG_BUFFER_SIZE;

const SUPPORTED_SIZE: usize = 12;

fn main() {
    // generate and serialize srs
    let pcs_srs = match File::open("srs.params") {
        Ok(mut p) => {
            println!("SRS already exists, please clear srs.params to reset");
            MultilinearUniversalParams::<Bls12_381>::deserialize_uncompressed_unchecked(&mut p).unwrap()
        },
        Err(_) => {
            let mut rng = test_rng();
            let srs = MultilinearKzgPCS::<Bls12_381>::gen_fake_srs_for_testing(&mut rng, SUPPORTED_SIZE).unwrap();
            let mut f = File::create("srs.params").unwrap();
            srs.serialize_uncompressed(&mut f).unwrap();
            srs
        }
    };

    // generate and serialize circuit
    let vanilla_gate = CustomizedGates::vanilla_plonk_gate();
    let circuit = MockCircuit::<Fr>::new(1 << SUPPORTED_SIZE, &vanilla_gate);
    let mut f2 = File::create("circuit.params").unwrap();
    circuit.serialize_uncompressed(&mut f2).unwrap();

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
    let mut f3 = File::create("pk.params").unwrap();
    pk.serialize_uncompressed(&mut f3).unwrap();
    let mut f4 = File::create("vk.params").unwrap();
    vk.serialize_uncompressed(&mut f4).unwrap();
}
