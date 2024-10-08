use std::time::Instant;

use ark_bls12_381::{Bls12_381, Fr, G1Affine as G1, G2Affine as G2};
use ark_ec::AffineRepr;
use ark_gemini::iterable::dummy::dummy_r1cs_stream;
use ark_gemini::iterable::dummy::DummyStreamer;
use ark_gemini::kzg::Commitment;
use ark_gemini::kzg::CommitterKeyStream;
use ark_gemini::psnark::Proof;
use ark_std::test_rng;

pub fn prover(min_size: usize, max_size: usize) {
    let rng = &mut test_rng();

    for nv in min_size..=max_size {
        let instance_size = 1 << nv;
        let max_msm_buffer = 1 << 20;

        let g1 = G1::generator();
        let g2 = G2::generator();
        let r1cs_stream = dummy_r1cs_stream::<Fr, _>(rng, instance_size);
        let ck = CommitterKeyStream {
            powers_of_g: DummyStreamer::new(g1, instance_size * 3 + 1),
            powers_of_g2: vec![g2; 4],
        };

        let index = vec![Commitment(g1.into_group()); 5];

        // generate a proof
        let _proof = timed!(
            format!("Gemini: Proving for {nv}",),
            Proof::<Bls12_381>::new_elastic(&ck, &r1cs_stream, &index, max_msm_buffer)
        );
    }
}
