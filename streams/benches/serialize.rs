#[macro_use]
extern crate criterion;

use ark_bls12_381::{Fq, Fr, G1Affine};
use ark_std::UniformRand;
use criterion::Criterion;
use scribe_streams::serialize::*;

fn serialize_fr(c: &mut Criterion) {
    c.bench_function("Serialize bls12_381::Fr", |b| {
        let mut vec = Vec::with_capacity(Fr::SIZE);
        let f = Fr::rand(&mut ark_std::test_rng());
        b.iter(|| {
            f.serialize_raw(&mut vec).unwrap();
            vec.clear();
        });
    });

    c.bench_function("Deserialize bls12_381::Fr", |b| {
        let mut vec = Vec::with_capacity(Fr::SIZE);
        let f = Fr::rand(&mut ark_std::test_rng());
        f.serialize_raw(&mut vec).unwrap();
        b.iter(|| Fr::deserialize_raw(&mut &vec[..]).unwrap());
    });
}

fn serialize_fq(c: &mut Criterion) {
    c.bench_function("Serialize bls12_381::Fq", |b| {
        let mut vec = Vec::with_capacity(Fq::SIZE);
        let f = Fq::rand(&mut ark_std::test_rng());
        b.iter(|| {
            f.serialize_raw(&mut vec).unwrap();
            vec.clear();
        });
    });

    c.bench_function("Deserialize bls12_381::Fq", |b| {
        let mut vec = Vec::with_capacity(Fq::SIZE);
        let f = Fq::rand(&mut ark_std::test_rng());
        f.serialize_raw(&mut vec).unwrap();
        b.iter(|| Fq::deserialize_raw(&mut &vec[..]).unwrap());
    });
}

fn serialize_g1(c: &mut Criterion) {
    c.bench_function("Serialize bls12_381::G1", |b| {
        let mut vec = Vec::with_capacity(G1Affine::SIZE);
        let g = G1Affine::rand(&mut ark_std::test_rng());
        b.iter(|| {
            g.serialize_raw(&mut vec).unwrap();
            vec.clear();
        });
    });
    c.bench_function("Deserialize bls12_381::G1", |b| {
        let mut vec = Vec::with_capacity(G1Affine::SIZE);
        let f = G1Affine::rand(&mut ark_std::test_rng());
        f.serialize_raw(&mut vec).unwrap();
        b.iter(|| G1Affine::deserialize_raw(&mut &vec[..]).unwrap());
    });
}

criterion_group!(serialize, serialize_fr, serialize_g1, serialize_fq);
criterion_main!(serialize);
