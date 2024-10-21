#[macro_use]
extern crate criterion;

use ark_bls12_381::Fr;
use ark_ff::Field;
use ark_std::UniformRand;
use criterion::{BenchmarkId, Criterion, Throughput};
use scribe_streams::iterator::*;
use scribe_streams::BUFFER_SIZE;

fn map(c: &mut Criterion) {
    let num_threads = rayon::current_num_threads();
    let mut group = c.benchmark_group(format!("iter::map {num_threads}"));
    let mut rng = &mut ark_std::test_rng();
    for size in [1, 2, 4, 8, 16] {
        let e = Fr::rand(&mut rng);
        let vec_size = BUFFER_SIZE * size;
        group.throughput(Throughput::Elements(vec_size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(vec_size), &size, |b, _| {
            b.iter(|| {
                repeat(e, vec_size)
                    .map(|e| e.double().double().double())
                    .for_each(|_| {})
            });
        });
    }
    group.finish();
}

fn for_each(c: &mut Criterion) {
    let num_threads = rayon::current_num_threads();
    let mut group = c.benchmark_group(format!("iter::for_each {num_threads}"));
    let mut rng = &mut ark_std::test_rng();
    for size in [1, 2, 4, 8, 16] {
        let e = Fr::rand(&mut rng);
        let vec_size = BUFFER_SIZE * size;
        group.throughput(Throughput::Elements(vec_size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(vec_size), &size, |b, _| {
            b.iter(|| {
                repeat(e, vec_size).map(|e| e.double()).for_each(|mut e| {
                    e.double_in_place();
                })
            });
        });
    }
    group.finish();
}

fn zip(c: &mut Criterion) {
    let num_threads = rayon::current_num_threads();
    let mut group = c.benchmark_group(format!("iter::zip {num_threads}"));
    let mut rng = &mut ark_std::test_rng();
    for size in [1, 2, 4, 8, 16] {
        let e = Fr::rand(&mut rng);
        let vec_size = BUFFER_SIZE * size;
        group.throughput(Throughput::Elements(vec_size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(vec_size), &size, |b, _| {
            b.iter(|| {
                let one = repeat(e, vec_size);
                let two = repeat(e, vec_size);
                one.zip(two).map(|(a, b)| a + b).for_each(|_| {});
            });
        });
    }
    group.finish();
}

fn array_chunks(c: &mut Criterion) {
    let num_threads = rayon::current_num_threads();
    let mut group = c.benchmark_group(format!("iter::array_chunks {num_threads}"));
    let mut rng = &mut ark_std::test_rng();
    for size in [1, 2, 4, 8, 16] {
        let e = Fr::rand(&mut rng);
        let vec_size = BUFFER_SIZE * size;
        group.throughput(Throughput::Elements(vec_size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(vec_size), &size, |b, _| {
            b.iter(|| {
                let one = repeat(e, vec_size);
                one.array_chunks::<2>().map(|[a, b]| a + b).for_each(|_| {});
            });
        });
    }
    group.finish();
}

criterion_group!(iter, map, for_each, zip, array_chunks);
criterion_main!(iter);
