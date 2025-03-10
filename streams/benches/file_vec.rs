#[macro_use]
extern crate criterion;

use ark_bls12_381::Fr;
use ark_ff::Field;
use ark_std::UniformRand;
use criterion::{BatchSize, BenchmarkId, Criterion, Throughput};
use scribe_streams::{file_vec::FileVec, iterator::BatchedIterator, BUFFER_SIZE};

fn for_each_simple(c: &mut Criterion) {
    let num_threads = rayon::current_num_threads();
    let mut group = c.benchmark_group(format!("fv::for_each_simple {num_threads}"));
    let mut rng = &mut ark_std::test_rng();
    for size in [1, 2, 4, 8, 16] {
        let e = Fr::rand(&mut rng);
        let vec_size = BUFFER_SIZE * size;
        group.throughput(Throughput::Elements(vec_size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(vec_size), &size, |b, _| {
            let mut fv = FileVec::from_iter((0..vec_size).map(|_| e));
            b.iter(|| fv.for_each(|e| *e += Fr::ONE));
        });
    }
    group.finish();
}

fn from_batched_iter(c: &mut Criterion) {
    let num_threads = rayon::current_num_threads();
    let mut group = c.benchmark_group(format!("fv::from_batched_iter {num_threads}"));
    let mut rng = &mut ark_std::test_rng();
    for size in [1, 2, 4, 8, 16] {
        let e = Fr::rand(&mut rng);
        let vec_size = BUFFER_SIZE * size;
        group.throughput(Throughput::Elements(vec_size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(vec_size), &size, |b, _| {
            use scribe_streams::iterator::*;
            b.iter(|| {
                repeat(e, vec_size)
                    .map(|e| e.square().square())
                    .to_file_vec()
            });
        });
    }
    group.finish();
}

fn for_each_complex(c: &mut Criterion) {
    let num_threads = rayon::current_num_threads();
    let mut group = c.benchmark_group(format!("fv::for_each_complex {num_threads}"));
    let mut rng = &mut ark_std::test_rng();
    for size in [1, 2, 4, 8, 16] {
        let e = Fr::rand(&mut rng);
        let vec_size = BUFFER_SIZE * size;
        group.throughput(Throughput::Elements(vec_size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(vec_size), &size, |b, _| {
            let mut fv = FileVec::from_iter((0..vec_size).map(|_| e));
            b.iter(|| {
                fv.for_each(|e| {
                    e.square_in_place()
                        .square_in_place()
                        .double_in_place()
                        .square_in_place();
                })
            });
        });
    }
    group.finish();
}

fn iter_map(c: &mut Criterion) {
    let num_threads = rayon::current_num_threads();
    let mut group = c.benchmark_group(format!("fv::iter_map {num_threads}"));
    let mut rng = &mut ark_std::test_rng();
    for size in [1, 2, 4, 8, 16] {
        let e = Fr::rand(&mut rng);
        let vec_size = BUFFER_SIZE * size;
        group.throughput(Throughput::Elements(vec_size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(vec_size), &size, |b, _| {
            let fv = FileVec::from_iter((0..vec_size).map(|_| e));
            b.iter(|| fv.iter().map(|e| e.double()).for_each(|_| {}));
        });
    }
    group.finish();
}

fn into_iter_map(c: &mut Criterion) {
    let num_threads = rayon::current_num_threads();
    let mut group = c.benchmark_group(format!("fv::into_iter_map {num_threads}"));
    let mut rng = &mut ark_std::test_rng();
    for size in [1, 2, 4, 8, 16] {
        let e = Fr::rand(&mut rng);
        let vec_size = BUFFER_SIZE * size;
        group.throughput(Throughput::Elements(vec_size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(vec_size), &size, |b, _| {
            let fv = FileVec::from_iter((0..vec_size).map(|_| e));
            b.iter_batched(
                || fv.deep_copy(),
                |fv| fv.into_iter().map(|e| e.double()).for_each(|_| {}),
                BatchSize::SmallInput,
            );
        });
    }
    group.finish();
}

fn iter_chunk_mapped(c: &mut Criterion) {
    let num_threads = rayon::current_num_threads();
    let mut group = c.benchmark_group(format!("fv::iter_chunk_mapped {num_threads}"));
    let mut rng = &mut ark_std::test_rng();
    for size in [1, 2, 4, 8, 16] {
        let e = Fr::rand(&mut rng);
        let vec_size = BUFFER_SIZE * size;
        group.throughput(Throughput::Elements(vec_size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(vec_size), &size, |b, _| {
            let fv = FileVec::from_iter((0..vec_size).map(|_| e));
            b.iter(|| {
                fv.iter_chunk_mapped::<2, _, _>(|c| c[0] * c[1])
                    .for_each(|_| {})
            });
        });
    }
    group.finish();
}

criterion_group!(
    file_vec,
    for_each_simple,
    for_each_complex,
    from_batched_iter,
    iter_map,
    into_iter_map,
    iter_chunk_mapped,
);
criterion_main!(file_vec);
