#[macro_use]
extern crate criterion;

use ark_bls12_381::Fr;
use ark_ff::Field;
use ark_std::UniformRand;
use criterion::{BenchmarkId, Criterion, Throughput};
use scribe::streams::{file_vec::FileVec, BUFFER_SIZE};

fn for_each_simple(c: &mut Criterion) {
    let mut group = c.benchmark_group("for_each_simple");
    let mut rng = &mut ark_std::test_rng();
    for size in [1, 2, 4, 8, 16] {
        let e = Fr::rand(&mut rng);
        let vec_size = BUFFER_SIZE * size;
        group.throughput(Throughput::Elements(vec_size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, _| {
            let mut fv = FileVec::from_iter((0..vec_size).map(|_| e));
            b.iter(|| fv.for_each(|e| *e += Fr::ONE));
        });
    }
    group.finish();
}

fn for_each_complex(c: &mut Criterion) {
    let mut group = c.benchmark_group("for_each_complex");
    let mut rng = &mut ark_std::test_rng();
    for size in [1, 2, 4, 8, 16] {
        let e = Fr::rand(&mut rng);
        let vec_size = BUFFER_SIZE * size;
        group.throughput(Throughput::Elements(vec_size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, _| {
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

criterion_group!(file_vec, for_each_simple, for_each_complex);
criterion_main!(file_vec);
