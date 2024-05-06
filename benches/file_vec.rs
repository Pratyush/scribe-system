#[macro_use]
extern crate criterion;

use ark_ff::Field;
use ark_std::UniformRand;
use criterion::{BenchmarkId, Criterion, Throughput};
use scribe::streams::{file_vec::FileVec, BUFFER_SIZE};
use ark_bls12_381::Fr;

fn for_each(c: &mut Criterion) {
    let mut group = c.benchmark_group("for_each");
    let mut rng = &mut ark_std::test_rng();
    for size in [1, 2, 4, 8, 16] {
        let size = BUFFER_SIZE * size;
        let e = Fr::rand(&mut rng);
        group.throughput(Throughput::Elements(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &size| {
            let mut fv = FileVec::from_iter((0..size).map(|_| e));
            b.iter(|| fv.for_each(|e| *e += Fr::ONE));
        });
    }
    group.finish();
}

criterion_group!(file_vec, for_each);
criterion_main!(file_vec);
