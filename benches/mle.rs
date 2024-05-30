#[macro_use]
extern crate criterion;

use ark_bls12_381::Fr;
use ark_std::UniformRand;
use criterion::{BenchmarkId, Criterion};
use scribe::streams::{LOG_BUFFER_SIZE, MLE};

fn eq(c: &mut Criterion) {
    let num_threads = rayon::current_num_threads();
    let mut group = c.benchmark_group(format!("mle::eq {num_threads}"));
    let mut rng = &mut ark_std::test_rng();
    for num_vars in LOG_BUFFER_SIZE as usize..=20 {
        let e = Fr::rand(&mut rng);
        group.bench_with_input(BenchmarkId::from_parameter(num_vars), &num_vars, |b, _| b.iter(|| MLE::eq_x_r(&vec![e; num_vars])));
    }
    group.finish();
}

criterion_group!(iter, eq);
criterion_main!(iter);
