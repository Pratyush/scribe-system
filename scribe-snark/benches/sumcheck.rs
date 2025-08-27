#[macro_use]
extern crate criterion;

use ark_bls12_381::Fr;
use criterion::{BenchmarkId, Criterion};
use mle::VirtualPolynomial;
use scribe::piop::prelude::SumCheck;
use scribe_streams::LOG_BUFFER_SIZE;

fn sumcheck_2(c: &mut Criterion) {
    let num_threads = rayon::current_num_threads();
    let mut group = c.benchmark_group(format!("sumcheck_2 {num_threads}"));
    let mut rng = &mut ark_std::test_rng();
    for num_vars in (LOG_BUFFER_SIZE - 1) as usize..=21 {
        group.bench_with_input(BenchmarkId::from_parameter(num_vars), &num_vars, |b, _| {
            let poly =
                VirtualPolynomial::<Fr>::rand_with_shared_terms(num_vars, (2, 3), 5, &mut rng)
                    .unwrap();
            b.iter(|| {
                let mut transcript = SumCheck::<Fr>::init_transcript();
                SumCheck::prove(&poly, &mut transcript).unwrap()
            })
        });
    }
    group.finish();
}

criterion_group!(piop, sumcheck_2,);
criterion_main!(piop);
