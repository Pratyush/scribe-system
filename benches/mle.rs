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
        group.bench_with_input(BenchmarkId::from_parameter(num_vars), &num_vars, |b, _| {
            b.iter(|| MLE::eq_x_r(&vec![e; num_vars]))
        });
    }
    group.finish();
}

fn eval(c: &mut Criterion) {
    let num_threads = rayon::current_num_threads();
    let mut group = c.benchmark_group(format!("mle::eval {num_threads}"));
    let mut rng = &mut ark_std::test_rng();
    for num_vars in LOG_BUFFER_SIZE as usize..=20 {
        let e = Fr::rand(&mut rng);
        group.bench_with_input(BenchmarkId::from_parameter(num_vars), &num_vars, |b, _| {
            let p = MLE::rand(num_vars, &mut rng);
            b.iter(|| p.evaluate(&vec![e; num_vars]))
        });
    }
    group.finish();
}

fn eval_vec(c: &mut Criterion) {
    let num_threads = rayon::current_num_threads();
    let mut group = c.benchmark_group(format!("mle::eval_vec {num_threads}"));
    let mut rng = &mut ark_std::test_rng();

    for num_vars in LOG_BUFFER_SIZE as usize..=20 {
        let e = Fr::rand(&mut rng);
        group.bench_with_input(BenchmarkId::from_parameter(num_vars), &num_vars, |b, _| {
            let p = vec![e; 1 << num_vars];
            b.iter(|| evaluate_vec(&p, &vec![e; num_vars]))
        });
    }
    group.finish();
}

pub fn evaluate_vec(poly: &[Fr], point: &[Fr]) -> Fr {
    fix_variables(poly, point)[0]
}

pub fn fix_variables(poly: &[Fr], partial_point: &[Fr]) -> Vec<Fr> {
    let nv = poly.len().ilog2() as usize;
    assert!(partial_point.len() <= nv, "invalid size of partial point");
    let mut poly = poly.to_vec();
    let dim = partial_point.len();
    // evaluate single variable of partial point from left to right
    for (i, point) in partial_point.iter().enumerate().take(dim) {
        poly = fix_one_variable_helper(&poly, nv - i, point);
    }

    poly[..(1 << (nv - dim))].to_vec()
}

fn fix_one_variable_helper(data: &[Fr], nv: usize, point: &Fr) -> Vec<Fr> {
    use ark_ff::Field;
    use rayon::prelude::*;
    let mut res = vec![Fr::ZERO; 1 << (nv - 1)];
    res.par_iter_mut().enumerate().for_each(|(i, x)| {
        *x = data[i << 1] + (data[(i << 1) + 1] - data[i << 1]) * point;
    });
    res
}

criterion_group!(iter, eq, eval, eval_vec);
criterion_main!(iter);
