use crate::pc::structs::Commitment;
use crate::pc::PCScheme;
use crate::snark::{custom_gate::CustomizedGates, errors::ScribeErrors, structs::ScribeConfig};
use crate::transcript::IOPTranscript;
use ark_ec::pairing::Pairing;
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{end_timer, start_timer};
use mle::virtual_polynomial::VirtualPolynomial;
use mle::MLE;
use rayon::prelude::*;
use scribe_streams::file_vec::FileVec;
use scribe_streams::{iterator::BatchedIterator, serialize::RawPrimeField};

use std::borrow::Borrow;

/// An accumulator structure that holds a polynomial and
/// its opening points
#[derive(Debug)]
pub(super) struct PCAccumulator<E: Pairing, PC: PCScheme<E>> {
    pub(crate) num_var: usize,
    pub(crate) polynomials: Vec<PC::Polynomial>,
    pub(crate) commitments: Vec<PC::Commitment>,
    pub(crate) points: Vec<PC::Point>,
}

impl<E, PC> PCAccumulator<E, PC>
where
    E: Pairing,
    E::ScalarField: RawPrimeField,
    PC: PCScheme<
        E,
        Polynomial = MLE<E::ScalarField>,
        Point = Vec<E::ScalarField>,
        Evaluation = E::ScalarField,
        Commitment = Commitment<E>,
    >,
{
    /// Create an empty accumulator.
    pub(super) fn new(num_var: usize) -> Self {
        Self {
            num_var,
            polynomials: vec![],
            commitments: vec![],
            points: vec![],
        }
    }

    /// Push a new evaluation point into the accumulator
    pub(super) fn insert_poly_and_points(
        &mut self,
        poly: &PC::Polynomial,
        commit: &PC::Commitment,
        point: &PC::Point,
    ) {
        assert!(poly.num_vars() == point.len());
        assert!(poly.num_vars() == self.num_var);

        self.polynomials.push(poly.clone());
        self.points.push(point.clone());
        self.commitments.push(*commit);
    }

    /// Batch open all the points over a merged polynomial.
    /// A simple wrapper of PC::multi_open
    pub(super) fn multi_open(
        &self,
        ck: impl Borrow<PC::CommitterKey>,
        transcript: &mut IOPTranscript<E::ScalarField>,
    ) -> Result<PC::BatchProof, ScribeErrors> {
        let start = start_timer!(|| "Multi-open");
        let evals_time = start_timer!(|| "Evaluations");
        let evals = self
            .polynomials
            .par_iter()
            .zip(&self.points)
            .map(|(poly, point)| {
                let pool = rayon::ThreadPoolBuilder::new()
                    .num_threads(4)
                    .build()
                    .unwrap();
                pool.install(|| poly.evaluate(point).unwrap())
            })
            .collect::<Vec<_>>();
        end_timer!(evals_time);
        let res = PC::multi_open(
            ck.borrow(),
            self.polynomials.as_ref(),
            self.points.as_ref(),
            &evals,
            transcript,
        )?;
        end_timer!(start);
        Ok(res)
    }
}

/// Sanity-check for Scribe SNARK proving
pub(crate) fn prover_sanity_check<F: RawPrimeField + CanonicalDeserialize + CanonicalSerialize>(
    params: &ScribeConfig,
    pub_input: &[F],
    witnesses: Vec<MLE<F>>,
) -> Result<(), ScribeErrors> {
    // public input length must be no greater than num_constraints
    if pub_input.len() > params.num_constraints {
        return Err(ScribeErrors::InvalidProver(format!(
            "Public input length {} is greater than num constraits {}",
            pub_input.len(),
            params.num_pub_input
        )));
    }

    // public input length
    if pub_input.len() != params.num_pub_input {
        return Err(ScribeErrors::InvalidProver(format!(
            "Public input length is not correct: got {}, expect {}",
            pub_input.len(),
            params.num_pub_input
        )));
    }
    if !pub_input.len().is_power_of_two() {
        return Err(ScribeErrors::InvalidProver(format!(
            "Public input length is not power of two: got {}",
            pub_input.len(),
        )));
    }

    // witnesses length
    for (i, w) in witnesses.iter().enumerate() {
        if 1 << w.num_vars() != params.num_constraints {
            return Err(ScribeErrors::InvalidProver(format!(
                "{}-th witness length is not correct: got {}, expect {}",
                i,
                1 << w.num_vars(),
                params.num_constraints
            )));
        }
    }
    // check public input matches witness[0]'s first 2^ell elements
    FileVec::from_iter(pub_input.to_vec())
        .iter()
        .zip(witnesses[0].evals().iter())
        .for_each(|(pi, w)| {
            if pi != w {
                panic!(
                    "Public input does not match witness[0]: got {:?}, expect {:?}",
                    pi, w
                );
            }
        });

    Ok(())
}

/// build `f(w_0(x),...w_d(x))` where `f` is the constraint polynomial
/// i.e., `f(a, b, c) = q_l a(x) + q_r b(x) + q_m a(x)b(x) - q_o c(x)` in
/// vanilla plonk
pub(crate) fn build_f<F: RawPrimeField>(
    gates: &CustomizedGates,
    num_vars: usize,
    selector_mles: &[MLE<F>],
    witness_mles: &[MLE<F>],
) -> Result<VirtualPolynomial<F>, ScribeErrors> {
    // TODO: check that selector and witness lengths match what is in
    // the gate definition

    for selector_mle in selector_mles.iter() {
        if selector_mle.num_vars() != num_vars {
            return Err(ScribeErrors::InvalidParameters(format!(
                "selector has different number of vars: {} vs {}",
                selector_mle.num_vars(),
                num_vars
            )));
        }
    }

    for witness_mle in witness_mles.iter() {
        if witness_mle.num_vars() != num_vars {
            return Err(ScribeErrors::InvalidParameters(format!(
                "selector has different number of vars: {} vs {}",
                witness_mle.num_vars(),
                num_vars
            )));
        }
    }

    let mut res = VirtualPolynomial::<F>::new(num_vars);

    for (coeff, selector, witnesses) in gates.gates.iter() {
        let coeff_fr = coeff.into_fp();
        let mut mle_list = vec![];
        if let Some(s) = *selector {
            mle_list.push(selector_mles[s].clone())
        }
        for &witness in witnesses.iter() {
            mle_list.push(witness_mles[witness].clone())
        }
        res.add_mles(mle_list, coeff_fr)?;
    }

    Ok(res)
}

pub(crate) fn eval_f<F: PrimeField>(
    gates: &CustomizedGates,
    selector_evals: &[F],
    witness_evals: &[F],
) -> Result<F, ScribeErrors> {
    let mut res = F::zero();
    for (coeff, selector, witnesses) in gates.gates.iter() {
        let mut cur_value: F = coeff.into_fp();
        cur_value *= match selector {
            Some(s) => selector_evals[*s],
            None => F::one(),
        };
        for &witness in witnesses.iter() {
            cur_value *= witness_evals[witness]
        }
        res += cur_value;
    }
    Ok(res)
}

// check perm check subclaim:
// proof.witness_perm_check_eval ?= perm_check_sub_claim.expected_eval
// Q(x) := prod(x) - p1(x) * p2(x)
//     + alpha * frac(x) * g1(x) * ... * gk(x)
//     - alpha * f1(x) * ... * fk(x)
//
// where p1(x) = (1-x1) * frac(x2, ..., xn, 0)
//             + x1 * prod(x2, ..., xn, 0),
// and p2(x) = (1-x1) * frac(x2, ..., xn, 1)
//           + x1 * prod(x2, ..., xn, 1)
// and gi(x) = (wi(x) + beta * perms_i(x) + gamma)
// and fi(x) = (wi(x) + beta * s_id_i(x) + gamma)
#[allow(clippy::too_many_arguments)]
pub(crate) fn eval_perm_gate<F: PrimeField>(
    prod_evals: &[F],
    frac_evals: &[F],
    witness_perm_evals: &[F],
    id_evals: &[F],
    perm_evals: &[F],
    alpha: F,
    beta: F,
    gamma: F,
    x1: F,
) -> Result<F, ScribeErrors> {
    let p1_eval = frac_evals[1] + x1 * (prod_evals[1] - frac_evals[1]);
    let p2_eval = frac_evals[2] + x1 * (prod_evals[2] - frac_evals[2]);
    let mut f_prod_eval = F::one();
    for (&w_eval, &id_eval) in witness_perm_evals.iter().zip(id_evals.iter()) {
        f_prod_eval *= w_eval + beta * id_eval + gamma;
    }
    let mut g_prod_eval = F::one();
    for (&w_eval, &p_eval) in witness_perm_evals.iter().zip(perm_evals.iter()) {
        g_prod_eval *= w_eval + beta * p_eval + gamma;
    }
    let res =
        prod_evals[0] - p1_eval * p2_eval + alpha * (frac_evals[0] * g_prod_eval - f_prod_eval);
    Ok(res)
}

#[cfg(test)]
mod test {
    use super::*;
    use ark_bls12_381::Fr;

    #[test]
    fn test_build_gate() -> Result<(), ScribeErrors> {
        test_build_gate_helper::<Fr>()
    }

    fn test_build_gate_helper<F: RawPrimeField>() -> Result<(), ScribeErrors> {
        let num_vars = 2;

        // ql = 3x1x2 + 2x2 whose evaluations are
        // 0, 0 |-> 0
        // 0, 1 |-> 2
        // 1, 0 |-> 0
        // 1, 1 |-> 5
        let ql_eval = vec![F::zero(), F::from(2u64), F::zero(), F::from(5u64)];
        let ql = MLE::from_evals_vec(ql_eval, 2);

        // W1 = x1x2 + x1 whose evaluations are
        // 0, 0 |-> 0
        // 0, 1 |-> 0
        // 1, 0 |-> 1
        // 1, 1 |-> 2
        let w_eval = vec![F::zero(), F::zero(), F::from(1u64), F::from(2u64)];
        let w1 = MLE::from_evals_vec(w_eval, 2);

        // W2 = x1 + x2 whose evaluations are
        // 0, 0 |-> 0
        // 0, 1 |-> 1
        // 1, 0 |-> 1
        // 1, 1 |-> 2
        let w_eval = vec![F::zero(), F::one(), F::from(1u64), F::from(2u64)];
        let w2 = MLE::from_evals_vec(w_eval, 2);

        // Example:
        //     q_L(X) * W_1(X)^5 - W_2(X)
        // is represented as
        // vec![
        //     ( 1,    Some(id_qL),    vec![id_W1, id_W1, id_W1, id_W1, id_W1]),
        //     (-1,    None,           vec![id_W2])
        // ]
        let gates = CustomizedGates {
            gates: vec![
                (1.into(), Some(0), vec![0, 0, 0, 0, 0]),
                ((-1).into(), None, vec![1]),
            ],
        };
        let f = build_f(&gates, num_vars, &[ql.clone()], &[w1.clone(), w2.clone()])?;

        // Sanity check on build_f
        // f(0, 0) = 0
        assert_eq!(f.evaluate(&[F::zero(), F::zero()])?, F::zero());
        // f(0, 1) = 2 * 0^5 + (-1) * 1 = -1
        assert_eq!(f.evaluate(&[F::zero(), F::one()])?, -F::one());
        // f(1, 0) = 0 * 1^5 + (-1) * 1 = -1
        assert_eq!(f.evaluate(&[F::one(), F::zero()])?, -F::one());
        // f(1, 1) = 5 * 2^5 + (-1) * 2 = 158
        assert_eq!(f.evaluate(&[F::one(), F::one()])?, F::from(158u64));

        // test eval_f
        {
            let point = [F::zero(), F::zero()];
            let selector_evals = ql.evaluate(&point).unwrap();
            let witness_evals = [w1.evaluate(&point).unwrap(), w2.evaluate(&point).unwrap()];
            let eval_f = eval_f(&gates, &[selector_evals], &witness_evals)?;
            // f(0, 0) = 0
            assert_eq!(eval_f, F::zero());
        }
        {
            let point = [F::zero(), F::one()];
            let selector_evals = ql.evaluate(&point).unwrap();
            let witness_evals = [w1.evaluate(&point).unwrap(), w2.evaluate(&point).unwrap()];
            let eval_f = eval_f(&gates, &[selector_evals], &witness_evals)?;
            // f(0, 1) = 2 * 0^5 + (-1) * 1 = -1
            assert_eq!(eval_f, -F::one());
        }
        {
            let point = [F::one(), F::zero()];
            let selector_evals = ql.evaluate(&point).unwrap();
            let witness_evals = [w1.evaluate(&point).unwrap(), w2.evaluate(&point).unwrap()];
            let eval_f = eval_f(&gates, &[selector_evals], &witness_evals)?;
            // f(1, 0) = 0 * 1^5 + (-1) * 1 = -1
            assert_eq!(eval_f, -F::one());
        }
        {
            let point = [F::one(), F::one()];
            let selector_evals = ql.evaluate(&point).unwrap();
            let witness_evals = [w1.evaluate(&point).unwrap(), w2.evaluate(&point).unwrap()];
            let eval_f = eval_f(&gates, &[selector_evals], &witness_evals)?;
            // f(1, 1) = 5 * 2^5 + (-1) * 2 = 158
            assert_eq!(eval_f, F::from(158u64));
        }
        Ok(())
    }
}
