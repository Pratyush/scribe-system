use crate::hyperplonk::arithmetic::virtual_polynomial::VirtualPolynomial;
use crate::hyperplonk::full_snark::{
    custom_gate::CustomizedGates, errors::HyperPlonkErrors, structs::HyperPlonkParams,
};
use crate::hyperplonk::pcs::prelude::{Commitment, PCSError};
use crate::hyperplonk::pcs::PolynomialCommitmentScheme;
use crate::hyperplonk::transcript::IOPTranscript;
use crate::read_write::{DenseMLPolyStream, ReadWriteStream};
use ark_ec::pairing::Pairing;
use ark_ff::PrimeField;
use ark_std::{end_timer, start_timer};
use std::sync::Mutex;
use std::{borrow::Borrow, sync::Arc};

/// An accumulator structure that holds a polynomial and
/// its opening points
#[derive(Debug)]
pub(super) struct PcsAccumulator<E: Pairing, PCS: PolynomialCommitmentScheme<E>> {
    pub(crate) num_var: usize,
    pub(crate) polynomials: Vec<PCS::Polynomial>,
    pub(crate) commitments: Vec<PCS::Commitment>,
    pub(crate) points: Vec<PCS::Point>,
    pub(crate) evals: Vec<PCS::Evaluation>,
}

impl<E, PCS> PcsAccumulator<E, PCS>
where
    E: Pairing,
    PCS: PolynomialCommitmentScheme<
        E,
        Polynomial = Arc<Mutex<DenseMLPolyStream<E::ScalarField>>>,
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
            evals: vec![],
        }
    }

    /// Push a new evaluation point into the accumulator
    pub(super) fn insert_poly_and_points(
        &mut self,
        poly: &PCS::Polynomial,
        commit: &PCS::Commitment,
        point: &PCS::Point,
    ) {
        let poly_num_vars = poly.lock().unwrap().num_vars;
        assert!(poly_num_vars == point.len());
        assert!(poly_num_vars == self.num_var);

        self.polynomials.push(poly.clone());
        self.points.push(point.clone());
        self.commitments.push(*commit);
    }

    /// Batch open all the points over a merged polynomial.
    /// A simple wrapper of PCS::multi_open
    pub(super) fn multi_open_single_point(
        &self,
        prover_param: impl Borrow<PCS::ProverParam>,
        transcript: &mut IOPTranscript<E::ScalarField>,
    ) -> Result<(PCS::Proof, PCS::Evaluation), PCSError> {
        // default uses the first point and assumes that all points are the same
        // TODO: confirm that all points are the same
        Ok(PCS::multi_open_single_point(
            prover_param.borrow(),
            self.polynomials.as_ref(),
            self.points[0].clone(),
            transcript,
        )?)
    }
}

/// Sanity-check for HyperPlonk SNARK proving
pub(crate) fn prover_sanity_check<F: PrimeField>(
    params: &HyperPlonkParams,
    pub_input: &[F],
    witnesses: Vec<Arc<Mutex<DenseMLPolyStream<F>>>>,
) -> Result<(), HyperPlonkErrors> {
    // public input length must be no greater than num_constraints
    if pub_input.len() > params.num_constraints {
        return Err(HyperPlonkErrors::InvalidProver(format!(
            "Public input length {} is greater than num constraits {}",
            pub_input.len(),
            params.num_pub_input
        )));
    }

    // public input length
    if pub_input.len() != params.num_pub_input {
        return Err(HyperPlonkErrors::InvalidProver(format!(
            "Public input length is not correct: got {}, expect {}",
            pub_input.len(),
            params.num_pub_input
        )));
    }
    if !pub_input.len().is_power_of_two() {
        return Err(HyperPlonkErrors::InvalidProver(format!(
            "Public input length is not power of two: got {}",
            pub_input.len(),
        )));
    }

    // witnesses length
    for (i, w) in witnesses.iter().enumerate() {
        if 1 << w.lock().unwrap().num_vars != params.num_constraints {
            return Err(HyperPlonkErrors::InvalidProver(format!(
                "{}-th witness length is not correct: got {}, expect {}",
                i,
                w.lock().unwrap().num_vars,
                params.num_constraints
            )));
        }
    }
    // check public input matches witness[0]'s first 2^ell elements
    let mut pub_stream = witnesses[0].lock().unwrap();

    #[cfg(debug_assertions)]
    println!("public input len: {}", pub_input.len());

    let pub_stream_result: Vec<F> = (0..pub_input.len())
        .map(|i| {
            #[cfg(debug_assertions)]
            println!("public input number {}", i);

            pub_stream.read_next().unwrap()
        })
        .collect();
    pub_stream.read_restart();
    drop(pub_stream);

    for (i, (&pi, w)) in pub_input.iter().zip(pub_stream_result).enumerate() {
        if pi != w {
            return Err(HyperPlonkErrors::InvalidProver(format!(
                "The {:?}-th public input {:?} does not match witness[0] {:?}",
                i, pi, w
            )));
        }
    }

    Ok(())
}

/// build `f(w_0(x),...w_d(x))` where `f` is the constraint polynomial
/// i.e., `f(a, b, c) = q_l a(x) + q_r b(x) + q_m a(x)b(x) - q_o c(x)` in
/// vanilla plonk
pub(crate) fn build_f<F: PrimeField>(
    gates: &CustomizedGates,
    num_vars: usize,
    selector_mles: &[Arc<Mutex<DenseMLPolyStream<F>>>],
    witness_mles: &[Arc<Mutex<DenseMLPolyStream<F>>>],
) -> Result<VirtualPolynomial<F>, HyperPlonkErrors> {
    let start = start_timer!(|| "build gate identity polynomial");

    // TODO: check that selector and witness lengths match what is in
    // the gate definition

    for selector_mle in selector_mles.iter() {
        let selector_mle = selector_mle.lock().expect("lock failed");
        if selector_mle.num_vars != num_vars {
            return Err(HyperPlonkErrors::InvalidParameters(format!(
                "selector has different number of vars: {} vs {}",
                selector_mle.num_vars, num_vars
            )));
        }
        drop(selector_mle)
    }

    for witness_mle in witness_mles.iter() {
        let witness_mle = witness_mle.lock().expect("lock failed");
        if witness_mle.num_vars != num_vars {
            return Err(HyperPlonkErrors::InvalidParameters(format!(
                "selector has different number of vars: {} vs {}",
                witness_mle.num_vars, num_vars
            )));
        }
        drop(witness_mle)
    }

    let mut res = VirtualPolynomial::<F>::new(num_vars);

    for (coeff, selector, witnesses) in gates.gates.iter() {
        let coeff_fr = if *coeff < 0 {
            -F::from(-*coeff as u64)
        } else {
            F::from(*coeff as u64)
        };
        let mut mle_list = vec![];
        if let Some(s) = *selector {
            mle_list.push(selector_mles[s].clone())
        }
        for &witness in witnesses.iter() {
            mle_list.push(witness_mles[witness].clone())
        }
        res.add_mle_list(mle_list, coeff_fr)?;
    }

    end_timer!(start);

    Ok(res)
}

pub(crate) fn eval_f<F: PrimeField>(
    gates: &CustomizedGates,
    selector_evals: &[F],
    witness_evals: &[F],
) -> Result<F, HyperPlonkErrors> {
    let mut res = F::zero();
    for (coeff, selector, witnesses) in gates.gates.iter() {
        let mut cur_value = if *coeff < 0 {
            -F::from(-*coeff as u64)
        } else {
            F::from(*coeff as u64)
        };
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

pub fn memory_traces() {
    #[cfg(all(feature = "print-trace", target_os = "linux"))]
    {
        // virtual memory page size can be obtained also with:
        // $ getconf PAGE_SIZE    # alternatively, PAGESIZE
        let pagesize = unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize };
        let mut previous_memory = 0usize;
        ark_std::thread::spawn(move || loop {
            // obtain the total virtual memory size, in pages
            // and convert it to bytes
            let pages_used = procinfo::pid::statm_self().unwrap().data;
            let memory_used = pagesize * pages_used;
            // if the memory changed of more than 10kibibytes from last clock tick,
            // then log it.
            if (memory_used - previous_memory) > 10 << 10 {
                log::debug!("memory (statm.data): {}B", memory_used);
                previous_memory = memory_used;
            }
            // sleep for 10 seconds
            ark_std::thread::sleep(std::time::Duration::from_secs(10))
        });
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::read_write::{copy_mle, DenseMLPolyStream};
    use ark_bls12_381::Fr;
    use ark_ff::PrimeField;
    use std::sync::Mutex;

    // TODO: this is currently failing, fix this
    #[test]
    fn test_build_gate() -> Result<(), HyperPlonkErrors> {
        test_build_gate_helper::<Fr>()
    }

    fn test_build_gate_helper<F: PrimeField>() -> Result<(), HyperPlonkErrors> {
        let num_vars = 2;

        // ql = 3x1x2 + 2x2 whose evaluations are
        // 0, 0 |-> 0
        // 0, 1 |-> 2
        // 1, 0 |-> 0
        // 1, 1 |-> 5
        let ql_eval = vec![F::zero(), F::from(2u64), F::zero(), F::from(5u64)];
        let ql = Arc::new(Mutex::new(DenseMLPolyStream::from_evaluations_vec(
            2, ql_eval, None, None,
        )));

        // W1 = x1x2 + x1 whose evaluations are
        // 0, 0 |-> 0
        // 0, 1 |-> 0
        // 1, 0 |-> 1
        // 1, 1 |-> 2
        let w_eval = vec![F::zero(), F::zero(), F::from(1u64), F::from(2u64)];
        let w1 = Arc::new(Mutex::new(DenseMLPolyStream::from_evaluations_vec(
            2, w_eval, None, None,
        )));

        // W2 = x1 + x2 whose evaluations are
        // 0, 0 |-> 0
        // 0, 1 |-> 1
        // 1, 0 |-> 1
        // 1, 1 |-> 2
        let w_eval = vec![F::zero(), F::one(), F::from(1u64), F::from(2u64)];
        let w2 = Arc::new(Mutex::new(DenseMLPolyStream::from_evaluations_vec(
            2, w_eval, None, None,
        )));

        // Example:
        //     q_L(X) * W_1(X)^5 - W_2(X)
        // is represented as
        // vec![
        //     ( 1,    Some(id_qL),    vec![id_W1, id_W1, id_W1, id_W1, id_W1]),
        //     (-1,    None,           vec![id_W2])
        // ]
        let gates = CustomizedGates {
            gates: vec![(1, Some(0), vec![0, 0, 0, 0, 0]), (-1, None, vec![1])],
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
            let ql = copy_mle(&ql, None, None);
            let w1 = copy_mle(&w1, None, None);
            let w2 = copy_mle(&w2, None, None);
            let mut ql = ql.lock().unwrap();
            let mut w1 = w1.lock().unwrap();
            let mut w2 = w2.lock().unwrap();
            let point = [F::zero(), F::zero()];
            let selector_evals = ql.evaluate(&point).unwrap();
            let witness_evals = [w1.evaluate(&point).unwrap(), w2.evaluate(&point).unwrap()];
            let eval_f = eval_f(&gates, &[selector_evals], &witness_evals)?;
            // f(0, 0) = 0
            assert_eq!(eval_f, F::zero());
        }
        {
            let ql = copy_mle(&ql, None, None);
            let w1 = copy_mle(&w1, None, None);
            let w2 = copy_mle(&w2, None, None);
            let mut ql = ql.lock().unwrap();
            let mut w1 = w1.lock().unwrap();
            let mut w2 = w2.lock().unwrap();
            let point = [F::zero(), F::one()];
            let selector_evals = ql.evaluate(&point).unwrap();
            let witness_evals = [w1.evaluate(&point).unwrap(), w2.evaluate(&point).unwrap()];
            let eval_f = eval_f(&gates, &[selector_evals], &witness_evals)?;
            // f(0, 1) = 2 * 0^5 + (-1) * 1 = -1
            assert_eq!(eval_f, -F::one());
        }
        {
            let ql = copy_mle(&ql, None, None);
            let w1 = copy_mle(&w1, None, None);
            let w2 = copy_mle(&w2, None, None);
            let mut ql = ql.lock().unwrap();
            let mut w1 = w1.lock().unwrap();
            let mut w2 = w2.lock().unwrap();
            let point = [F::one(), F::zero()];
            let selector_evals = ql.evaluate(&point).unwrap();
            let witness_evals = [w1.evaluate(&point).unwrap(), w2.evaluate(&point).unwrap()];
            let eval_f = eval_f(&gates, &[selector_evals], &witness_evals)?;
            // f(1, 0) = 0 * 1^5 + (-1) * 1 = -1
            assert_eq!(eval_f, -F::one());
        }
        {
            let ql = copy_mle(&ql, None, None);
            let w1 = copy_mle(&w1, None, None);
            let w2 = copy_mle(&w2, None, None);
            let mut ql = ql.lock().unwrap();
            let mut w1 = w1.lock().unwrap();
            let mut w2 = w2.lock().unwrap();
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
