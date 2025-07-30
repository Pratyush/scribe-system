use crate::{EqEvalIter, MLE, eq_iter::EqEvalIterWithBuf};
use rayon::iter::{Copied, MinLen};
use scribe_streams::{
    iterator::{BatchedIterator, BatchedIteratorAssocTypes},
    serialize::RawPrimeField,
};

use crate::util::eq_eval;

#[derive(Clone, PartialEq, Eq)]
pub enum VirtualMLE<F: RawPrimeField> {
    MLE(MLE<F>),
    EqAtPoint {
        num_vars: usize,
        point: Vec<F>,
        fixed_vars: Vec<F>,
    },
}

impl<F: RawPrimeField> VirtualMLE<F> {
    pub fn eq_x_r(point: &[F]) -> Self {
        VirtualMLE::EqAtPoint {
            num_vars: point.len(),
            point: point.to_vec(),
            fixed_vars: vec![],
        }
    }

    pub fn num_vars(&self) -> usize {
        match self {
            VirtualMLE::MLE(mle) => mle.num_vars(),
            VirtualMLE::EqAtPoint { num_vars, .. } => *num_vars,
        }
    }

    pub fn evaluate(&self, point: &[F]) -> Option<F> {
        match self {
            VirtualMLE::MLE(mle) => mle.evaluate(point),
            VirtualMLE::EqAtPoint {
                num_vars,
                fixed_vars,
                point: eq_point,
            } => {
                let mut new_point = fixed_vars.clone();
                new_point.extend(point);
                (point.len() == *num_vars).then(|| eq_eval(eq_point, &new_point).unwrap())
            },
        }
    }

    pub fn evals(&self) -> VirtualMLEIter<'_, F> {
        match self {
            VirtualMLE::MLE(mle) => VirtualMLEIter::MLE(mle.evals().iter()),
            VirtualMLE::EqAtPoint {
                point, fixed_vars, ..
            } => VirtualMLEIter::EqAtPoint(EqEvalIter::new_with_fixed_vars(
                point.clone(),
                fixed_vars.to_vec(),
            )),
        }
    }

    pub fn evals_with_buf<'a>(&'a self, buf: &'a mut Vec<F>) -> VirtualMLEIterWithBuf<'a, F> {
        match self {
            Self::MLE(mle) => VirtualMLEIterWithBuf::MLE(mle.evals().iter_with_buf(buf)),
            Self::EqAtPoint {
                point, fixed_vars, ..
            } => VirtualMLEIterWithBuf::EqAtPoint(EqEvalIterWithBuf::new_with_fixed_vars(
                point.clone(),
                fixed_vars.to_vec(),
                buf,
            )),
        }
    }

    pub fn fix_variables(&self, partial_point: &[F]) -> Self {
        match self {
            VirtualMLE::MLE(mle) => VirtualMLE::MLE(mle.fix_variables(partial_point)),
            VirtualMLE::EqAtPoint {
                num_vars,
                point,
                fixed_vars,
            } => {
                let num_vars = num_vars.checked_sub(partial_point.len()).unwrap();
                let mut fixed_vars = fixed_vars.to_vec();
                fixed_vars.extend(partial_point);
                VirtualMLE::EqAtPoint {
                    num_vars,
                    point: point.to_vec(),
                    fixed_vars,
                }
            },
        }
    }

    pub fn fix_variables_in_place(&mut self, partial_point: &[F]) {
        match self {
            VirtualMLE::MLE(mle) => mle.fix_variables_in_place(partial_point),
            VirtualMLE::EqAtPoint {
                num_vars,
                fixed_vars,
                ..
            } => {
                *num_vars = num_vars.checked_sub(partial_point.len()).unwrap();
                fixed_vars.extend(partial_point);
            },
        }
    }
}

impl<F: RawPrimeField> From<MLE<F>> for VirtualMLE<F> {
    fn from(mle: MLE<F>) -> Self {
        VirtualMLE::MLE(mle)
    }
}

impl<F: RawPrimeField> PartialEq<MLE<F>> for VirtualMLE<F> {
    fn eq(&self, other: &MLE<F>) -> bool {
        match self {
            VirtualMLE::MLE(mle) => mle == other,
            VirtualMLE::EqAtPoint { .. } => false,
        }
    }
}

pub enum VirtualMLEIter<'a, F: RawPrimeField> {
    MLE(scribe_streams::file_vec::Iter<'a, F>),
    EqAtPoint(EqEvalIter<F>),
}

impl<'a, F: RawPrimeField> BatchedIteratorAssocTypes for VirtualMLEIter<'a, F> {
    type Item = F;
    type Batch<'b> = MinLen<rayon::vec::IntoIter<F>>;
}

impl<'a, F: RawPrimeField> BatchedIterator for VirtualMLEIter<'a, F> {
    fn next_batch<'b>(&'b mut self) -> Option<Self::Batch<'b>> {
        match self {
            VirtualMLEIter::MLE(mle) => mle.next_batch(),
            VirtualMLEIter::EqAtPoint(e) => e.next_batch(),
        }
    }

    fn len(&self) -> Option<usize> {
        match self {
            VirtualMLEIter::MLE(mle) => mle.len(),
            VirtualMLEIter::EqAtPoint(e) => e.len(),
        }
    }
}

pub enum VirtualMLEIterWithBuf<'a, F: RawPrimeField> {
    MLE(scribe_streams::file_vec::IterWithBuf<'a, F>),
    EqAtPoint(EqEvalIterWithBuf<'a, F>),
}

impl<'a, F: RawPrimeField> BatchedIteratorAssocTypes for VirtualMLEIterWithBuf<'a, F> {
    type Item = F;
    type Batch<'b> = MinLen<Copied<rayon::slice::Iter<'b, F>>>;
}

impl<'a, F: RawPrimeField> BatchedIterator for VirtualMLEIterWithBuf<'a, F> {
    fn next_batch<'b>(&'b mut self) -> Option<Self::Batch<'b>> {
        match self {
            Self::MLE(mle) => mle.next_batch(),
            Self::EqAtPoint(e) => e.next_batch(),
        }
    }

    fn len(&self) -> Option<usize> {
        match self {
            Self::MLE(mle) => mle.len(),
            Self::EqAtPoint(e) => e.len(),
        }
    }
}

impl<F: RawPrimeField> std::fmt::Debug for VirtualMLE<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VirtualMLE::MLE(_mle) => write!(f, "VirtualMLE::MLE(..)"),
            VirtualMLE::EqAtPoint {
                num_vars,
                point,
                fixed_vars,
            } => write!(
                f,
                "VirtualMLE::EqAtPoint(num_vars: {}, point: {:?}, fixed_vars: {:?})",
                num_vars, point, fixed_vars
            ),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use ark_bls12_381::Fr as F;
    use ark_ff::UniformRand;

    #[test]
    fn test_virtual_mle() {
        let mut rng = ark_std::test_rng();
        for nv in 3..=20 {
            let mle = MLE::rand(nv, &mut rng);
            let point = vec![F::rand(&mut rng); nv];
            let virtual_mle = VirtualMLE::from(mle.clone());

            assert_eq!(virtual_mle.num_vars(), nv);
            assert_eq!(virtual_mle.evaluate(&point), mle.evaluate(&point));
            for fixed_nv in 0..nv {
                let partial_point = vec![F::rand(&mut rng); fixed_nv];
                let v_mle = virtual_mle.fix_variables(&partial_point);
                let mle = mle.fix_variables(&partial_point);
                assert_eq!(v_mle.evals().to_vec(), mle.evals().iter().to_vec());
            }
        }
    }

    #[test]
    fn test_virtual_eq() {
        let mut rng = ark_std::test_rng();
        for nv in 3..=20 {
            let r = (0..nv).map(|_| F::rand(&mut rng)).collect::<Vec<_>>();
            let mle = MLE::eq_x_r(&r);
            let virtual_mle = VirtualMLE::eq_x_r(&r);

            let point = (0..nv).map(|_| F::rand(&mut rng)).collect::<Vec<_>>();
            assert_eq!(virtual_mle.num_vars(), nv);
            assert_eq!(virtual_mle.evaluate(&point), mle.evaluate(&point));

            for fixed_nv in 0..nv {
                let partial_point = vec![F::rand(&mut rng); fixed_nv];
                let v_mle = virtual_mle.fix_variables(&partial_point);
                let mle = mle.fix_variables(&partial_point);
                let v_mle_evals = v_mle.evals().to_vec();
                let mle_evals = mle.evals().iter().to_vec();
                assert_eq!(
                    v_mle_evals.len(),
                    mle_evals.len(),
                    "failed for num_vars = {nv} and num_fixed_vars = {fixed_nv}"
                );
                for (i, (a, b)) in v_mle_evals.iter().zip(&mle_evals).enumerate() {
                    assert_eq!(
                        a, b,
                        "failed for num_vars = {nv} at {i} and num_fixed_vars = {fixed_nv}"
                    );
                }
            }
        }
    }

    #[test]
    fn test_fix_variables_in_place() {
        let mut rng = ark_std::test_rng();
        for nv in 3..=20 {
            let r = (0..nv).map(|_| F::rand(&mut rng)).collect::<Vec<_>>();
            let mle = MLE::eq_x_r(&r);
            let virtual_mle = VirtualMLE::eq_x_r(&r);

            let point = (0..nv).map(|_| F::rand(&mut rng)).collect::<Vec<_>>();
            assert_eq!(virtual_mle.num_vars(), nv);
            assert_eq!(virtual_mle.evaluate(&point), mle.evaluate(&point));
            for fixed_nv in 0..nv {
                let mut virtual_mle = virtual_mle.clone();
                let mut mle = mle.deep_copy();
                let partial_point = vec![F::rand(&mut rng); fixed_nv];
                virtual_mle.fix_variables_in_place(&partial_point);
                mle.fix_variables_in_place(&partial_point);
                assert_eq!(virtual_mle.evals().to_vec(), mle.evals().iter().to_vec());
            }
        }
    }

    #[test]
    fn eq_edge_case() {
        use std::str::FromStr;
        let points = [
            [
                F::from_str(
                    "45909269702051616127763153969329798362276091327351889759971200635134300168589",
                )
                .unwrap(),
                F::from_str(
                    "45689589183091439082645544067987265580924333006197028415140741742407839195752",
                )
                .unwrap(),
            ],
            [
                F::from_str("0").unwrap(),
                F::from_str(
                    "45909269702051616127763153969329798362276091327351889759971200635134300168589",
                )
                .unwrap(),
            ],
            [
                F::from_str("1").unwrap(),
                F::from_str(
                    "45909269702051616127763153969329798362276091327351889759971200635134300168589",
                )
                .unwrap(),
            ],
            [F::from_str("0").unwrap(), F::from_str("1").unwrap()],
        ];
        for (i, point) in points.iter().enumerate() {
            let mle = MLE::eq_x_r(point);
            let virtual_mle = VirtualMLE::eq_x_r(point);
            println!("evaluation result MLE: {}", mle.evaluate(point).unwrap());
            println!(
                "Evaluation result VirtualMLE: {}",
                virtual_mle.evaluate(point).unwrap()
            );
            println!(
                "Evaluation result eq_x_r: {}",
                eq_eval(point, point).unwrap()
            );
            assert_eq!(virtual_mle.num_vars(), 2);
            let vmle_evals = virtual_mle.evals().map(|a| a.to_string()).to_vec();
            let mle_evals = mle.evals().iter().map(|a| a.to_string()).to_vec();
            let point_display = point.iter().map(|x| x.to_string()).collect::<Vec<_>>();
            assert_eq!(
                vmle_evals, mle_evals,
                "failed for point: {point_display:?} at index: {i}",
            )
        }
    }
}
