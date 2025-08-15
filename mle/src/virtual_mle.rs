use crate::{EqEvalIter, LexicoIter, MLE, SmallMLE};
use rayon::{
    iter::{Copied, MinLen},
    prelude::*,
};
use scribe_streams::{
    iterator::{self, BatchedIterator, BatchedIteratorAssocTypes, Repeat},
    serialize::RawPrimeField,
};

use crate::util::eq_eval;

#[derive(Clone, PartialEq, Eq)]
pub enum VirtualMLE<F: RawPrimeField> {
    MLE(MLE<F>),
    Small(SmallMLE<F>),
    EqAtPoint {
        num_vars: usize,
        point: Vec<F>,
        fixed_vars: Vec<F>,
    },
    Lexicographic {
        num_vars: usize,
        offset: F,
        step_size: F,
    },
    Constant {
        value: F,
        num_vars: usize,
    },
}

impl<F: RawPrimeField> VirtualMLE<F> {
    pub fn eq_x_r(point: &[F]) -> Self {
        Self::EqAtPoint {
            num_vars: point.len(),
            point: point.to_vec(),
            fixed_vars: vec![],
        }
    }

    pub fn lexicographic(num_vars: usize, offset: F) -> Self {
        let step_size = F::one();
        Self::Lexicographic {
            num_vars,
            offset,
            step_size,
        }
    }

    pub fn constant(value: F, num_vars: usize) -> Self {
        Self::Constant { value, num_vars }
    }

    pub fn num_vars(&self) -> usize {
        match self {
            Self::MLE(mle) => mle.num_vars(),
            Self::Small(inner) => inner.num_vars(),
            Self::EqAtPoint { num_vars, .. } => *num_vars,
            Self::Lexicographic { num_vars, .. } => *num_vars,
            Self::Constant { num_vars, .. } => *num_vars,
        }
    }

    pub fn evaluate(&self, point: &[F]) -> Option<F> {
        match self {
            Self::MLE(mle) => mle.evaluate(point),
            Self::Small(inner) => inner.evaluate(point),
            Self::EqAtPoint {
                num_vars,
                fixed_vars,
                point: eq_point,
            } => {
                let mut new_point = fixed_vars.clone();
                new_point.extend(point);
                (point.len() == *num_vars).then(|| eq_eval(eq_point, &new_point).unwrap())
            },
            Self::Lexicographic {
                num_vars,
                offset,
                step_size,
            } => {
                if point.len() != *num_vars {
                    return None;
                }
                let mut res = *offset;
                let mut coeff = F::one();
                for p in point {
                    res += *p * coeff;
                    coeff *= *step_size;
                }
                Some(res)
            },
            Self::Constant { value, num_vars } => {
                if point.len() != *num_vars {
                    None
                } else {
                    Some(*value)
                }
            },
        }
    }

    pub fn evals(&self) -> VirtualMLEIter<'_, F> {
        match self {
            Self::MLE(mle) => VirtualMLEIter::MLE(mle.evals().iter()),
            Self::Small(inner) => VirtualMLEIter::Small {
                iter: inner.evals.iter(),
                buffer: vec![],
            },
            Self::EqAtPoint {
                point, fixed_vars, ..
            } => VirtualMLEIter::EqAtPoint(EqEvalIter::new_with_fixed_vars(
                point.clone(),
                fixed_vars.to_vec(),
            )),
            Self::Lexicographic {
                num_vars,
                offset,
                step_size,
            } => VirtualMLEIter::Lexicographic(LexicoIter::new(*num_vars, *offset, *step_size)),
            Self::Constant { value, num_vars } => VirtualMLEIter::Constant {
                iter: iterator::repeat(*value, 1 << num_vars),
                buffer: vec![],
            },
        }
    }

    pub fn fix_variables(&self, partial_point: &[F]) -> Self {
        match self {
            Self::MLE(mle) => Self::MLE(mle.fix_variables(partial_point)),
            Self::Small(inner) => Self::MLE(inner.fix_variables(partial_point)).into(),
            Self::EqAtPoint {
                num_vars,
                point,
                fixed_vars,
            } => {
                let num_vars = num_vars.checked_sub(partial_point.len()).unwrap();
                let mut fixed_vars = fixed_vars.to_vec();
                fixed_vars.extend(partial_point);
                Self::EqAtPoint {
                    num_vars,
                    point: point.to_vec(),
                    fixed_vars,
                }
            },
            Self::Lexicographic {
                num_vars,
                offset,
                step_size,
            } => {
                let num_vars = num_vars.checked_sub(partial_point.len()).unwrap();
                let mut step_size = *step_size;
                let offset = partial_point.iter().fold(*offset, |acc, x| {
                    let result = acc + *x * step_size;
                    step_size.double_in_place();
                    result
                });
                Self::Lexicographic {
                    num_vars,
                    offset,
                    step_size,
                }
            },
            Self::Constant { value, num_vars } => {
                let num_vars = num_vars.checked_sub(partial_point.len()).unwrap();
                Self::Constant {
                    value: *value,
                    num_vars,
                }
            },
        }
    }

    pub fn fix_variables_in_place(&mut self, partial_point: &[F]) {
        match self {
            Self::MLE(mle) => mle.fix_variables_in_place(partial_point),
            Self::Small(inner) => {
                *self = Self::MLE(inner.fix_variables(partial_point));
            },
            Self::EqAtPoint {
                num_vars,
                fixed_vars,
                ..
            } => {
                *num_vars = num_vars.checked_sub(partial_point.len()).unwrap();
                fixed_vars.extend(partial_point);
            },
            Self::Lexicographic {
                num_vars,
                step_size,
                offset,
            } => {
                *num_vars = num_vars.checked_sub(partial_point.len()).unwrap();
                *offset = partial_point.iter().fold(*offset, |acc, x| {
                    let result = acc + *x * *step_size;
                    step_size.double_in_place();
                    result
                });
            },
            Self::Constant { num_vars, .. } => {
                *num_vars = num_vars.checked_sub(partial_point.len()).unwrap();
            },
        }
    }

    /// Creates multiple identity permutation streams equal to the number of witness streams
    /// Identity permutations are continuous from one to another
    #[inline(always)]
    pub fn identity_permutations(num_vars: usize, num_chunks: usize) -> Vec<Self> {
        let shift = F::from(1u64 << num_vars);

        (0..num_chunks as u64)
            .map(|chunk_idx| {
                let offset = F::from(chunk_idx) * shift;
                Self::Lexicographic {
                    num_vars,
                    offset,
                    step_size: F::one(),
                }
            })
            .collect()
    }
}

impl<F: RawPrimeField> From<MLE<F>> for VirtualMLE<F> {
    fn from(mle: MLE<F>) -> Self {
        Self::MLE(mle)
    }
}

impl<F: RawPrimeField> From<SmallMLE<F>> for VirtualMLE<F> {
    fn from(mle: SmallMLE<F>) -> Self {
        Self::Small(mle)
    }
}

impl<F: RawPrimeField> PartialEq<MLE<F>> for VirtualMLE<F> {
    fn eq(&self, other: &MLE<F>) -> bool {
        match self {
            Self::MLE(mle) => mle == other,
            _ => false,
        }
    }
}

pub enum VirtualMLEIter<'a, F: RawPrimeField> {
    MLE(scribe_streams::file_vec::Iter<'a, F>),
    Small {
        iter: scribe_streams::file_vec::Iter<'a, u64>,
        buffer: Vec<F>,
    },
    EqAtPoint(EqEvalIter<F>),
    Lexicographic(LexicoIter<F>),
    Constant {
        iter: Repeat<F>,
        buffer: Vec<F>,
    },
}

impl<'a, F: RawPrimeField> BatchedIteratorAssocTypes for VirtualMLEIter<'a, F> {
    type Item = F;
    type Batch<'b> = MinLen<Copied<rayon::slice::Iter<'b, F>>>;
}

impl<'a, F: RawPrimeField> BatchedIterator for VirtualMLEIter<'a, F> {
    fn next_batch<'b>(&'b mut self) -> Option<Self::Batch<'b>> {
        match self {
            Self::MLE(mle) => mle.next_batch(),
            Self::Small { iter, buffer } => {
                buffer.clear();
                iter.next_batch().map(|b| {
                    b.map(F::from).collect_into_vec(buffer);
                    buffer.par_iter().copied().with_min_len(1 << 12)
                })
            },
            Self::EqAtPoint(e) => e.next_batch(),
            Self::Lexicographic(l) => l.next_batch(),
            Self::Constant { iter, buffer } => iter.next_batch().map(|batch| {
                batch.collect_into_vec(buffer);
                buffer.par_iter().copied().with_min_len(1 << 12)
            }),
        }
    }

    fn len(&self) -> Option<usize> {
        match self {
            Self::MLE(mle) => mle.len(),
            Self::Small { iter, .. } => iter.len(),
            Self::EqAtPoint(e) => e.len(),
            Self::Lexicographic(l) => l.len(),
            Self::Constant { iter, .. } => iter.len(),
        }
    }
}

pub enum VirtualMLEIterWithBuf<'a, F: RawPrimeField> {
    MLE(scribe_streams::file_vec::IterWithBuf<'a, F>),
    EqAtPoint(EqEvalIter<F>),
    Lexicographic(LexicoIter<F>),
    Constant {
        iter: Repeat<F>,
        buffer: &'a mut Vec<F>,
    },
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
            Self::Lexicographic(l) => l.next_batch(),
            Self::Constant { iter, buffer } => {
                buffer.clear();
                iter.next_batch().map(|b| {
                    b.collect_into_vec(buffer);
                    buffer.par_iter().copied().with_min_len(1 << 12)
                })
            },
        }
    }

    fn len(&self) -> Option<usize> {
        match self {
            Self::MLE(mle) => mle.len(),
            Self::EqAtPoint(e) => e.len(),
            Self::Lexicographic(l) => l.len(),
            Self::Constant { iter, .. } => iter.len(),
        }
    }
}

impl<F: RawPrimeField> std::fmt::Debug for VirtualMLE<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MLE(_mle) => write!(
                f,
                "VirtualMLE::MLE(is_file = {}; len = {})",
                _mle.evals().is_file(),
                _mle.evals().len()
            ),
            Self::Small(_inner) => write!(
                f,
                "VirtualMLE::Small(is_file = {}; len = {})",
                _inner.evals.is_file(),
                _inner.evals.len()
            ),
            Self::EqAtPoint {
                num_vars,
                fixed_vars,
                ..
            } => write!(
                f,
                "VirtualMLE::EqAtPoint(num_vars: {}, fixed_vars: {:?})",
                num_vars,
                fixed_vars.len()
            ),
            Self::Lexicographic {
                num_vars,
                offset,
                step_size,
            } => write!(
                f,
                "VirtualMLE::Lexicographic(num_vars: {}, offset: {}, step_size: {:?})",
                num_vars, offset, step_size,
            ),
            Self::Constant { value, num_vars } => write!(
                f,
                "VirtualMLE::Constant(num_vars: {}, value: {})",
                num_vars, value
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
