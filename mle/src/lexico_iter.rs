use ark_ff::Field;
use rayon::{iter::MinLen, prelude::*};
use scribe_streams::{
    BUFFER_SIZE,
    iterator::{BatchedIterator, BatchedIteratorAssocTypes},
};

pub struct LexicoIterInner<F: Field> {
    next_value: F,
    step: F,
    remaining: usize,
    nv: usize,
}

impl<F: Field> LexicoIterInner<F> {
    pub fn new(nv: usize, offset: F, step: F) -> Self {
        Self {
            nv,
            next_value: offset,
            step,
            remaining: 1 << nv,
        }
    }

    #[inline]
    pub fn next_batch_helper(&mut self, out: &mut Vec<F>) -> Option<()> {
        let total_num_evals = 1 << self.nv;
        if self.remaining == 0 {
            return None;
        } else {
            let batch_size = total_num_evals.min(BUFFER_SIZE);
            let batch_start = self.next_value;
            let batch_end = self.next_value + self.step * F::from(batch_size as u64);
            let chunk_starts = (0..batch_size as u64)
                .step_by(CHUNK_SIZE)
                .map(|i| batch_start + self.step * F::from(i))
                .collect::<Vec<_>>();
            out.clear();

            out.par_extend(
                chunk_starts
                    .into_par_iter()
                    .enumerate()
                    .flat_map(|(i, start)| {
                        let mut acc = start;
                        (0..CHUNK_SIZE.min(batch_size - i * CHUNK_SIZE))
                            .map(|_| {
                                let val = acc;
                                acc += self.step;
                                val
                            })
                            .collect::<Vec<_>>()
                    }),
            );
            self.next_value = batch_end;
            self.remaining -= batch_size;
            Some(())
        }
    }
}

const CHUNK_SIZE: usize = if BUFFER_SIZE < (1 << 14) {
    BUFFER_SIZE
} else {
    1 << 14
};

pub struct LexicoIter<F: Field>(LexicoIterInner<F>);

impl<F: Field> LexicoIter<F> {
    pub fn new(nv: usize, offset: F, step: F) -> Self {
        Self(LexicoIterInner::new(nv, offset, step))
    }
}

impl<F: Field> BatchedIteratorAssocTypes for LexicoIter<F> {
    type Item = F;
    type Batch<'b> = MinLen<rayon::vec::IntoIter<F>>;
}
impl<F: Field> BatchedIterator for LexicoIter<F> {
    fn next_batch(&mut self) -> Option<Self::Batch<'_>> {
        let mut buffer = Vec::with_capacity(BUFFER_SIZE);
        self.0.next_batch_helper(&mut buffer)?;
        Some(buffer.into_par_iter().with_min_len(1 << 12))
    }

    fn len(&self) -> Option<usize> {
        Some(self.0.remaining)
    }
}

pub struct LexicoIterWithBuf<'a, F: Field> {
    inner: LexicoIterInner<F>,
    buffer: &'a mut Vec<F>,
}

impl<'a, F: Field> LexicoIterWithBuf<'a, F> {
    pub fn new(nv: usize, offset: F, step: F, buffer: &'a mut Vec<F>) -> Self {
        Self {
            inner: LexicoIterInner::new(nv, offset, step),
            buffer,
        }
    }
}

impl<'a, F: Field> BatchedIteratorAssocTypes for LexicoIterWithBuf<'a, F> {
    type Item = F;
    type Batch<'b> = MinLen<rayon::iter::Copied<rayon::slice::Iter<'b, F>>>;
}
impl<'a, F: Field> BatchedIterator for LexicoIterWithBuf<'a, F> {
    fn next_batch(&mut self) -> Option<Self::Batch<'_>> {
        self.inner.next_batch_helper(self.buffer)?;
        Some(self.buffer.par_iter().copied().with_min_len(1 << 12))
    }

    fn len(&self) -> Option<usize> {
        Some(self.inner.remaining)
    }
}

#[cfg(test)]
mod tests {
    use crate::VirtualMLE;

    use super::*;
    use ark_bls12_381::Fr;
    use ark_ff::Zero;
    use ark_ff::{One, UniformRand};

    #[test]
    fn test_lexico_iter() {
        for nv in 1..20 {
            let iter = LexicoIter::new(nv, Fr::zero(), Fr::one());
            let lexico_result = (0..(1 << nv))
                .map(|s| Fr::from(s as u64))
                .collect::<Vec<_>>();
            let iter_result = iter.to_vec();
            for (i, (a, b)) in lexico_result.iter().zip(&iter_result).enumerate() {
                assert_eq!(a, b, "failed for {nv} at {i}");
            }
        }
    }

    #[test]
    fn test_lexico_iter_with_offset() {
        let rng = &mut ark_std::test_rng();
        for nv in 1..20 {
            let offset = Fr::rand(rng);
            let iter = LexicoIter::new(nv, offset, Fr::one());
            let lexico_result = (0..(1 << nv))
                .map(|s| offset + Fr::from(s as u64))
                .collect::<Vec<_>>();
            let iter_result = iter.to_vec();
            for (i, (a, b)) in lexico_result.iter().zip(&iter_result).enumerate() {
                assert_eq!(a, b, "failed for {nv} at {i}");
            }
        }
    }

    #[test]
    fn test_lexico_iter_with_offset_fix_variable() {
        let rng = &mut ark_std::test_rng();
        for nv in 1..20 {
            for fixed_nv in 0..nv {
                let fixed_vars = (0..fixed_nv).map(|_| Fr::rand(rng)).collect::<Vec<_>>();
                let offset = Fr::rand(rng);
                let mle = VirtualMLE::lexicographic(nv, offset);
                let mle = mle.fix_variables(&fixed_vars);

                let offset = offset
                    + fixed_vars
                        .iter()
                        .enumerate()
                        .fold(Fr::zero(), |acc, (i, v)| acc + *v * Fr::from(1u64 << i));
                let lexico_result = (0..(1 << nv))
                    .step_by(1 << fixed_nv)
                    .map(|s| offset + Fr::from(s as u64))
                    .collect::<Vec<_>>();

                let iter_result = mle.evals().to_vec();
                for (i, (a, b)) in lexico_result.iter().zip(&iter_result).enumerate() {
                    assert_eq!(a, b, "failed for {nv} at {i}");
                }
            }
        }
    }
}
