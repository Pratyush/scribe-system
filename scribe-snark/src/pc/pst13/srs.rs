use crate::streams::file_vec::FileVec;
use crate::{
    pc::{errors::PCError, pst13::util::eq_extension, StructuredReferenceString},
    streams::serialize::RawAffine,
};
use ark_ec::{pairing::Pairing, scalar_mul::fixed_base::FixedBase, CurveGroup};
use ark_ff::{Field, PrimeField};
use ark_poly::DenseMultilinearExtension;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError, Valid};
use ark_std::{
    collections::LinkedList, end_timer, format, rand::Rng, start_timer, string::ToString, vec::Vec,
    UniformRand,
};
use core::iter::FromIterator;
use std::sync::Arc;

/// Universal Parameter
#[derive(Debug, CanonicalDeserialize, CanonicalSerialize)]
pub struct SRS<E: Pairing>
where
    E::G1Affine: RawAffine,
{
    /// prover parameters
    pub prover_param: CommitterKey<E>,
    /// h^randomness: h^t1, h^t2, ..., **h^{t_nv}**
    pub h_mask: Vec<E::G2Affine>,
}

/// Committer Key
#[derive(Debug)]
pub struct CommitterKey<E: Pairing>
where
    E::G1Affine: RawAffine,
{
    /// number of variables
    pub num_vars: usize,
    /// `pp_{0}`, `pp_{1}`, ...,pp_{nu_vars} defined
    /// by XZZPD19 where pp_{nv-0}=g and
    /// pp_{nv-i}=g^{eq((t_1,..t_i),(X_1,..X_i))}
    pub powers_of_g: Vec<Arc<FileVec<E::G1Affine>>>,
    /// generator for G1
    pub g: E::G1Affine,
    /// generator for G2
    pub h: E::G2Affine,
}

impl<E: Pairing> ark_serialize::CanonicalSerialize for CommitterKey<E>
where
    E::G1Affine: RawAffine,
{
    fn serialize_with_mode<W: ark_serialize::Write>(
        &self,
        mut writer: W,
        compress: ark_serialize::Compress,
    ) -> Result<(), SerializationError> {
        self.num_vars.serialize_with_mode(&mut writer, compress)?;

        self.powers_of_g
            .len()
            .serialize_with_mode(&mut writer, compress)?;
        for powers in &self.powers_of_g {
            powers.serialize_with_mode(&mut writer, compress)?;
        }

        self.g.serialize_with_mode(&mut writer, compress)?;
        self.h.serialize_with_mode(&mut writer, compress)?;
        Ok(())
    }

    fn serialized_size(&self, compress: ark_serialize::Compress) -> usize {
        let mut size = 0;
        size += self.num_vars.serialized_size(compress);
        size += self.powers_of_g.len().serialized_size(compress);
        size += self
            .powers_of_g
            .iter()
            .fold(0, |acc, x| acc + x.serialized_size(compress));
        size += self.g.serialized_size(compress);
        size += self.h.serialized_size(compress);
        size
    }
}

impl<E: Pairing> CanonicalDeserialize for CommitterKey<E>
where
    E::G1Affine: RawAffine,
{
    fn deserialize_with_mode<R: ark_serialize::Read>(
        mut reader: R,
        compress: ark_serialize::Compress,
        validate: ark_serialize::Validate,
    ) -> Result<Self, SerializationError> {
        let num_vars = usize::deserialize_with_mode(&mut reader, compress, validate)?;

        let len = usize::deserialize_with_mode(&mut reader, compress, validate)?;
        let mut powers_of_g = Vec::with_capacity(len);
        for i in 0..len {
            powers_of_g.push(Arc::new(FileVec::deserialize_with_mode_and_prefix(
                &mut reader,
                &format!("ck_{i}"),
                compress,
                validate,
            )?));
        }
        let g = E::G1Affine::deserialize_with_mode(&mut reader, compress, validate)?;
        let h = E::G2Affine::deserialize_with_mode(&mut reader, compress, validate)?;

        Ok(CommitterKey {
            num_vars,
            powers_of_g,
            g,
            h,
        })
    }
}

impl<E: Pairing> Valid for CommitterKey<E>
where
    E::G1Affine: RawAffine,
{
    #[allow(unused_mut, unused_variables)]
    fn check(&self) -> Result<(), SerializationError> {
        Valid::check(&self.num_vars)?;
        Valid::check(&self.powers_of_g)?;
        Valid::check(&self.g)?;
        Valid::check(&self.h)?;
        Ok(())
    }
    #[allow(unused_mut, unused_variables)]
    fn batch_check<'a>(
        batch: impl Iterator<Item = &'a Self> + Send,
    ) -> Result<(), SerializationError>
    where
        Self: 'a,
    {
        let batch: Vec<_> = batch.collect();
        Valid::batch_check(batch.iter().map(|v| &v.num_vars))?;
        Valid::batch_check(batch.iter().map(|v| &v.powers_of_g))?;
        Valid::batch_check(batch.iter().map(|v| &v.g))?;
        Valid::batch_check(batch.iter().map(|v| &v.h))?;
        Ok(())
    }
}

/// Verifier Parameters
#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug)]
pub struct VerifierKey<E: Pairing> {
    /// number of variables
    pub num_vars: usize,
    /// generator of G1
    pub g: E::G1Affine,
    /// generator of G2
    pub h: E::G2Affine,
    /// h^randomness: h^t1, h^t2, ..., **h^{t_nv}**
    pub h_mask: Vec<E::G2Affine>,
}

impl<E: Pairing> StructuredReferenceString<E> for SRS<E>
where
    E::G1Affine: RawAffine,
{
    type CommitterKey = CommitterKey<E>;
    type VerifierKey = VerifierKey<E>;

    /// Extract the prover parameters from the public parameters.
    fn extract_ck(&self, supported_num_vars: usize) -> Self::CommitterKey {
        let to_reduce = self.prover_param.num_vars - supported_num_vars;

        Self::CommitterKey {
            powers_of_g: self.prover_param.powers_of_g[to_reduce..]
                .iter()
                .map(|x| Arc::clone(x))
                .collect(),
            g: self.prover_param.g,
            h: self.prover_param.h,
            num_vars: supported_num_vars,
        }
    }

    /// Extract the verifier parameters from the public parameters.
    fn extract_vk(&self, supported_num_vars: usize) -> Self::VerifierKey {
        let to_reduce = self.prover_param.num_vars - supported_num_vars;
        Self::VerifierKey {
            num_vars: supported_num_vars,
            g: self.prover_param.g,
            h: self.prover_param.h,
            h_mask: self.h_mask[to_reduce..].to_vec(),
        }
    }

    /// Trim the universal parameters to specialize the public parameters
    /// for multilinear polynomials to the given `supported_num_vars`, and
    /// returns committer key and verifier key. `supported_num_vars` should
    /// be in range `1..=params.num_vars`
    fn trim(
        &self,
        supported_num_vars: usize,
    ) -> Result<(Self::CommitterKey, Self::VerifierKey), PCError> {
        if supported_num_vars > self.prover_param.num_vars {
            return Err(PCError::InvalidParameters(format!(
                "SRS does not support target number of vars {}",
                supported_num_vars
            )));
        }

        let to_reduce = self.prover_param.num_vars - supported_num_vars;
        let ck = Self::CommitterKey {
            powers_of_g: self.prover_param.powers_of_g[to_reduce..]
                .iter()
                .map(|x| Arc::clone(x))
                .collect(),
            g: self.prover_param.g,
            h: self.prover_param.h,
            num_vars: supported_num_vars,
        };
        let vk = Self::VerifierKey {
            num_vars: supported_num_vars,
            g: self.prover_param.g,
            h: self.prover_param.h,
            h_mask: self.h_mask[to_reduce..].to_vec(),
        };
        Ok((ck, vk))
    }

    /// Build SRS for testing.
    /// WARNING: THIS FUNCTION IS FOR TESTING PURPOSE ONLY.
    /// THE OUTPUT SRS SHOULD NOT BE USED IN PRODUCTION.
    fn gen_srs_for_testing<R: Rng>(rng: &mut R, num_vars: usize) -> Result<Self, PCError> {
        if num_vars == 0 {
            return Err(PCError::InvalidParameters(
                "constant polynomial not supported".to_string(),
            ));
        }

        let total_timer = start_timer!(|| format!("SRS generation for nv = {num_vars}"));

        let pp_generation_timer = start_timer!(|| "Prover Param generation");

        let g = E::G1::rand(rng);
        let h = E::G2::rand(rng);

        let mut powers_of_g = Vec::new();

        let t: Vec<_> = (0..num_vars).map(|_| E::ScalarField::rand(rng)).collect();
        let scalar_bits = E::ScalarField::MODULUS_BIT_SIZE as usize;

        let mut eq: LinkedList<DenseMultilinearExtension<E::ScalarField>> =
            LinkedList::from_iter(eq_extension(&t));
        let mut eq_arr = LinkedList::new();
        let mut base = eq.pop_back().unwrap().evaluations;

        for i in (0..num_vars).rev() {
            eq_arr.push_front(remove_dummy_variable(&base, i)?);
            if i != 0 {
                let mul = eq.pop_back().unwrap().evaluations;
                base = base
                    .into_iter()
                    .zip(mul.into_iter())
                    .map(|(a, b)| a * b)
                    .collect();
            }
        }

        let mut pp_powers = Vec::new();
        let mut total_scalars = 0;
        for i in 0..num_vars {
            let eq = eq_arr.pop_front().unwrap();
            let pp_k_powers = (0..(1 << (num_vars - i))).map(|x| eq[x]);
            pp_powers.extend(pp_k_powers);
            total_scalars += 1 << (num_vars - i);
        }
        let window_size = FixedBase::get_mul_window_size(total_scalars);
        let g_table = FixedBase::get_window_table(scalar_bits, window_size, g);

        let pp_g = E::G1::normalize_batch(&FixedBase::msm(
            scalar_bits,
            window_size,
            &g_table,
            &pp_powers,
        ));

        let mut start = 0;
        for i in 0..num_vars {
            let size = 1 << (num_vars - i);
            let pp_k_g = Arc::new(FileVec::from_iter_with_prefix(
                pp_g[start..(start + size)].iter().copied(),
                format!("srs_{i}"),
            ));
            // check correctness of pp_k_g
            // let t_eval_0 = eq_eval(&vec![E::ScalarField::zero(); num_vars - i], &t[i..num_vars])?;
            // assert_eq!((g * t_eval_0).into(), pp_k_g.evals[0]);
            powers_of_g.push(pp_k_g);
            start += size;
        }
        let gg = Arc::new(FileVec::from_iter_with_prefix(
            [g.into_affine()].to_vec(),
            format!("srs_{num_vars}"),
        ));
        powers_of_g.push(gg);

        let pp = Self::CommitterKey {
            num_vars,
            g: g.into_affine(),
            h: h.into_affine(),
            powers_of_g,
        };

        // print the length of each powers_of_g evaluation
        // for i in 0..num_vars + 1 {
        //     println!(
        //         "powers_of_g[{}] length: {}",
        //         i,
        //         pp.powers_of_g[i].evals.len()
        //     );
        // }

        end_timer!(pp_generation_timer);

        let vp_generation_timer = start_timer!(|| "VP generation");
        let h_mask = {
            let window_size = FixedBase::get_mul_window_size(num_vars);
            let h_table = FixedBase::get_window_table(scalar_bits, window_size, h);
            E::G2::normalize_batch(&FixedBase::msm(scalar_bits, window_size, &h_table, &t))
        };

        end_timer!(vp_generation_timer);
        end_timer!(total_timer);
        Ok(Self {
            prover_param: pp,
            h_mask,
        })
    }

    fn gen_fake_srs_for_testing<R: Rng>(
        rng: &mut R,
        supported_degree: usize,
    ) -> Result<Self, PCError> {
        let start = start_timer!(|| format!("Fake SRS generation for nv = {supported_degree}"));

        let pp = Self::CommitterKey {
            num_vars: supported_degree,
            g: E::G1::rand(rng).into_affine(),
            h: E::G2::rand(rng).into_affine(),
            powers_of_g: (0..supported_degree + 1)
                .rev()
                .map(|degree| {
                    let mut rand_g1 = E::G1::rand(rng).into_affine();
                    Arc::new(FileVec::from_iter((0..(1 << degree)).map(|i| {
                        if (i % (1 << 10)) == 0 {
                            rand_g1 = E::G1::rand(rng).into_affine();
                        }
                        rand_g1
                    })))
                })
                .collect(),
        };

        let h_mask: Vec<_> = (0..supported_degree)
            .map(|_| E::G2::rand(rng).into_affine())
            .collect();

        end_timer!(start);

        Ok(Self {
            prover_param: pp,
            h_mask,
        })
    }
}

/// fix first `pad` variables of `poly` represented in evaluation form to zero
fn remove_dummy_variable<F: Field>(poly: &[F], pad: usize) -> Result<Vec<F>, PCError> {
    if pad == 0 {
        return Ok(poly.to_vec());
    }
    if !poly.len().is_power_of_two() {
        return Err(PCError::InvalidParameters(
            "Size of polynomial should be power of two.".to_string(),
        ));
    }
    let nv = ark_std::log2(poly.len()) as usize - pad;
    Ok((0..(1 << nv)).map(|x| poly[x << pad]).collect())
}

#[cfg(test)]
mod tests {
    use std::fs::File;

    use super::*;
    use ark_bls12_381::Bls12_381;

    use ark_ec::bls12::Bls12;
    use ark_std::test_rng;
    use ark_std::UniformRand;
    type E = Bls12_381;

    #[test]
    fn test_srs_gen() -> Result<(), PCError> {
        let mut rng = test_rng();
        for nv in 4..10 {
            let _ = SRS::<E>::gen_fake_srs_for_testing(&mut rng, nv)?;
        }

        Ok(())
    }

    #[test]
    fn test_file_vec_serialization() {
        let mut rng = test_rng();
        let evaluations = FileVec::from_iter((0..16).map(|_| {
            <Bls12<ark_bls12_381::Config> as ark_ec::pairing::Pairing>::G1::rand(&mut rng)
                .into_affine()
        }));

        let evaluations_2 = FileVec::from_iter((0..16).map(|_| {
            <Bls12<ark_bls12_381::Config> as ark_ec::pairing::Pairing>::G1::rand(&mut rng)
                .into_affine()
        }));

        let evaluations_vec = vec![evaluations, evaluations_2];

        let mut f = File::create("evaluations.serialization.test").unwrap();
        evaluations_vec.serialize_uncompressed(&mut f).unwrap();
        let evaluations_vec = evaluations_vec
            .into_iter()
            .map(Arc::new)
            .collect::<Vec<_>>();

        let mut f2 = File::open("evaluations.serialization.test").unwrap();
        let evaluations_deserialized = Vec::<
            FileVec<<Bls12_381 as ark_ec::pairing::Pairing>::G1Affine>,
        >::deserialize_uncompressed_unchecked(&mut f2)
        .unwrap();
        let evaluations_deserialized = evaluations_deserialized
            .into_iter()
            .map(Arc::new)
            .collect::<Vec<_>>();
        assert_eq!(evaluations_vec, evaluations_deserialized);

        let prover_param: CommitterKey<E> = CommitterKey {
            num_vars: 4,
            powers_of_g: evaluations_vec,
            g: <Bls12_381 as ark_ec::pairing::Pairing>::G1::rand(&mut rng).into_affine(),
            h: <Bls12_381 as ark_ec::pairing::Pairing>::G2::rand(&mut rng).into_affine(),
        };

        let mut f3 = File::create("prover_param.serialization.test").unwrap();
        prover_param.serialize_uncompressed(&mut f3).unwrap();

        let mut f4 = File::open("prover_param.serialization.test").unwrap();
        let prover_param_deserailized =
            CommitterKey::<E>::deserialize_uncompressed_unchecked(&mut f4).unwrap();
        assert_eq!(
            prover_param.powers_of_g,
            prover_param_deserailized.powers_of_g
        );
    }

    #[test]
    fn test_srs_serialization() {
        let mut rng = test_rng();
        let srs = SRS::<E>::gen_fake_srs_for_testing(&mut rng, 7).unwrap();
        let mut f = File::create("srs.serialization.test").unwrap();
        srs.serialize_uncompressed(&mut f).unwrap();

        let mut f2 = File::open("srs.serialization.test").unwrap();
        SRS::<E>::deserialize_uncompressed_unchecked(&mut f2).unwrap();
    }
}
