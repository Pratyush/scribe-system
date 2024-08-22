use crate::streams::file_vec::FileVec;
use crate::{
    hyperplonk::pcs::{
        errors::PCSError, multilinear_kzg::util::eq_extension, StructuredReferenceString,
    },
    streams::serialize::RawAffine,
};
use ark_ec::{pairing::Pairing, scalar_mul::fixed_base::FixedBase, CurveGroup};
use ark_ff::{Field, PrimeField};
use ark_poly::DenseMultilinearExtension;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{
    collections::LinkedList, end_timer, format, rand::Rng, start_timer, string::ToString, vec::Vec,
    UniformRand,
};
use core::iter::FromIterator;

/// Universal Parameter
#[derive(Debug, CanonicalDeserialize, CanonicalSerialize)]
pub struct MultilinearUniversalParams<E: Pairing>
where
    E::G1Affine: RawAffine,
{
    /// prover parameters
    pub prover_param: MultilinearProverParam<E>,
    /// h^randomness: h^t1, h^t2, ..., **h^{t_nv}**
    pub h_mask: Vec<E::G2Affine>,
}

/// Prover Parameters
#[derive(Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct MultilinearProverParam<E: Pairing>
where
    E::G1Affine: RawAffine,
{
    /// number of variables
    pub num_vars: usize,
    /// `pp_{0}`, `pp_{1}`, ...,pp_{nu_vars} defined
    /// by XZZPD19 where pp_{nv-0}=g and
    /// pp_{nv-i}=g^{eq((t_1,..t_i),(X_1,..X_i))}
    pub powers_of_g: Vec<FileVec<E::G1Affine>>,
    /// generator for G1
    pub g: E::G1Affine,
    /// generator for G2
    pub h: E::G2Affine,
}

/// Verifier Parameters
#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug)]
pub struct MultilinearVerifierParam<E: Pairing> {
    /// number of variables
    pub num_vars: usize,
    /// generator of G1
    pub g: E::G1Affine,
    /// generator of G2
    pub h: E::G2Affine,
    /// h^randomness: h^t1, h^t2, ..., **h^{t_nv}**
    pub h_mask: Vec<E::G2Affine>,
}

impl<E: Pairing> StructuredReferenceString<E> for MultilinearUniversalParams<E>
where
    E::G1Affine: RawAffine,
{
    type ProverParam = MultilinearProverParam<E>;
    type VerifierParam = MultilinearVerifierParam<E>;

    /// Extract the prover parameters from the public parameters.
    fn extract_prover_param(&self, supported_num_vars: usize) -> Self::ProverParam {
        let to_reduce = self.prover_param.num_vars - supported_num_vars;

        Self::ProverParam {
            powers_of_g: self.prover_param.powers_of_g[to_reduce..]
                .iter()
                .map(|x| x.deep_copy())
                .collect(),
            g: self.prover_param.g,
            h: self.prover_param.h,
            num_vars: supported_num_vars,
        }
    }

    /// Extract the verifier parameters from the public parameters.
    fn extract_verifier_param(&self, supported_num_vars: usize) -> Self::VerifierParam {
        let to_reduce = self.prover_param.num_vars - supported_num_vars;
        Self::VerifierParam {
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
    ) -> Result<(Self::ProverParam, Self::VerifierParam), PCSError> {
        if supported_num_vars > self.prover_param.num_vars {
            return Err(PCSError::InvalidParameters(format!(
                "SRS does not support target number of vars {}",
                supported_num_vars
            )));
        }

        let to_reduce = self.prover_param.num_vars - supported_num_vars;
        let ck = Self::ProverParam {
            powers_of_g: self.prover_param.powers_of_g[to_reduce..]
                .iter()
                .map(|x| x.deep_copy())
                .collect(),
            g: self.prover_param.g,
            h: self.prover_param.h,
            num_vars: supported_num_vars,
        };
        let vk = Self::VerifierParam {
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
    fn gen_srs_for_testing<R: Rng>(rng: &mut R, num_vars: usize) -> Result<Self, PCSError> {
        if num_vars == 0 {
            return Err(PCSError::InvalidParameters(
                "constant polynomial not supported".to_string(),
            ));
        }

        let total_timer = start_timer!(|| format!("SRS generation for nv = {}", num_vars));

        let pp_generation_timer = start_timer!(|| "Prover Param generation");

        let g = E::G1::rand(rng);
        let h = E::G2::rand(rng);

        let mut powers_of_g = Vec::new();

        let t: Vec<_> = (0..num_vars).map(|_| E::ScalarField::rand(rng)).collect();
        let scalar_bits = E::ScalarField::MODULUS_BIT_SIZE as usize;

        let mut eq: LinkedList<DenseMultilinearExtension<E::ScalarField>> =
            LinkedList::from_iter(eq_extension(&t).into_iter());
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
            let pp_k_g = FileVec::from_iter(pp_g[start..(start + size)].to_vec());
            // check correctness of pp_k_g
            // let t_eval_0 = eq_eval(&vec![E::ScalarField::zero(); num_vars - i], &t[i..num_vars])?;
            // assert_eq!((g * t_eval_0).into(), pp_k_g.evals[0]);
            powers_of_g.push(pp_k_g);
            start += size;
        }
        let gg = FileVec::from_iter([g.into_affine()].to_vec());
        powers_of_g.push(gg);

        let pp = Self::ProverParam {
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
    ) -> Result<Self, PCSError> {
        let start = start_timer!(|| format!("Fake SRS generation for nv = {}", supported_degree));

        let pp = Self::ProverParam {
            num_vars: supported_degree,
            g: E::G1::rand(rng).into_affine(),
            h: E::G2::rand(rng).into_affine(),
            powers_of_g: (0..supported_degree + 1)
                .rev()
                .map(|degree| {
                    let mut rand_g1 = E::G1::rand(rng).into_affine();
                    FileVec::from_iter((0..(1 << degree)).map(|i| {
                        if (i % (1 << 10)) == 0 {
                            rand_g1 = E::G1::rand(rng).into_affine();
                        }
                        rand_g1
                    }))
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
fn remove_dummy_variable<F: Field>(poly: &[F], pad: usize) -> Result<Vec<F>, PCSError> {
    if pad == 0 {
        return Ok(poly.to_vec());
    }
    if !poly.len().is_power_of_two() {
        return Err(PCSError::InvalidParameters(
            "Size of polynomial should be power of two.".to_string(),
        ));
    }
    let nv = ark_std::log2(poly.len()) as usize - pad;
    Ok((0..(1 << nv)).map(|x| poly[x << pad]).collect())
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::ops::Mul;

    use super::*;
    use ark_bls12_381::Bls12_381;
    use ark_bls12_381::Fr;
    use ark_ec::bls12::Bls12;
    use ark_std::test_rng;
    use ark_std::UniformRand;
    type E = Bls12_381;

    #[test]
    fn test_srs_gen() -> Result<(), PCSError> {
        let mut rng = test_rng();
        for nv in 4..10 {
            let _ = MultilinearUniversalParams::<E>::gen_fake_srs_for_testing(&mut rng, nv)?;
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

        let mut f2 = File::open("evaluations.serialization.test").unwrap();
        let evaluations_deserialized = Vec::<
            FileVec<<Bls12_381 as ark_ec::pairing::Pairing>::G1Affine>,
        >::deserialize_uncompressed_unchecked(&mut f2)
        .unwrap();
        assert_eq!(evaluations_vec, evaluations_deserialized);

        let prover_param: MultilinearProverParam<E> = MultilinearProverParam {
            num_vars: 4,
            powers_of_g: evaluations_vec,
            g: <Bls12_381 as ark_ec::pairing::Pairing>::G1::rand(&mut rng).into_affine(),
            h: <Bls12_381 as ark_ec::pairing::Pairing>::G2::rand(&mut rng).into_affine(),
        };

        let mut f3 = File::create("prover_param.serialization.test").unwrap();
        prover_param.serialize_uncompressed(&mut f3).unwrap();

        let mut f4 = File::open("prover_param.serialization.test").unwrap();
        let prover_param_deserailized =
            MultilinearProverParam::<E>::deserialize_uncompressed_unchecked(&mut f4).unwrap();
        assert_eq!(
            prover_param.powers_of_g,
            prover_param_deserailized.powers_of_g
        );
    }

    #[test]
    fn test_srs_serialization() {
        let mut rng = test_rng();
        let srs = MultilinearUniversalParams::<E>::gen_fake_srs_for_testing(&mut rng, 7).unwrap();
        let mut f = File::create("srs.serialization.test").unwrap();
        srs.serialize_uncompressed(&mut f).unwrap();

        let mut f2 = File::open("srs.serialization.test").unwrap();
        MultilinearUniversalParams::<E>::deserialize_uncompressed_unchecked(&mut f2).unwrap();
    }
}
