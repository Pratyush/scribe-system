use crate::{arithmetic::errors::ArithError, streams::{serialize::RawPrimeField, MLE}};
use ark_ff::Field;
// use ark_poly::{DenseMultilinearExtension, MultilinearExtension};
use ark_serialize::CanonicalSerialize;
use ark_std::{
    end_timer,
    rand::{Rng, RngCore},
    start_timer,
};
use rayon::iter::IntoParallelRefMutIterator;
use rayon::prelude::*;
use std::{cmp::max, marker::PhantomData};

/// A virtual polynomial is a sum of products of multilinear polynomials;
/// where the multilinear polynomials are stored via their multilinear
/// extensions:  `(coefficient, DenseMultilinearExtension)`
///
/// * Number of products n = `polynomial.products.len()`,
/// * Number of multiplicands of ith product m_i =
///   `polynomial.products[i].1.len()`,
/// * Coefficient of ith product c_i = `polynomial.products[i].0`
///
/// The resulting polynomial is
///
/// $$ \sum_{i=0}^{n} c_i \cdot \prod_{j=0}^{m_i} P_{ij} $$
///
/// Example:
///  f = c0 * f0 * f1 * f2 + c1 * f3 * f4
/// where f0 ... f4 are multilinear polynomials
///
/// - flattened_ml_extensions stores the multilinear extension representation of
///   f0, f1, f2, f3 and f4
/// - products is
///     \[
///         (c0, \[0, 1, 2\]),
///         (c1, \[3, 4\])
///     \]
/// - raw_pointers_lookup_table maps fi to i
///
#[derive(Clone)]
pub struct VirtualPolynomial<F: RawPrimeField> {
    /// Aux information about the multilinear polynomial
    pub aux_info: VPAuxInfo<F>,
    /// list of reference to products (as usize) of multilinear extension
    pub products: Vec<(F, Vec<usize>)>,
    /// Stores multilinear extensions in which product multiplicand can refer
    /// to.
    pub mles: Vec<MLE<F>>,
}

/// Auxiliary information about the multilinear polynomial
#[derive(Clone, Debug, Default, PartialEq, Eq, CanonicalSerialize)]
pub struct VPAuxInfo<F: RawPrimeField> {
    /// max number of multiplicands in each product
    pub max_degree: usize,
    /// number of variables of the polynomial
    pub num_variables: usize,
    /// Associated field
    #[doc(hidden)]
    pub phantom: PhantomData<F>,
}

// TODO: convert this into a trait
impl<F: RawPrimeField> VirtualPolynomial<F> {
    /// Creates an empty virtual polynomial with `num_variables`.
    pub fn new(num_variables: usize) -> Self {
        VirtualPolynomial {
            aux_info: VPAuxInfo {
                max_degree: 0,
                num_variables,
                phantom: PhantomData::default(),
            },
            products: Vec::new(),
            mles: Vec::new(),
        }
    }

    /// Creates an new virtual polynomial from a MLE and its coefficient.
    pub fn new_from_mle(mle: &MLE<F>, coefficient: F) -> Self {
        let num_vars = mle.num_vars();

        VirtualPolynomial {
            aux_info: VPAuxInfo {
                // The max degree is the max degree of any individual variable
                max_degree: 1,
                num_variables: num_vars,
                phantom: PhantomData::default(),
            },
            // here `0` points to the first polynomial of `flattened_ml_extensions`
            products: vec![(coefficient, vec![0])],
            mles: vec![mle.clone()],
        }
    }

    /// Returns the number of variables of the virtual polynomial.
    pub fn num_vars(&self) -> usize {
        self.aux_info.num_variables
    }

    /// Returns the maximum degree of the virtual polynomial.
    pub fn individual_degree(&self) -> usize {
        self.aux_info.max_degree
    }

    /// Add a product of list of multilinear extensions to self
    /// Returns an error if the list is empty, or the MLE has a different
    /// `num_vars` from self.
    ///
    /// The MLEs will be multiplied together, and then multiplied by the scalar
    /// `coefficient`.
    pub fn add_mles(
        &mut self,
        mles: impl IntoIterator<Item = MLE<F>>,
        coefficient: F,
    ) -> Result<(), ArithError> {
        let mle_list = Vec::from_iter(mles);
        let mut indexed_product = Vec::with_capacity(mle_list.len());

        if mle_list.is_empty() {
            return Ok(());
        }

        self.aux_info.max_degree = max(self.aux_info.max_degree, mle_list.len());

        for mle in mle_list {
            if mle.num_vars() != self.num_vars() {
                return Err(ArithError::InvalidParameters(format!(
                    "product has a multiplicand with wrong number of variables {} vs {}",
                    mle.num_vars(),
                    self.aux_info.num_variables
                )));
            }

            let mle_index = match self.mles.iter().position(|e| e == &mle) {
                Some(p) => p,
                None => {
                    self.mles.push(mle.clone());
                    self.mles.len() - 1
                }
            };
            indexed_product.push(mle_index);
        }
        self.products.push((coefficient, indexed_product));
        Ok(())
    }

    /// Multiply the current VirtualPolynomial by an MLE:
    /// - add the MLE to the MLE list;
    /// - multiply each product by MLE and its coefficient.
    /// Returns an error if the MLE has a different `num_vars` from self.
    pub fn mul_by_mle(&mut self, mle: MLE<F>, coefficient: F) -> Result<(), ArithError> {
        let start = start_timer!(|| "mul by mle");
        if mle.num_vars() != self.num_vars() {
            return Err(ArithError::InvalidParameters(format!(
                "product has a multiplicand with wrong number of variables {} vs {}",
                mle.num_vars(),
                self.num_vars()
            )));
        }

        let mle_index = match self.mles.iter().position(|e| e == &mle) {
            Some(p) => p,
            None => {
                self.mles.push(mle);
                self.mles.len() - 1
            }
        };

        for (prod_coef, indices) in self.products.iter_mut() {
            // - add the MLE to the MLE list;
            // - multiple each product by MLE and its coefficient.
            indices.push(mle_index);
            *prod_coef *= coefficient;
        }

        // increase the max degree by one as the MLE has degree 1.
        self.aux_info.max_degree += 1;

        end_timer!(start);
        Ok(())
    }

    /// Evaluate the virtual polynomial at point `point`.
    /// Returns an error is point.len() does not match `num_variables`.
    pub fn evaluate(&self, point: &[F]) -> Result<F, ArithError> {
        let start = start_timer!(|| "evaluation");
        if point.len() != self.num_vars() {
            return Err(ArithError::InvalidParameters(format!(
                "point length is different from number of variables: {} vs {}",
                point.len(),
                self.num_vars()
            )));
        }

        let evals: Vec<F> = self
            .mles
            .iter()
            .map(|mle| mle.evaluate(point).unwrap())
            .collect();

        let res = self
            .products
            .iter()
            .map(|(c, p)| *c * p.iter().map(|&i| evals[i]).product::<F>())
            .sum();

        end_timer!(start);
        Ok(res)
    }

    /// Sample a random virtual polynomial, return the polynomial and its sum.
    pub fn rand<R: RngCore>(
        nv: usize,
        num_multiplicands_range: (usize, usize),
        num_products: usize,
        rng: &mut R,
    ) -> Result<(Self, F), ArithError> {
        let start = start_timer!(|| "sample random virtual polynomial");

        let mut sum = F::zero();
        let mut poly = VirtualPolynomial::new(nv);
        for _ in 0..num_products {
            let num_multiplicands =
                rng.gen_range(num_multiplicands_range.0..num_multiplicands_range.1);
            let (product, product_sum) = MLE::rand_product_with_sum(nv, num_multiplicands, rng);
            let coefficient = F::rand(rng);
            poly.add_mles(product.into_iter(), coefficient)?;
            sum += product_sum * coefficient;
        }

        #[cfg(debug_assertions)]
        println!("final rand sum: {:?}", sum);

        end_timer!(start);
        Ok((poly, sum))
    }

    /// Sample a random virtual polynomial that evaluates to zero everywhere
    /// over the boolean hypercube.
    pub fn rand_zero<R: RngCore>(
        nv: usize,
        num_multiplicands_range: (usize, usize),
        num_products: usize,
        rng: &mut R,
    ) -> Result<Self, ArithError> {
        let mut poly = VirtualPolynomial::new(nv);
        for _ in 0..num_products {
            let num_multiplicands =
                rng.gen_range(num_multiplicands_range.0..num_multiplicands_range.1);
            let product = MLE::rand_product_summing_to_zero(nv, num_multiplicands, rng);
            let coefficient = F::rand(rng);
            poly.add_mles(product.into_iter(), coefficient)?;
        }

        #[cfg(debug_assertions)]
        poly.products.iter().for_each(|(_, p)| {
            println!("rand_zero product: {:?}", p);
        });

        Ok(poly)
    }

    // Input poly f(x) and a random vector r, output
    //      \hat f(x) = \sum_{x_i \in eval_x} f(x_i) eq(x, r)
    // where
    //      eq(x,y) = \prod_i=1^num_var (x_i * y_i + (1-x_i)*(1-y_i))
    //
    // This function is used in ZeroCheck.
    pub fn build_f_hat(&self, r: &[F]) -> Result<Self, ArithError> {
        let start = start_timer!(|| "zero check build hat f");

        if self.aux_info.num_variables != r.len() {
            return Err(ArithError::InvalidParameters(format!(
                "r.len() is different from number of variables: {} vs {}",
                r.len(),
                self.aux_info.num_variables
            )));
        }

        let eq_x_r = MLE::eq_x_r(r)?;
        let mut res = self.clone();
        res.mul_by_mle(eq_x_r, F::one())?;

        end_timer!(start);
        Ok(res)
    }

    // conduct a batch zero check on t_1 and t_2
    // t_1 = h_p * (p + alpha * pi + gamma) - 1
    // t_2 = h_q * (q + alpha * index + gamma) - 1
    // poly = t_1 + batch_factor * t_2 = h_p * (p + alpha * pi + gamma) - 1 + batch_factor * (h_q * (q + alpha * index + gamma) - 1)
    // = -1-batch_factor + h_p*p + h_p*alpha*pi + batch_factor*h_q*q + batch_factor*h_q*alpha*index + gamma*h_p + gamma*batch_factor*h_q
    pub fn build_perm_check_poly(
        h_p: MLE<F>,
        h_q: MLE<F>,
        p: MLE<F>,
        q: MLE<F>,
        pi: MLE<F>,
        index: MLE<F>,
        alpha: F,
        batch_factor: F,
        gamma: F,
    ) -> Result<VirtualPolynomial<F>, ArithError> {
        let num_vars = h_p.num_vars();

        let mut poly = VirtualPolynomial::new_from_mle(
            &MLE::constant(-batch_factor - F::ONE, num_vars),
            F::one(),
        );
        poly.add_mles(vec![h_p.clone(), p], F::one())?;
        poly.add_mles(vec![h_p.clone(), pi], alpha)?;
        poly.add_mles(vec![h_q.clone(), q], batch_factor)?;
        poly.add_mles(vec![h_q.clone(), index], alpha * batch_factor)?;
        poly.add_mles(vec![h_p], gamma)?;
        poly.add_mles(vec![h_q], gamma * batch_factor)?;

        Ok(poly)
    }

    // conduct a batch zero check on t_1, t_2, ..., t_n where n is the number of witnesses
    // note that there's no p and q but only p, as witness is checked against a permutation of itself
    pub fn build_perm_check_poly_plonk(
        h_p: Vec<MLE<F>>,
        h_q: Vec<MLE<F>>,
        p: Vec<MLE<F>>,
        pi: Vec<MLE<F>>,
        index: Vec<MLE<F>>,
        alpha: F,
        batch_factor: F,
        gamma: F,
    ) -> Result<VirtualPolynomial<F>, ArithError> {
        let num_vars = h_p[0].num_vars();

        // create constant = - 1 - batch_factor - batch_factor ^ 2 - ... - batch_factor ^ (num_vars - 1)
        let mut constant = F::one();
        let mut batch_factor_power = batch_factor;
        for _ in 0..num_vars {
            constant += batch_factor_power;
            batch_factor_power *= batch_factor;
        }

        let mut poly =
            VirtualPolynomial::new_from_mle(&MLE::constant(constant, num_vars), F::one());

        let mut batch_factor_lower_power = F::one();
        let mut batch_factor_higher_power = batch_factor;

        for i in 0..h_p.len() {
            poly.add_mles(vec![h_p[i].clone(), p[i].clone()], batch_factor_lower_power)
                .unwrap();
            poly.add_mles(
                vec![h_p[i].clone(), pi[i].clone()],
                batch_factor_lower_power * alpha,
            )
            .unwrap();
            poly.add_mles(
                vec![h_q[i].clone(), p[i].clone()],
                batch_factor_higher_power,
            )
            .unwrap();
            poly.add_mles(
                vec![h_q[i].clone(), index[i].clone()],
                batch_factor_higher_power * alpha,
            )
            .unwrap();
            poly.add_mles(vec![h_p[i].clone()], batch_factor_lower_power * gamma)
                .unwrap();
            poly.add_mles(vec![h_q[i].clone()], batch_factor_higher_power * gamma)
                .unwrap();

            batch_factor_lower_power = batch_factor_lower_power * batch_factor * batch_factor;
            batch_factor_higher_power = batch_factor_higher_power * batch_factor * batch_factor;
        }

        Ok(poly)
    }

    // same as build_perm_check_poly_plonk except that it adds to an existing virtual poly
    // TODO: replace this with a proper adding two virtual polynomials function
    pub fn add_build_perm_check_poly_plonk(
        self: &mut VirtualPolynomial<F>,
        h_p: Vec<MLE<F>>,
        h_q: Vec<MLE<F>>,
        p: Vec<MLE<F>>,
        pi: Vec<MLE<F>>,
        index: Vec<MLE<F>>,
        alpha: F,
        batch_factor: F,
        gamma: F,
    ) -> Result<(), ArithError> {
        // return smart pointer to const mle
        let start = start_timer!(|| "build perm check batch zero check polynomial");
        let num_vars = h_p[0].num_vars();

        // create constant = - batch_factor - batch_factor ^ 2 - ... - batch_factor ^ (h_p.len() * 2)
        let mut constant = -batch_factor;
        let mut batch_factor_power = -batch_factor * batch_factor;
        for _ in 0..(h_p.len() * 2 - 1) {
            constant += batch_factor_power;
            batch_factor_power *= batch_factor;
        }

        let constant_mle = MLE::constant(constant, num_vars);

        self.add_mles(vec![constant_mle.clone()], F::one()).unwrap();

        let mut batch_factor_lower_power = batch_factor;
        let mut batch_factor_higher_power = batch_factor * batch_factor;

        for i in 0..h_p.len() {
            self.add_mles([h_p[i].clone(), p[i].clone()], batch_factor_lower_power)
                .unwrap();
            self.add_mles(
                [h_p[i].clone(), pi[i].clone()],
                batch_factor_lower_power * alpha,
            )
            .unwrap();
            self.add_mles([h_q[i].clone(), p[i].clone()], batch_factor_higher_power)
                .unwrap();
            self.add_mles(
                [h_q[i].clone(), index[i].clone()],
                batch_factor_higher_power * alpha,
            )
            .unwrap();
            self.add_mles([h_p[i].clone()], batch_factor_lower_power * gamma)
                .unwrap();
            self.add_mles([h_q[i].clone()], batch_factor_higher_power * gamma)
                .unwrap();

            batch_factor_lower_power = batch_factor_lower_power * batch_factor * batch_factor;
            batch_factor_higher_power = batch_factor_higher_power * batch_factor * batch_factor;
        }

        end_timer!(start);

        Ok(())
    }
}

/// This function build the eq(x, r) polynomial for any given r, and output the
/// evaluation of eq(x, r) in its vector form.
///
/// Evaluate
///      eq(x,y) = \prod_i=1^num_var (x_i * y_i + (1-x_i)*(1-y_i))
/// over r, which is
///      eq(x,y) = \prod_i=1^num_var (x_i * r_i + (1-x_i)*(1-r_i))
pub fn build_eq_x_r_vec<F: Field>(r: &[F]) -> Result<Vec<F>, ArithError> {
    // we build eq(x,r) from its evaluations
    // we want to evaluate eq(x,r) over x \in {0, 1}^num_vars
    // for example, with num_vars = 4, x is a binary vector of 4, then
    //  0 0 0 0 -> (1-r0)   * (1-r1)    * (1-r2)    * (1-r3)
    //  1 0 0 0 -> r0       * (1-r1)    * (1-r2)    * (1-r3)
    //  0 1 0 0 -> (1-r0)   * r1        * (1-r2)    * (1-r3)
    //  1 1 0 0 -> r0       * r1        * (1-r2)    * (1-r3)
    //  ....
    //  1 1 1 1 -> r0       * r1        * r2        * r3
    // we will need 2^num_var evaluations

    let mut eval = Vec::new();
    build_eq_x_r_vec_helper(r, &mut eval)?;

    Ok(eval)
}

/// A helper function to build eq(x, r) recursively.
/// This function takes `r.len()` steps, and for each step it requires a maximum
/// `r.len()-1` multiplications.
fn build_eq_x_r_vec_helper<F: Field>(r: &[F], buf: &mut Vec<F>) -> Result<(), ArithError> {
    if r.is_empty() {
        return Err(ArithError::InvalidParameters("r length is 0".to_string()));
    } else if r.len() == 1 {
        // initializing the buffer with [1-r_0, r_0]
        buf.push(F::one() - r[0]);
        buf.push(r[0]);
    } else {
        build_eq_x_r_vec_helper(&r[1..], buf)?;

        let mut res = vec![F::zero(); buf.len() << 1];
        res.par_iter_mut().enumerate().for_each(|(i, val)| {
            let bi = buf[i >> 1];
            let tmp = r[0] * bi;
            if i & 1 == 0 {
                *val = bi - tmp;
            } else {
                *val = tmp;
            }
        });
        *buf = res;
    }

    Ok(())
}

/// Evaluate eq polynomial.
pub fn eq_eval<F: RawPrimeField>(x: &[F], y: &[F]) -> Result<F, ArithError> {
    if x.len() != y.len() {
        return Err(ArithError::InvalidParameters(
            "x and y have different length".to_string(),
        ));
    }
    // let start = start_timer!(|| "eq_eval");
    let mut res = F::one();
    for (&xi, &yi) in x.iter().zip(y.iter()) {
        let xi_yi = xi * yi;
        res *= xi_yi + xi_yi - xi - yi + F::one();
    }
    // end_timer!(start);
    Ok(res)
}

/// Decompose an integer into a binary vector in little endian.
pub fn bit_decompose(input: u64, num_var: usize) -> Vec<bool> {
    let mut res = Vec::with_capacity(num_var);
    let mut i = input;
    for _ in 0..num_var {
        res.push(i & 1 == 1);
        i >>= 1;
    }
    res
}

pub fn identity_permutation<F: RawPrimeField>(num_vars: usize, num_chunks: usize) -> Vec<F> {
    let len = (num_chunks as u64) * (1u64 << num_vars);
    (0..len).map(F::from).collect()
}

#[cfg(test)]
mod test {
    use super::VirtualPolynomial;
    use super::*;
    use crate::streams::iterator::BatchedIterator;
    use ark_bls12_381::Fr;
    use ark_ff::Field;
    use ark_ff::UniformRand;
    use ark_std::test_rng;

    // TODO: this is failing now, need to fix it
    #[test]
    fn test_build_perm_check_poly() {
        // Setup sample values for alpha and r
        let alpha = Fr::from(11u64);
        let gamma = Fr::from(13u64);
        let r = Fr::from(12u64);

        // Setup sample streams for h_p, h_q, p, q, and pi
        let h_p = MLE::from_evals_vec(vec![Fr::from(1u64), Fr::from(2u64)], 1);
        let h_q = MLE::from_evals_vec(vec![Fr::from(3u64), Fr::from(4u64)], 1);
        let p = MLE::from_evals_vec(vec![Fr::from(5u64), Fr::from(6u64)], 1);
        let q = MLE::from_evals_vec(vec![Fr::from(7u64), Fr::from(8u64)], 1);
        let pi = MLE::from_evals_vec(vec![Fr::from(9u64), Fr::from(10u64)], 1);
        let index = MLE::from_evals_vec(vec![Fr::from(13u64), Fr::from(14u64)], 1);

        // Call the function under test
        let result_poly =
            VirtualPolynomial::build_perm_check_poly(h_p, h_q, p, q, pi, index, alpha, r, gamma)
                .unwrap();

        // Define expected products directly
        let expected_products = vec![
            (Fr::from(1u64), vec![0]),
            (Fr::from(1u64), vec![1, 2]),
            (Fr::from(11u64), vec![1, 3]),
            (Fr::from(12u64), vec![4, 5]),
            (Fr::from(132u64), vec![4, 6]),
            (Fr::from(13u64), vec![0]),
            (Fr::from(156u64), vec![1]),
        ];

        // Compare max_degree and num_variables
        assert_eq!(result_poly.aux_info.max_degree, 2);
        assert_eq!(result_poly.aux_info.num_variables, 1);

        // Compare the length of products
        assert_eq!(
            result_poly.products.len(),
            expected_products.len(),
            "Products length mismatch"
        );

        // Detailed comparison of products
        for (i, (expected_coef, expected_indices)) in expected_products.iter().enumerate() {
            let (result_coef, result_indices) = &result_poly.products[i];
            assert_eq!(
                result_coef, expected_coef,
                "Mismatch in coefficient at index {}",
                i
            );
            assert_eq!(
                result_indices, expected_indices,
                "Mismatch in indices at index {}",
                i
            );
        }

        // Compare lengths of flattened_ml_extensions and raw_pointers_lookup_table
        assert_eq!(
            result_poly.mles.len(),
            7,
            "Mismatch in flattened_ml_extensions length"
        );
    }

    #[test]
    fn test_build_eq_x_r() {
        // Setup
        let r = [Fr::from(2u64), Fr::from(3u64)]; // Example r values
        let one = Fr::ONE;
        let expected_stream = vec![
            // Manually calculate expected values for eq(x, r) given r
            (one - Fr::from(2)) * (one - Fr::from(3)),
            Fr::from(2) * (one - Fr::from(3)),
            (one - Fr::from(2)) * Fr::from(3),
            Fr::from(2) * Fr::from(3),
        ];

        // Action
        let result_stream = MLE::eq_x_r(&r).expect("Failed to build eq(x, r)");

        // Fetch the stream's values for comparison
        let result_values = result_stream.evals().iter().to_vec();

        assert_eq!(
            expected_stream.len(),
            result_values.len(),
            "Stream lengths do not match"
        );
        assert_eq!(expected_stream, result_values, "Stream values do not match");
    }

    #[test]
    fn test_virtual_polynomial_mul_by_mle() -> Result<(), ArithError> {
        let mut rng = test_rng();
        for nv in 2..5 {
            for num_products in 2..5 {
                let base: Vec<Fr> = (0..nv).map(|_| Fr::rand(&mut rng)).collect();

                let (a, _a_sum) =
                    VirtualPolynomial::<Fr>::rand(nv, (2, 3), num_products, &mut rng)?;
                let (b, _b_sum) = MLE::rand_product_with_sum(nv, 1, &mut rng);
                let b_mle = b[0].clone();
                let coeff = Fr::rand(&mut rng);
                let b_vp = VirtualPolynomial::new_from_mle(&b_mle, coeff);

                let mut c = a.clone();

                c.mul_by_mle(b_mle, coeff)?;

                assert_eq!(
                    a.evaluate(&base)? * b_vp.evaluate(&base)?,
                    c.evaluate(&base)?
                );
            }
        }

        Ok(())
    }
}
