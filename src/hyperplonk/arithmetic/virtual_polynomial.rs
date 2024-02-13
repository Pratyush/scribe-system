// Copyright (c) 2023 Espresso Systems (espressosys.com)
// This file is part of the HyperPlonk library.

// You should have received a copy of the MIT License
// along with the HyperPlonk library. If not, see <https://mit-license.org/>.

//! This module defines our main mathematical object `VirtualPolynomial`; and
//! various functions associated with it.

use crate::{
    hyperplonk::{arithmetic::errors::ArithErrors, full_snark::prelude::WitnessColumn},
    read_write::{DenseMLPolyStream, ReadWriteStream},
};
use ark_ff::PrimeField;
// use ark_poly::{DenseMultilinearExtension, MultilinearExtension};
use ark_serialize::CanonicalSerialize;
use ark_std::{
    end_timer,
    rand::{Rng, RngCore},
    start_timer,
};
use core::num;
use rayon::iter::IntoParallelRefMutIterator;
use rayon::prelude::*;
use std::{
    cmp::max,
    collections::HashMap,
    io::Seek,
    marker::PhantomData,
    sync::{Arc, Mutex},
};

#[rustfmt::skip]
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
pub struct VirtualPolynomial<F: PrimeField> {
    /// Aux information about the multilinear polynomial
    pub aux_info: VPAuxInfo<F>,
    /// list of reference to products (as usize) of multilinear extension
    pub products: Vec<(F, Vec<usize>)>,
    /// Stores multilinear extensions in which product multiplicand can refer
    /// to.
    pub flattened_ml_extensions: Vec<Arc<Mutex<DenseMLPolyStream<F>>>>,
    /// Pointers to the above poly extensions
    raw_pointers_lookup_table: HashMap<*const Mutex<DenseMLPolyStream<F>>, usize>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, CanonicalSerialize)]
/// Auxiliary information about the multilinear polynomial
pub struct VPAuxInfo<F: PrimeField> {
    /// max number of multiplicands in each product
    pub max_degree: usize,
    /// number of variables of the polynomial
    pub num_variables: usize,
    /// Associated field
    #[doc(hidden)]
    pub phantom: PhantomData<F>,
}


// TODO: convert this into a trait
impl<F: PrimeField> VirtualPolynomial<F> {
    /// Creates an empty virtual polynomial with `num_variables`.
    pub fn new(num_variables: usize) -> Self {
        VirtualPolynomial {
            aux_info: VPAuxInfo {
                max_degree: 0,
                num_variables,
                phantom: PhantomData::default(),
            },
            products: Vec::new(),
            flattened_ml_extensions: Vec::new(),
            raw_pointers_lookup_table: HashMap::new(),
        }
    }

    /// Creates an new virtual polynomial from a MLE and its coefficient.
    pub fn new_from_mle(mle: &Arc<Mutex<DenseMLPolyStream<F>>>, coefficient: F) -> Self {
        let mle_locked = mle.lock().expect("Failed to lock mutex");
        let num_vars = mle_locked.num_vars;
        drop(mle_locked); // Release the lock

        let mle_ptr: *const Mutex<DenseMLPolyStream<F>> = Arc::as_ptr(mle);
        let mut hm = HashMap::new();
        hm.insert(mle_ptr, 0);

        VirtualPolynomial {
            aux_info: VPAuxInfo {
                // The max degree is the max degree of any individual variable
                max_degree: 1,
                num_variables: num_vars,
                phantom: PhantomData::default(),
            },
            // here `0` points to the first polynomial of `flattened_ml_extensions`
            products: vec![(coefficient, vec![0])],
            flattened_ml_extensions: vec![mle.clone()],
            raw_pointers_lookup_table: hm,
        }
    }

    /// Add a product of list of multilinear extensions to self
    /// Returns an error if the list is empty, or the MLE has a different
    /// `num_vars` from self.
    ///
    /// The MLEs will be multiplied together, and then multiplied by the scalar
    /// `coefficient`.
    pub fn add_mle_list(
        &mut self,
        mle_list: impl IntoIterator<Item = Arc<Mutex<DenseMLPolyStream<F>>>>,
        coefficient: F,
    ) -> Result<(), ArithErrors> {
        let mle_list: Vec<Arc<Mutex<DenseMLPolyStream<F>>>> = mle_list.into_iter().collect();
        let mut indexed_product = Vec::with_capacity(mle_list.len());

        if mle_list.is_empty() {
            return Err(ArithErrors::InvalidParameters(
                "input mle_list is empty".to_string(),
            ));
        }

        self.aux_info.max_degree = max(self.aux_info.max_degree, mle_list.len());

        for mle in mle_list {
            let mle_locked = mle.lock().expect("Failed to lock mutex");

            // // print num_vars
            // println!("add_mle_list num_vars: {}", mle_locked.num_vars);

            if mle_locked.num_vars != self.aux_info.num_variables {
                return Err(ArithErrors::InvalidParameters(format!(
                    "product has a multiplicand with wrong number of variables {} vs {}",
                    mle_locked.num_vars, self.aux_info.num_variables
                )));
            }

            let mle_ptr: *const Mutex<DenseMLPolyStream<F>> = Arc::as_ptr(&mle);
            if let Some(index) = self.raw_pointers_lookup_table.get(&mle_ptr) {
                indexed_product.push(*index);
                // println!("mle_ptr existing: {:p}", mle_ptr);
            } else {
                let curr_index = self.flattened_ml_extensions.len();
                self.flattened_ml_extensions.push(mle.clone());
                // println!("mle_ptr: {:p}, curr_index: {}", mle_ptr, curr_index);
                self.raw_pointers_lookup_table.insert(mle_ptr, curr_index);
                indexed_product.push(curr_index);
            }
        }
        // println!("self.products: {:?}", &indexed_product);
        self.products.push((coefficient, indexed_product));
        Ok(())
    }

    /// Multiple the current VirtualPolynomial by an MLE:
    /// - add the MLE to the MLE list;
    /// - multiple each product by MLE and its coefficient.
    /// Returns an error if the MLE has a different `num_vars` from self.
    pub fn mul_by_mle(
        &mut self,
        mle: Arc<Mutex<DenseMLPolyStream<F>>>,
        coefficient: F,
    ) -> Result<(), ArithErrors> {
        let start = start_timer!(|| "mul by mle");

        let mle_locked = mle.lock().expect("Failed to lock mutex");

        if mle_locked.num_vars != self.aux_info.num_variables {
            return Err(ArithErrors::InvalidParameters(format!(
                "product has a multiplicand with wrong number of variables {} vs {}",
                mle_locked.num_vars, self.aux_info.num_variables
            )));
        }

        drop(mle_locked); // Release the lock

        let mle_ptr: *const Mutex<DenseMLPolyStream<F>> = Arc::as_ptr(&mle);

        // check if this mle already exists in the virtual polynomial
        let mle_index = match self.raw_pointers_lookup_table.get(&mle_ptr) {
            Some(&p) => p,
            None => {
                self.raw_pointers_lookup_table
                    .insert(mle_ptr, self.flattened_ml_extensions.len());
                self.flattened_ml_extensions.push(mle);
                self.flattened_ml_extensions.len() - 1
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
    pub fn evaluate(&self, point: &[F]) -> Result<F, ArithErrors> {
        let start = start_timer!(|| "evaluation");

        // if self.aux_info.num_variables != point.len() {
        //     return Err(ArithErrors::InvalidParameters(format!(
        //         "wrong number of variables {} vs {}",
        //         self.aux_info.num_variables,
        //         point.len()
        //     )));
        // }

        // print point len and self.aux_info.num_variables
        // println!("virtual poly `evaluate()`: point len: {}, self.aux_info.num_variables: {}", point.len(), self.aux_info.num_variables);

        let evals: Vec<F> = self
            .flattened_ml_extensions
            .iter()
            .map(|x| {
                // print num_vars
                // let num_vars = x.lock().unwrap().num_vars;
                // println!("virtual poly `evaluate()`: num_vars: {}", num_vars);

                x.lock()
                    .expect("Failed to lock mutex")
                    .evaluate(point)
                    .unwrap() // safe unwrap here since we have
                              // already checked that num_var
                              // matches
            })
            .collect();

        let res = self
            .products
            .iter()
            .map(|(c, p)| *c * p.iter().map(|&i| evals[i]).product::<F>())
            .sum();

        end_timer!(start);
        Ok(res)
    }

    // For testing only
    // because our evaluate function updates the stream, after all streams are evaluated, the result will be one single value in each stream
    // this function calculates the evaluation result of the VirtualPolynomial without needing a point
    pub fn evaluate_single_field_streams(&self) -> Result<F, ArithErrors> {
        let start = start_timer!(|| "evaluation");

        // if self.aux_info.num_variables != point.len() {
        //     return Err(ArithErrors::InvalidParameters(format!(
        //         "wrong number of variables {} vs {}",
        //         self.aux_info.num_variables,
        //         point.len()
        //     )));
        // }

        // print point len and self.aux_info.num_variables
        // println!("virtual poly `evaluate()`: point len: {}, self.aux_info.num_variables: {}", point.len(), self.aux_info.num_variables);

        let evals: Vec<F> = self
            .flattened_ml_extensions
            .iter()
            .map(|x| {
                // print num_vars
                // let num_vars = x.lock().unwrap().num_vars;
                // println!("virtual poly `evaluate()`: num_vars: {}", num_vars);
                let mut locked_stream = x.lock().expect("Lock failed");
                let field = locked_stream.read_next().unwrap();
                locked_stream.read_restart();
                drop(locked_stream);
                field
            })
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
    ) -> Result<(Self, F), ArithErrors> {
        let start = start_timer!(|| "sample random virtual polynomial");

        let mut sum = F::zero();
        let mut poly = VirtualPolynomial::new(nv);
        for _ in 0..num_products {
            let num_multiplicands =
                rng.gen_range(num_multiplicands_range.0..num_multiplicands_range.1);
            let (product, product_sum) =
                DenseMLPolyStream::random_mle_list(nv, num_multiplicands, rng, None, None);
            let coefficient = F::rand(rng);
            // let coefficient = F::one();
            poly.add_mle_list(product.into_iter(), coefficient)?;
            sum += product_sum * coefficient;
        }

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
    ) -> Result<Self, ArithErrors> {
        let mut poly = VirtualPolynomial::new(nv);
        for _ in 0..num_products {
            let num_multiplicands =
                rng.gen_range(num_multiplicands_range.0..num_multiplicands_range.1);
            let product = DenseMLPolyStream::random_zero_mle_list(nv, num_multiplicands, rng);
            let coefficient = F::rand(rng);
            poly.add_mle_list(product.into_iter(), coefficient)?;
        }

        // print products of self.products
        // poly.products.iter().for_each(|(_, p)| {
        //     println!("rand_zero product: {:?}", p);
        // });

        Ok(poly)
    }

    // Input poly f(x) and a random vector r, output
    //      \hat f(x) = \sum_{x_i \in eval_x} f(x_i) eq(x, r)
    // where
    //      eq(x,y) = \prod_i=1^num_var (x_i * y_i + (1-x_i)*(1-y_i))
    //
    // This function is used in ZeroCheck.
    pub fn build_f_hat(&self, r: &[F]) -> Result<Self, ArithErrors> {
        let start = start_timer!(|| "build and multiply by eq_x_r polynomial");

        if self.aux_info.num_variables != r.len() {
            return Err(ArithErrors::InvalidParameters(format!(
                "r.len() is different from number of variables: {} vs {}",
                r.len(),
                self.aux_info.num_variables
            )));
        }

        let eq_x_r = build_eq_x_r(r)?;

        // print read pointer of eq_x_r
        // let read_pos = eq_x_r.lock().unwrap().read_pointer.stream_position().unwrap();
        // println!("build_f_hat eq_x_r read pointer: {}", read_pos);

        let mut res = self.clone();
        res.mul_by_mle(eq_x_r, F::one())?;

        end_timer!(start);
        Ok(res)
    }

    //     /// Print out the evaluation map for testing. Panic if the num_vars > 5.
    //     pub fn print_evals(&self) {
    //         if self.aux_info.num_variables > 5 {
    //             panic!("this function is used for testing only. cannot print more than 5 num_vars")
    //         }
    //         for i in 0..1 << self.aux_info.num_variables {
    //             let point = bit_decompose(i, self.aux_info.num_variables);
    //             let point_fr: Vec<F> = point.iter().map(|&x| F::from(x)).collect();
    //             println!("{} {}", i, self.evaluate(point_fr.as_ref()).unwrap())
    //         }
    //         println!()
    //     }
    // }

    pub fn build_perm_check_poly(
        h_p: Arc<Mutex<DenseMLPolyStream<F>>>,
        h_q: Arc<Mutex<DenseMLPolyStream<F>>>,
        p: Arc<Mutex<DenseMLPolyStream<F>>>,
        q: Arc<Mutex<DenseMLPolyStream<F>>>,
        pi: Arc<Mutex<DenseMLPolyStream<F>>>,
        index: Arc<Mutex<DenseMLPolyStream<F>>>,
        alpha: F,
        batch_factor: F,
        gamma: F,
    ) -> Result<VirtualPolynomial<F>, ArithErrors> {
        // conduct a batch zero check on t_1 and t_2
        // poly = t_1 + batch_factor * t_2 = h_p * (p + alpha * pi + gamma) - 1 + batch_factor * (h_q * (q + alpha * index + gamma) - 1)
        // = -1-batch_factor + h_p*p + h_p*alpha*pi + batch_factor*h_q*q + batch_factor*h_q*alpha*index + gamma*h_p + gamma*batch_factor*h_q
        let num_vars = h_p.lock().unwrap().num_vars;

        let mut poly = VirtualPolynomial::new_from_mle(
            &DenseMLPolyStream::const_mle(-batch_factor - F::ONE, num_vars, None, None),
            F::one(),
        );
        poly.add_mle_list(vec![h_p.clone(), p], F::one()).unwrap();
        poly.add_mle_list(vec![h_p.clone(), pi], alpha).unwrap();
        poly.add_mle_list(vec![h_q.clone(), q], batch_factor)
            .unwrap();
        poly.add_mle_list(vec![h_q.clone(), index], alpha * batch_factor)
            .unwrap();
        poly.add_mle_list(vec![h_p], gamma).unwrap();
        poly.add_mle_list(vec![h_q], gamma * batch_factor).unwrap();

        Ok(poly)
    }

    pub fn build_perm_check_poly_plonk(
        h_p: Vec<Arc<Mutex<DenseMLPolyStream<F>>>>,
        h_q: Vec<Arc<Mutex<DenseMLPolyStream<F>>>>,
        p: Vec<Arc<Mutex<DenseMLPolyStream<F>>>>,
        pi: Vec<Arc<Mutex<DenseMLPolyStream<F>>>>,
        index: Vec<Arc<Mutex<DenseMLPolyStream<F>>>>,
        alpha: F,
        batch_factor: F,
        gamma: F,
    ) -> Result<VirtualPolynomial<F>, ArithErrors> {
        // conduct a batch zero check on t_1 and t_2
        // poly = t_1 + batch_factor * t_2 = h_p * (p + alpha * pi) - 1 + batch_factor * (h_q * (q + alpha * index) - 1)
        // = -1-batch_factor + h_p*p + h_p*alpha*pi + batch_factor*h_q*q + batch_factor*h_q*alpha*index
        let num_vars = h_p[0].lock().unwrap().num_vars;

        // // print num_vars
        // println!("p num_vars: {}", num_vars);
        // // print each element of h_p
        // let mut h_p_lock = h_p.lock().unwrap();
        // while let Some(val) = h_p_lock.read_next() {
        //     println!("h_p val: {}", val);
        // }
        // drop(h_p_lock);
        // // print each element of pi
        // let mut pi_lock = pi.lock().unwrap();
        // while let Some(val) = pi_lock.read_next() {
        //     println!("pi val: {}", val);
        // }
        // // print pi num_vars
        // println!("pi num_vars: {}", pi_lock.num_vars);
        // drop(pi_lock);

        // create constant = - 1 - batch_factor - batch_factor ^ 2 - ... - batch_factor ^ (num_vars - 1)
        let mut constant = F::one();
        let mut batch_factor_power = batch_factor;
        for _ in 0..num_vars {
            constant += batch_factor_power;
            batch_factor_power *= batch_factor;
        }

        let mut poly = VirtualPolynomial::new_from_mle(
            &DenseMLPolyStream::const_mle(constant, num_vars, None, None),
            F::one(),
        );

        let mut batch_factor_lower_power = F::one();
        let mut batch_factor_higher_power = batch_factor;

        for i in 0..h_p.len() {
            poly.add_mle_list(vec![h_p[i].clone(), p[i].clone()], batch_factor_lower_power)
                .unwrap();
            poly.add_mle_list(vec![h_p[i].clone(), pi[i].clone()], batch_factor_lower_power * alpha)
                .unwrap();
            poly.add_mle_list(vec![h_q[i].clone(), p[i].clone()], batch_factor_higher_power).unwrap();
            poly.add_mle_list(vec![h_q[i].clone(), index[i].clone()], batch_factor_higher_power * alpha)
                .unwrap();
            poly.add_mle_list(vec![h_p[i].clone()], batch_factor_lower_power * gamma);
            poly.add_mle_list(vec![h_q[i].clone()], batch_factor_higher_power * gamma).unwrap();
            
            batch_factor_lower_power = batch_factor_lower_power * batch_factor * batch_factor;
            batch_factor_higher_power = batch_factor_higher_power * batch_factor * batch_factor;
        }

        Ok(poly)
    }

    // same as build_perm_check_poly_plonk except that it adds to an existing virtual poly
    // just to sketch up the prover quickly for benchmark, should be removed
    // and replaced with a proper adding two virtual polynomials function
    pub fn add_build_perm_check_poly_plonk(
        self: &mut VirtualPolynomial<F>,
        h_p: Vec<Arc<Mutex<DenseMLPolyStream<F>>>>,
        h_q: Vec<Arc<Mutex<DenseMLPolyStream<F>>>>,
        p: Vec<Arc<Mutex<DenseMLPolyStream<F>>>>,
        pi: Vec<Arc<Mutex<DenseMLPolyStream<F>>>>,
        index: Vec<Arc<Mutex<DenseMLPolyStream<F>>>>,
        alpha: F,
        batch_factor: F,
        gamma: F,
    ) -> Result<(), ArithErrors> {

        let start = start_timer!(|| "build perm check batch zero check polynomial");
        // conduct a batch zero check on t_1 and t_2
        // poly = t_1 + batch_factor * t_2 = h_p * (p + alpha * pi) - 1 + batch_factor * (h_q * (q + alpha * index) - 1)
        // = -1-batch_factor + h_p*p + h_p*alpha*pi + batch_factor*h_q*q + batch_factor*h_q*alpha*index
        let num_vars = h_p[0].lock().unwrap().num_vars;

        // // print num_vars
        // println!("p num_vars: {}", num_vars);
        // // print each element of h_p
        // let mut h_p_lock = h_p.lock().unwrap();
        // while let Some(val) = h_p_lock.read_next() {
        //     println!("h_p val: {}", val);
        // }
        // drop(h_p_lock);
        // // print each element of pi
        // let mut pi_lock = pi.lock().unwrap();
        // while let Some(val) = pi_lock.read_next() {
        //     println!("pi val: {}", val);
        // }
        // // print pi num_vars
        // println!("pi num_vars: {}", pi_lock.num_vars);
        // drop(pi_lock);

        // create constant = - batch_factor - batch_factor ^ 2 - ... - batch_factor ^ (h_p.len() * 2)
        let mut constant = -batch_factor;
        let mut batch_factor_power = -batch_factor * batch_factor;
        for _ in 0..(h_p.len() * 2 - 1) {
            constant += batch_factor_power;
            batch_factor_power *= batch_factor;
        }

        let mut constant_mle = 
            DenseMLPolyStream::const_mle(constant, num_vars, None, None);

        self.add_mle_list(vec![constant_mle], F::one()).unwrap();

        let mut batch_factor_lower_power = batch_factor;
        let mut batch_factor_higher_power = batch_factor * batch_factor;

        for i in 0..h_p.len() {
            self.add_mle_list(vec![h_p[i].clone(), p[i].clone()], batch_factor_lower_power)
                .unwrap();
            self.add_mle_list(vec![h_p[i].clone(), pi[i].clone()], batch_factor_lower_power * alpha)
                .unwrap();
            self.add_mle_list(vec![h_q[i].clone(), p[i].clone()], batch_factor_higher_power).unwrap();
            self.add_mle_list(vec![h_q[i].clone(), index[i].clone()], batch_factor_higher_power * alpha)
                .unwrap();
            self.add_mle_list(vec![h_p[i].clone()], batch_factor_lower_power * gamma);
            self.add_mle_list(vec![h_q[i].clone()], batch_factor_higher_power * gamma).unwrap();
            
            batch_factor_lower_power = batch_factor_lower_power * batch_factor * batch_factor;
            batch_factor_higher_power = batch_factor_higher_power * batch_factor * batch_factor;
        }

        end_timer!(start);

        Ok(())
    }
}

/// merge a set of polynomials. Returns an error if the
/// polynomials do not share a same number of nvs.
pub fn merge_polynomials<F: PrimeField>(
    polynomials: &[WitnessColumn<F>],
    num_vars: usize,
) -> Result<Arc<Mutex<DenseMLPolyStream<F>>>, ArithErrors> {
    let vec_len = polynomials[0].0.len();
    // assert that vec_len is 2^num_vars
    if vec_len != (1 << num_vars) {
        return Err(ArithErrors::InvalidParameters(
            "merge_polynomial() input WitnessColumn length is not 2^num_vars".to_string(),
        ));
    }
    // target length is the ceiling of the log of the number of polynomials
    // we want to merge
    let target_num_vars = ((polynomials.len() as f64).log2().ceil() as usize) + num_vars;
    let mut scalars = vec![];
    for poly in polynomials.iter() {
        if vec_len != poly.0.len() {
            return Err(ArithErrors::InvalidParameters(
                "num_vars do not match for polynomials".to_string(),
            ));
        }
        scalars.extend_from_slice(poly.0.as_slice());
    }

    scalars.extend_from_slice(vec![F::zero(); (1 << target_num_vars) - scalars.len()].as_ref());
    Ok(Arc::new(Mutex::new(
        DenseMLPolyStream::from_evaluations_vec(target_num_vars, scalars, None, None),
    )))
}

/// This function build the eq(x, r) polynomial for any given r.
///
/// Evaluate
///      eq(x,y) = \prod_i=1^num_var (x_i * y_i + (1-x_i)*(1-y_i))
/// over r, which is
///      eq(x,y) = \prod_i=1^num_var (x_i * r_i + (1-x_i)*(1-r_i))
pub fn build_eq_x_r<F: PrimeField>(
    r: &[F],
) -> Result<Arc<Mutex<DenseMLPolyStream<F>>>, ArithErrors> {
    let mut stream: DenseMLPolyStream<F> = DenseMLPolyStream::new(r.len(), None, None);

    let _ = build_eq_x_r_helper(r, &mut stream);

    // print all elements of the stream
    // while let Some(val) = stream.read_next() {
    //     println!("final eq_x_r val: {}", val);
    // }
    // stream.read_restart();

    Ok(Arc::new(Mutex::new(stream)))
}
/// This function build the eq(x, r) polynomial for any given r, and output the
/// evaluation of eq(x, r) in its vector form.
///
/// Evaluate
///      eq(x,y) = \prod_i=1^num_var (x_i * y_i + (1-x_i)*(1-y_i))
/// over r, which is
///      eq(x,y) = \prod_i=1^num_var (x_i * r_i + (1-x_i)*(1-r_i))
// pub fn build_eq_x_r_vec<F: PrimeField>(r: &[F]) -> Result<Vec<F>, ArithErrors> {
//     // we build eq(x,r) from its evaluations
//     // we want to evaluate eq(x,r) over x \in {0, 1}^num_vars
//     // for example, with num_vars = 4, x is a binary vector of 4, then
//     //  0 0 0 0 -> (1-r0)   * (1-r1)    * (1-r2)    * (1-r3)
//     //  1 0 0 0 -> r0       * (1-r1)    * (1-r2)    * (1-r3)
//     //  0 1 0 0 -> (1-r0)   * r1        * (1-r2)    * (1-r3)
//     //  1 1 0 0 -> r0       * r1        * (1-r2)    * (1-r3)
//     //  ....
//     //  1 1 1 1 -> r0       * r1        * r2        * r3
//     // we will need 2^num_var evaluations

//     let mut eval = Vec::new();
//     build_eq_x_r_helper(r, &mut eval)?;

//     Ok(eval)
// }

/// A helper function to build eq(x, r) recursively.
/// This function takes `r.len()` steps, and for each step it requires a maximum
/// `r.len()-1` multiplications.
fn build_eq_x_r_helper<F: PrimeField>(
    r: &[F],
    buf: &mut DenseMLPolyStream<F>,
) -> Result<(), ArithErrors> {
    if r.is_empty() {
        return Err(ArithErrors::InvalidParameters("r length is 0".to_string()));
    } else if r.len() == 1 {
        // println!("CASE r.len == 1");
        // initializing the buffer with [1-r_0, r_0]
        buf.write_next_unchecked(F::one() - r[0]);
        buf.write_next_unchecked(r[0]);

        buf.swap_read_write();

        // print all read elements and restart read
        // while let Some(val) = buf.read_next() {
        //     println!("helper eq_x_r val: {}", val);
        // }
        // buf.read_restart();
    } else {
        // println!("CASE else");
        build_eq_x_r_helper(&r[1..], buf)?;

        // suppose at the previous step we received [b_1, ..., b_k]
        // for the current step we will need
        // if x_0 = 0:   (1-r0) * [b_1, ..., b_k]
        // if x_0 = 1:   r0 * [b_1, ..., b_k]
        // let mut res = vec![];
        // for &b_i in buf.iter() {
        //     let tmp = r[0] * b_i;
        //     res.push(b_i - tmp);
        //     res.push(tmp);
        // }
        // *buf = res;

        // using read_next_unchecked, because we write two elements for each element read
        while let Some(elem) = buf.read_next_unchecked() {
            // print elem
            // println!("helper eq_x_r elem: {}", elem);
            let tmp = r[0] * elem;
            buf.write_next_unchecked(elem - tmp);
            buf.write_next_unchecked(tmp);
        }
        buf.swap_read_write();

        // print all read elements and restart read
        // while let Some(val) = buf.read_next() {
        //     println!("helper eq_x_r val: {}", val);
        // }
        buf.read_restart();
    }

    Ok(())
}

/// Evaluate eq polynomial.
pub fn eq_eval<F: PrimeField>(x: &[F], y: &[F]) -> Result<F, ArithErrors> {
    if x.len() != y.len() {
        return Err(ArithErrors::InvalidParameters(
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

pub fn identity_permutation<F: PrimeField>(num_vars: usize, num_chunks: usize) -> Vec<F> {
    let len = (num_chunks as u64) * (1u64 << num_vars);
    (0..len).map(F::from).collect()
}

#[cfg(test)]
mod test {
    use super::VirtualPolynomial;
    use super::*;
    use ark_ff::Field;
    use ark_ff::UniformRand;
    use ark_std::test_rng;
    use ark_bls12_381::Fr;

    #[test]
    fn test_merge_polynomials_success() {
        let polynomials = vec![
            WitnessColumn(vec![Fr::from(1), Fr::from(2), Fr::from(3), Fr::from(4)]),
            WitnessColumn(vec![Fr::from(4), Fr::from(5), Fr::from(6), Fr::from(7)]),
        ];
        let stream = merge_polynomials(&polynomials, 2).unwrap();

        // Fetch the stream's values for comparison using stream.lock().unwrap().read_next()
        let mut result_values = vec![];
        {
            let mut stream = stream.lock().unwrap();
            stream.read_restart(); // Ensure we start reading from the beginning
            while let Some(val) = stream.read_next() {
                result_values.push(val);
            }
        }
        // assert that result values are correct
        assert_eq!(
            result_values,
            vec![
                Fr::from(1),
                Fr::from(2),
                Fr::from(3),
                Fr::from(4),
                Fr::from(4),
                Fr::from(5),
                Fr::from(6),
                Fr::from(7)
            ]
        );
    }

    #[test]
    fn test_merge_polynomials_failure_due_to_different_nvs() {
        let polynomials = vec![
            WitnessColumn(vec![Fr::from(1), Fr::from(2), Fr::from(3)]),
            WitnessColumn(vec![Fr::from(4), Fr::from(5)]), // Different number of elements
        ];
        let result = merge_polynomials(&polynomials, 2);
        assert!(result.is_err());
    }

    #[test]
    fn test_merge_polynomials_odd_number() {
        let polynomials = vec![
            WitnessColumn(vec![Fr::from(1), Fr::from(2), Fr::from(3), Fr::from(4)]),
            WitnessColumn(vec![Fr::from(4), Fr::from(5), Fr::from(6), Fr::from(7)]),
            WitnessColumn(vec![Fr::from(4), Fr::from(5), Fr::from(6), Fr::from(7)]),
        ];
        let stream = merge_polynomials(&polynomials, 2).unwrap();

        // Fetch the stream's values for comparison using stream.lock().unwrap().read_next()
        let mut result_values = vec![];
        {
            let mut stream = stream.lock().unwrap();
            stream.read_restart(); // Ensure we start reading from the beginning
            while let Some(val) = stream.read_next() {
                result_values.push(val);
            }
        }
        // assert that result values are correct
        assert_eq!(
            result_values,
            vec![
                Fr::from(1),
                Fr::from(2),
                Fr::from(3),
                Fr::from(4),
                Fr::from(4),
                Fr::from(5),
                Fr::from(6),
                Fr::from(7),
                Fr::from(4),
                Fr::from(5),
                Fr::from(6),
                Fr::from(7),
                Fr::from(0),
                Fr::from(0),
                Fr::from(0),
                Fr::from(0)
            ]
        );
    }

    #[test]
    fn test_build_perm_check_poly() {
        // Setup sample values for alpha and r
        let alpha = Fr::from(11u64);
        let gamma = Fr::from(13u64);
        let r = Fr::from(12u64);

        // Setup sample streams for h_p, h_q, p, q, and pi
        let h_p = Arc::new(Mutex::new(DenseMLPolyStream::from_evaluations_vec(
            1,
            vec![Fr::from(1u64), Fr::from(2u64)],
            None,
            None,
        )));
        let h_q = Arc::new(Mutex::new(DenseMLPolyStream::from_evaluations_vec(
            1,
            vec![Fr::from(3u64), Fr::from(4u64)],
            None,
            None,
        )));
        let p = Arc::new(Mutex::new(DenseMLPolyStream::from_evaluations_vec(
            1,
            vec![Fr::from(5u64), Fr::from(6u64)],
            None,
            None,
        )));
        let q = Arc::new(Mutex::new(DenseMLPolyStream::from_evaluations_vec(
            1,
            vec![Fr::from(7u64), Fr::from(8u64)],
            None,
            None,
        )));
        let pi = Arc::new(Mutex::new(DenseMLPolyStream::from_evaluations_vec(
            1,
            vec![Fr::from(9u64), Fr::from(10u64)],
            None,
            None,
        )));
        let index = Arc::new(Mutex::new(DenseMLPolyStream::from_evaluations_vec(
            1,
            vec![Fr::from(13u64), Fr::from(14u64)],
            None,
            None,
        )));

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
            result_poly.flattened_ml_extensions.len(),
            7,
            "Mismatch in flattened_ml_extensions length"
        );
        assert_eq!(
            result_poly.raw_pointers_lookup_table.len(),
            7,
            "Mismatch in raw_pointers_lookup_table length"
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
        let result_stream = build_eq_x_r(&r).expect("Failed to build eq(x, r)");

        // Fetch the stream's values for comparison
        let mut result_values = vec![];
        {
            let mut stream = result_stream.lock().unwrap();
            stream.read_restart(); // Ensure we start reading from the beginning
            while let Some(val) = stream.read_next() {
                result_values.push(val);
            }
        }

        // Assertion
        assert_eq!(
            expected_stream.len(),
            result_values.len(),
            "Stream lengths do not match"
        );
        for (expected, result) in expected_stream.iter().zip(result_values.iter()) {
            assert_eq!(expected, result, "Stream values do not match");
        }
    }

    #[test]
    fn test_virtual_polynomial_mul_by_mle() -> Result<(), ArithErrors> {
        let mut rng = test_rng();
        for nv in 2..5 {
            for num_products in 2..5 {
                let base: Vec<Fr> = (0..nv).map(|_| Fr::rand(&mut rng)).collect();

                let (a, _a_sum) =
                    VirtualPolynomial::<Fr>::rand(nv, (2, 3), num_products, &mut rng)?;
                let (b, _b_sum) = DenseMLPolyStream::random_mle_list(nv, 1, &mut rng, None, None);
                let b_mle = b[0].clone();
                let coeff = Fr::rand(&mut rng);
                let b_vp = VirtualPolynomial::new_from_mle(&b_mle, coeff);

                let mut c = a.clone();

                c.mul_by_mle(b_mle, coeff)?;

                assert_eq!(
                    a.evaluate(base.as_ref())? * b_vp.evaluate(base.as_ref())?,
                    c.evaluate_single_field_streams()?
                );
            }
        }

        Ok(())
    }
}
