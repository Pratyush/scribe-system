// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Circuit implementation for arithmetic extensions

use super::utils::next_multiple;
use crate::{
    Circuit, CircuitError, PlonkCircuit, Variable,
    constants::{GATE_WIDTH, N_MUL_SELECTORS},
    gates::{
        ConstantAdditionGate, ConstantMultiplicationGate, FifthRootGate, LinCombGate, MulAddGate,
        QuadPolyGate,
    },
};
use ark_std::{borrow::ToOwned, boxed::Box, string::ToString, vec::Vec};
use scribe_streams::serialize::RawPrimeField;

impl<F: RawPrimeField> PlonkCircuit<F> {
    /// Arithmetic gates
    ///
    /// Quadratic polynomial gate: q1 * a + q2 * b + q3 * c + q4 * d + q12 * a *
    /// b + q34 * c * d + q_c = q_o * e, where q1, q2, q3, q4, q12, q34,
    /// q_c, q_o are selectors; a, b, c, d are input wires; e is the output
    /// wire. Return error if variables are invalid.
    pub fn quad_poly_gate(
        &mut self,
        wires: &[Variable; GATE_WIDTH + 1],
        q_lc: &[F; GATE_WIDTH],
        q_mul: &[F; N_MUL_SELECTORS],
        q_o: F,
        q_c: F,
    ) -> Result<(), CircuitError> {
        self.check_vars_bound(wires)?;

        self.insert_gate(
            wires,
            Box::new(QuadPolyGate {
                q_lc: *q_lc,
                q_mul: *q_mul,
                q_o,
                q_c,
            }),
        )?;
        Ok(())
    }

    /// Arithmetic gates
    ///
    /// Quadratic polynomial gate:
    /// e = q1 * a + q2 * b + q3 * c + q4 * d + q12 * a *
    /// b + q34 * c * d + q_c, where q1, q2, q3, q4, q12, q34,
    /// q_c are selectors; a, b, c, d are input wires
    ///
    /// Return the variable for
    /// Return error if variables are invalid.
    pub fn gen_quad_poly(
        &mut self,
        wires: &[Variable; GATE_WIDTH],
        q_lc: &[F; GATE_WIDTH],
        q_mul: &[F; N_MUL_SELECTORS],
        q_c: F,
    ) -> Result<Variable, CircuitError> {
        self.check_vars_bound(wires)?;
        let output_val = q_lc[0] * self.witness(wires[0])?
            + q_lc[1] * self.witness(wires[1])?
            + q_lc[2] * self.witness(wires[2])?
            + q_lc[3] * self.witness(wires[3])?
            + q_mul[0] * self.witness(wires[0])? * self.witness(wires[1])?
            + q_mul[1] * self.witness(wires[2])? * self.witness(wires[3])?
            + q_c;
        let output_var = self.create_variable(output_val)?;
        let wires = [wires[0], wires[1], wires[2], wires[3], output_var];

        self.insert_gate(
            &wires,
            Box::new(QuadPolyGate {
                q_lc: *q_lc,
                q_mul: *q_mul,
                q_o: F::one(),
                q_c,
            }),
        )?;

        Ok(output_var)
    }

    /// Constrain a linear combination gate:
    /// q1 * a + q2 * b + q3 * c + q4 * d  = y
    pub fn lc_gate(
        &mut self,
        wires: &[Variable; GATE_WIDTH + 1],
        coeffs: &[F; GATE_WIDTH],
    ) -> Result<(), CircuitError> {
        self.check_vars_bound(wires)?;

        let wire_vars = [wires[0], wires[1], wires[2], wires[3], wires[4]];
        self.insert_gate(&wire_vars, Box::new(LinCombGate { coeffs: *coeffs }))?;
        Ok(())
    }

    /// Obtain a variable representing a linear combination.
    /// Return error if variables are invalid.
    pub fn lc(
        &mut self,
        wires_in: &[Variable; GATE_WIDTH],
        coeffs: &[F; GATE_WIDTH],
    ) -> Result<Variable, CircuitError> {
        self.check_vars_bound(wires_in)?;

        let vals_in: Vec<F> = wires_in
            .iter()
            .map(|&var| self.witness(var))
            .collect::<Result<Vec<_>, CircuitError>>()?;

        // calculate y as the linear combination of coeffs and vals_in
        let y_val = vals_in
            .iter()
            .zip(coeffs.iter())
            .map(|(&val, &coeff)| val * coeff)
            .sum();
        let y = self.create_variable(y_val)?;

        let wires = [wires_in[0], wires_in[1], wires_in[2], wires_in[3], y];
        self.lc_gate(&wires, coeffs)?;
        Ok(y)
    }

    /// Constrain a mul-addition gate:
    /// q_muls\[0\] * wires\[0\] *  wires\[1\] +  q_muls\[1\] * wires\[2\] *
    /// wires\[3\] = wires\[4\]
    pub fn mul_add_gate(
        &mut self,
        wires: &[Variable; GATE_WIDTH + 1],
        q_muls: &[F; N_MUL_SELECTORS],
    ) -> Result<(), CircuitError> {
        self.check_vars_bound(wires)?;

        let wire_vars = [wires[0], wires[1], wires[2], wires[3], wires[4]];
        self.insert_gate(&wire_vars, Box::new(MulAddGate { coeffs: *q_muls }))?;
        Ok(())
    }

    /// Obtain a variable representing `q12 * a * b + q34 * c * d`,
    /// where `a, b, c, d` are input wires, and `q12`, `q34` are selectors.
    /// Return error if variables are invalid.
    pub fn mul_add(
        &mut self,
        wires_in: &[Variable; GATE_WIDTH],
        q_muls: &[F; N_MUL_SELECTORS],
    ) -> Result<Variable, CircuitError> {
        self.check_vars_bound(wires_in)?;

        let vals_in: Vec<F> = wires_in
            .iter()
            .map(|&var| self.witness(var))
            .collect::<Result<Vec<_>, CircuitError>>()?;

        // calculate y as the mul-addition of coeffs and vals_in
        let y_val = q_muls[0] * vals_in[0] * vals_in[1] + q_muls[1] * vals_in[2] * vals_in[3];
        let y = self.create_variable(y_val)?;

        let wires = [wires_in[0], wires_in[1], wires_in[2], wires_in[3], y];
        self.mul_add_gate(&wires, q_muls)?;
        Ok(y)
    }

    /// Obtain a variable representing the sum of a list of variables.
    /// Return error if variables are invalid.
    pub fn sum(&mut self, elems: &[Variable]) -> Result<Variable, CircuitError> {
        if elems.is_empty() {
            return Err(CircuitError::ParameterError(
                "Sum over an empty slice of variables is undefined".to_string(),
            ));
        }
        self.check_vars_bound(elems)?;

        let sum = {
            let sum_val: F = elems
                .iter()
                .map(|&elem| self.witness(elem))
                .collect::<Result<Vec<_>, CircuitError>>()?
                .iter()
                .sum();
            self.create_variable(sum_val)?
        };

        // pad to ("next multiple of 3" + 1) in length
        let mut padded: Vec<Variable> = elems.to_owned();
        let rate = GATE_WIDTH - 1; // rate at which each lc add
        let padded_len = next_multiple(elems.len() - 1, rate)? + 1;
        padded.resize(padded_len, self.zero());

        // z_0 = = x_0
        // z_i = z_i-1 + x_3i-2 + x_3i-1 + x_3i
        let coeffs = [F::one(); GATE_WIDTH];
        let mut accum = padded[0];
        for i in 1..padded_len / rate {
            accum = self.lc(
                &[
                    accum,
                    padded[rate * i - 2],
                    padded[rate * i - 1],
                    padded[rate * i],
                ],
                &coeffs,
            )?;
        }
        // final round
        let wires = [
            accum,
            padded[padded_len - 3],
            padded[padded_len - 2],
            padded[padded_len - 1],
            sum,
        ];
        self.lc_gate(&wires, &coeffs)?;

        Ok(sum)
    }

    /// Constrain variable `y` to the addition of `a` and `c`, where `c` is a
    /// constant value Return error if the input variables are invalid.
    pub fn add_constant_gate(
        &mut self,
        x: Variable,
        c: F,
        y: Variable,
    ) -> Result<(), CircuitError> {
        self.check_var_bound(x)?;
        self.check_var_bound(y)?;

        let wire_vars = &[x, self.one(), 0, 0, y];
        self.insert_gate(wire_vars, Box::new(ConstantAdditionGate(c)))?;
        Ok(())
    }

    /// Obtains a variable representing an addition with a constant value
    /// Return error if the input variable is invalid
    pub fn add_constant(
        &mut self,
        input_var: Variable,
        elem: &F,
    ) -> Result<Variable, CircuitError> {
        self.check_var_bound(input_var)?;

        let input_val = self.witness(input_var).unwrap();
        let output_val = *elem + input_val;
        let output_var = self.create_variable(output_val).unwrap();

        self.add_constant_gate(input_var, *elem, output_var)?;

        Ok(output_var)
    }

    /// Constrain variable `y` to the product of `a` and `c`, where `c` is a
    /// constant value Return error if the input variables are invalid.
    pub fn mul_constant_gate(
        &mut self,
        x: Variable,
        c: F,
        y: Variable,
    ) -> Result<(), CircuitError> {
        self.check_var_bound(x)?;
        self.check_var_bound(y)?;

        let wire_vars = &[x, 0, 0, 0, y];
        self.insert_gate(wire_vars, Box::new(ConstantMultiplicationGate(c)))?;
        Ok(())
    }

    /// Obtains a variable representing a multiplication with a constant value
    /// Return error if the input variable is invalid
    pub fn mul_constant(
        &mut self,
        input_var: Variable,
        elem: &F,
    ) -> Result<Variable, CircuitError> {
        self.check_var_bound(input_var)?;

        let input_val = self.witness(input_var).unwrap();
        let output_val = *elem * input_val;
        let output_var = self.create_variable(output_val).unwrap();

        self.mul_constant_gate(input_var, *elem, output_var)?;

        Ok(output_var)
    }

    /// Return a variable to be the 11th power of the input variable.
    /// Cost: 3 constraints.
    pub fn power_11_gen(&mut self, x: Variable) -> Result<Variable, CircuitError> {
        self.check_var_bound(x)?;

        // now we prove that x^11 = x_to_11
        let x_val = self.witness(x)?;
        let x_to_5_val = x_val.pow([5]);
        let x_to_5 = self.create_variable(x_to_5_val)?;
        let wire_vars = &[x, 0, 0, 0, x_to_5];
        self.insert_gate(wire_vars, Box::new(FifthRootGate))?;

        let x_to_10 = self.mul(x_to_5, x_to_5)?;
        self.mul(x_to_10, x)
    }

    /// Constraint a variable to be the 11th power of another variable.
    /// Cost: 3 constraints.
    pub fn power_11_gate(&mut self, x: Variable, x_to_11: Variable) -> Result<(), CircuitError> {
        self.check_var_bound(x)?;
        self.check_var_bound(x_to_11)?;

        // now we prove that x^11 = x_to_11
        let x_val = self.witness(x)?;
        let x_to_5_val = x_val.pow([5]);
        let x_to_5 = self.create_variable(x_to_5_val)?;
        let wire_vars = &[x, 0, 0, 0, x_to_5];
        self.insert_gate(wire_vars, Box::new(FifthRootGate))?;

        let x_to_10 = self.mul(x_to_5, x_to_5)?;
        self.mul_gate(x_to_10, x, x_to_11)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{Circuit, CircuitError, PlonkCircuit, constants::GATE_WIDTH};
    use ark_bls12_377::Fq as Fq377;
    use ark_ed_on_bls12_377::Fq as FqEd377;
    use ark_ed_on_bls12_381::Fq as FqEd381;
    use ark_ed_on_bn254::Fq as FqEd254;
    use ark_std::{vec, vec::Vec};
    use jf_utils::test_rng;

    #[test]
    fn test_quad_poly_gate() -> Result<(), CircuitError> {
        test_quad_poly_gate_helper::<FqEd254>()?;
        test_quad_poly_gate_helper::<FqEd377>()?;
        test_quad_poly_gate_helper::<FqEd381>()?;
        test_quad_poly_gate_helper::<Fq377>()
    }
    fn test_quad_poly_gate_helper<F: RawPrimeField>() -> Result<(), CircuitError> {
        let mut circuit: PlonkCircuit<F> = PlonkCircuit::new_in_prove_mode(true);
        let q_lc = [F::from(2u32), F::from(3u32), F::from(5u32), F::from(2u32)];
        let q_mul = [F::one(), F::from(2u8)];
        let q_o = F::one();
        let q_c = F::from(9u8);
        let wires_1: Vec<_> = [
            F::from(23u32),
            F::from(8u32),
            F::from(1u32),
            -F::from(20u32),
            F::from(188u32),
        ]
        .iter()
        .map(|val| circuit.create_variable(*val).unwrap())
        .collect();
        let wires_2: Vec<_> = [
            F::zero(),
            -F::from(8u32),
            F::from(1u32),
            F::zero(),
            -F::from(10u32),
        ]
        .iter()
        .map(|val| circuit.create_variable(*val).unwrap())
        .collect();

        // 23 * 2 + 8 * 3 + 1 * 5 + (-20) * 2 + 23 * 8 + 2 * 1 * (-20) + 9 = 188
        let var = wires_1[0];
        circuit.quad_poly_gate(&wires_1.try_into().unwrap(), &q_lc, &q_mul, q_o, q_c)?;
        // 0 * 2 + (-8) * 3 + 1 * 5 + 0 * 2 + 0 * -8 + 1 * 0 + 9 = -10
        circuit.quad_poly_gate(&wires_2.try_into().unwrap(), &q_lc, &q_mul, q_o, q_c)?;
        assert!(circuit.check_circuit_satisfiability(&[]).is_ok());
        *circuit.witness_mut(var) = F::from(34u32);
        assert!(circuit.check_circuit_satisfiability(&[]).is_err());
        // Check variable out of bound error.
        assert!(
            circuit
                .quad_poly_gate(&[0, 1, 1, circuit.num_vars(), 0], &q_lc, &q_mul, q_o, q_c)
                .is_err()
        );

        let _ = build_quad_poly_gate_circuit([
            -F::from(98973u32),
            F::from(4u32),
            F::zero(),
            F::from(79u32),
            F::one(),
        ])?;
        let _ = build_quad_poly_gate_circuit([
            F::one(),
            F::zero(),
            F::from(6u32),
            -F::from(9u32),
            F::one(),
        ])?;

        Ok(())
    }
    fn build_quad_poly_gate_circuit<F: RawPrimeField>(
        wires: [F; GATE_WIDTH + 1],
    ) -> Result<PlonkCircuit<F>, CircuitError> {
        let mut circuit: PlonkCircuit<F> = PlonkCircuit::new_in_prove_mode(true);
        let wires: Vec<_> = wires
            .iter()
            .map(|val| circuit.create_variable(*val).unwrap())
            .collect();
        let q_lc = [F::from(2u32), F::from(3u32), F::from(5u32), F::from(2u32)];
        let q_mul = [F::one(), F::from(2u8)];
        let q_o = F::one();
        let q_c = F::from(9u8);
        circuit.quad_poly_gate(&wires.try_into().unwrap(), &q_lc, &q_mul, q_o, q_c)?;
        circuit.finalize_for_arithmetization()?;
        Ok(circuit)
    }

    #[test]
    fn test_lc() -> Result<(), CircuitError> {
        test_lc_helper::<FqEd254>()?;
        test_lc_helper::<FqEd377>()?;
        test_lc_helper::<FqEd381>()?;
        test_lc_helper::<Fq377>()
    }
    fn test_lc_helper<F: RawPrimeField>() -> Result<(), CircuitError> {
        let mut circuit: PlonkCircuit<F> = PlonkCircuit::new_in_prove_mode(true);
        let wire_in_1: Vec<_> = [
            F::from(23u32),
            F::from(8u32),
            F::from(1u32),
            -F::from(20u32),
        ]
        .iter()
        .map(|val| circuit.create_variable(*val).unwrap())
        .collect();
        let wire_in_2: Vec<_> = [F::zero(), -F::from(8u32), F::from(1u32), F::zero()]
            .iter()
            .map(|val| circuit.create_variable(*val).unwrap())
            .collect();
        let coeffs = [F::from(2u32), F::from(3u32), F::from(5u32), F::from(2u32)];
        let y_1 = circuit.lc(&wire_in_1.try_into().unwrap(), &coeffs)?;
        let y_2 = circuit.lc(&wire_in_2.try_into().unwrap(), &coeffs)?;

        // 23 * 2 + 8 * 3 + 1 * 5 + (-20) * 2 = 35
        assert_eq!(circuit.witness(y_1)?, F::from(35u32));
        // 0 * 2 + (-8) * 3 + 1 * 5 + 0 * 2 = -19
        assert_eq!(circuit.witness(y_2)?, -F::from(19u32));
        assert!(circuit.check_circuit_satisfiability(&[]).is_ok());
        *circuit.witness_mut(y_1) = F::from(34u32);
        assert!(circuit.check_circuit_satisfiability(&[]).is_err());
        // Check variable out of bound error.
        assert!(circuit.lc(&[0, 1, 1, circuit.num_vars()], &coeffs).is_err());

        let _ = build_lc_circuit([-F::from(98973u32), F::from(4u32), F::zero(), F::from(79u32)])?;
        let _ = build_lc_circuit([F::one(), F::zero(), F::from(6u32), -F::from(9u32)])?;

        Ok(())
    }

    fn build_lc_circuit<F: RawPrimeField>(
        wires_in: [F; 4],
    ) -> Result<PlonkCircuit<F>, CircuitError> {
        let mut circuit: PlonkCircuit<F> = PlonkCircuit::new_in_prove_mode(true);
        let wires_in: Vec<_> = wires_in
            .iter()
            .map(|val| circuit.create_variable(*val).unwrap())
            .collect();
        let coeffs = [F::from(2u32), F::from(3u32), F::from(5u32), F::from(2u32)];
        circuit.lc(&wires_in.try_into().unwrap(), &coeffs)?;
        circuit.finalize_for_arithmetization()?;
        Ok(circuit)
    }

    #[test]
    fn test_mul_add() -> Result<(), CircuitError> {
        test_mul_add_helper::<FqEd254>()?;
        test_mul_add_helper::<FqEd377>()?;
        test_mul_add_helper::<FqEd381>()?;
        test_mul_add_helper::<Fq377>()
    }

    fn test_mul_add_helper<F: RawPrimeField>() -> Result<(), CircuitError> {
        let mut circuit = PlonkCircuit::<F>::new_in_prove_mode(true);
        let wire_in_1: Vec<_> = [
            F::from(23u32),
            F::from(8u32),
            F::from(1u32),
            -F::from(20u32),
        ]
        .iter()
        .map(|val| circuit.create_variable(*val).unwrap())
        .collect();
        let wire_in_2: Vec<_> = [F::one(), -F::from(8u32), F::one(), F::one()]
            .iter()
            .map(|val| circuit.create_variable(*val).unwrap())
            .collect();
        let q_muls = [F::from(3u32), F::from(5u32)];
        let y_1 = circuit.mul_add(&wire_in_1.try_into().unwrap(), &q_muls)?;
        let y_2 = circuit.mul_add(&wire_in_2.try_into().unwrap(), &q_muls)?;

        // 3 * (23 * 8) + 5 * (1 * -20) = 452
        assert_eq!(circuit.witness(y_1)?, F::from(452u32));
        // 3 * (1 * -8) + 5 * (1 * 1)= -19
        assert_eq!(circuit.witness(y_2)?, -F::from(19u32));
        assert!(circuit.check_circuit_satisfiability(&[]).is_ok());
        *circuit.witness_mut(y_1) = F::from(34u32);
        assert!(circuit.check_circuit_satisfiability(&[]).is_err());
        // Check variable out of bound error.
        assert!(
            circuit
                .mul_add(&[0, 1, 1, circuit.num_vars()], &q_muls)
                .is_err()
        );

        let _ =
            build_mul_add_circuit([-F::from(98973u32), F::from(4u32), F::zero(), F::from(79u32)])?;
        let _ = build_mul_add_circuit([F::one(), F::zero(), F::from(6u32), -F::from(9u32)])?;

        Ok(())
    }

    fn build_mul_add_circuit<F: RawPrimeField>(
        wires_in: [F; 4],
    ) -> Result<PlonkCircuit<F>, CircuitError> {
        let mut circuit = PlonkCircuit::new_in_prove_mode(true);
        let wires_in: Vec<_> = wires_in
            .iter()
            .map(|val| circuit.create_variable(*val).unwrap())
            .collect();
        let q_muls = [F::from(3u32), F::from(5u32)];
        circuit.mul_add(&wires_in.try_into().unwrap(), &q_muls)?;
        circuit.finalize_for_arithmetization()?;
        Ok(circuit)
    }

    #[test]
    fn test_sum() -> Result<(), CircuitError> {
        test_sum_helper::<FqEd254>()?;
        test_sum_helper::<FqEd377>()?;
        test_sum_helper::<FqEd381>()?;
        test_sum_helper::<Fq377>()
    }

    fn test_sum_helper<F: RawPrimeField>() -> Result<(), CircuitError> {
        let mut circuit: PlonkCircuit<F> = PlonkCircuit::new_in_prove_mode(true);
        let mut vars = vec![];
        for i in 0..11 {
            vars.push(circuit.create_variable(F::from(i as u32))?);
        }

        // sum over an empty array should be undefined behavior, thus fail
        assert!(circuit.sum(&[]).is_err());

        for until in 1..11 {
            let expected_sum = F::from((0..until).sum::<u32>());
            let sum = circuit.sum(&vars[..until as usize])?;
            assert_eq!(circuit.witness(sum)?, expected_sum);
        }
        assert!(circuit.check_circuit_satisfiability(&[]).is_ok());
        // if mess up the wire value, should fail
        *circuit.witness_mut(vars[5]) = F::one();
        assert!(circuit.check_circuit_satisfiability(&[]).is_err());
        // Check variable out of bound error.
        assert!(circuit.sum(&[circuit.num_vars()]).is_err());

        let _ = build_sum_circuit(vec![
            -F::from(73u32),
            F::from(4u32),
            F::zero(),
            F::from(79u32),
            F::from(23u32),
        ])?;
        let _ = build_sum_circuit(vec![
            F::one(),
            F::zero(),
            F::from(6u32),
            -F::from(9u32),
            F::one(),
        ])?;

        Ok(())
    }

    fn build_sum_circuit<F: RawPrimeField>(vals: Vec<F>) -> Result<PlonkCircuit<F>, CircuitError> {
        let mut circuit: PlonkCircuit<F> = PlonkCircuit::new_in_prove_mode(true);
        let mut vars = vec![];
        for val in vals {
            vars.push(circuit.create_variable(val)?);
        }
        circuit.sum(&vars[..])?;
        circuit.finalize_for_arithmetization()?;
        Ok(circuit)
    }

    #[test]
    fn test_power_11_gen_gate() -> Result<(), CircuitError> {
        test_power_11_gen_gate_helper::<FqEd254>()?;
        test_power_11_gen_gate_helper::<FqEd377>()?;
        test_power_11_gen_gate_helper::<FqEd381>()?;
        test_power_11_gen_gate_helper::<Fq377>()
    }
    fn test_power_11_gen_gate_helper<F: RawPrimeField>() -> Result<(), CircuitError> {
        let mut rng = test_rng();
        let x = F::rand(&mut rng);
        let y = F::rand(&mut rng);
        let x11 = x.pow([11]);

        // Create a satisfied circuit
        let mut circuit: PlonkCircuit<F> = PlonkCircuit::new_in_prove_mode(true);

        let x_var = circuit.create_variable(x)?;
        let x_to_11_var = circuit.create_variable(x11)?;

        let x_to_11_var_rec = circuit.power_11_gen(x_var)?;
        circuit.enforce_equal(x_to_11_var, x_to_11_var_rec)?;
        assert!(circuit.check_circuit_satisfiability(&[]).is_ok());

        // Create an unsatisfied circuit
        let mut circuit: PlonkCircuit<F> = PlonkCircuit::new_in_prove_mode(true);

        let y_var = circuit.create_variable(y)?;
        let x_to_11_var = circuit.create_variable(x11)?;

        let x_to_11_var_rec = circuit.power_11_gen(y_var)?;
        circuit.enforce_equal(x_to_11_var, x_to_11_var_rec)?;
        assert!(circuit.check_circuit_satisfiability(&[]).is_err());

        // Create an unsatisfied circuit
        let mut circuit: PlonkCircuit<F> = PlonkCircuit::new_in_prove_mode(true);
        let x_var = circuit.create_variable(x)?;
        let y_var = circuit.create_variable(y)?;

        let x_to_11_var_rec = circuit.power_11_gen(x_var)?;
        circuit.enforce_equal(y_var, x_to_11_var_rec)?;
        assert!(circuit.check_circuit_satisfiability(&[]).is_err());

        Ok(())
    }

    #[test]
    fn test_power_11_gate() -> Result<(), CircuitError> {
        test_power_11_gate_helper::<FqEd254>()?;
        test_power_11_gate_helper::<FqEd377>()?;
        test_power_11_gate_helper::<FqEd381>()?;
        test_power_11_gate_helper::<Fq377>()
    }
    fn test_power_11_gate_helper<F: RawPrimeField>() -> Result<(), CircuitError> {
        let mut rng = test_rng();
        let x = F::rand(&mut rng);
        let y = F::rand(&mut rng);
        let x11 = x.pow([11]);

        // Create a satisfied circuit
        let mut circuit: PlonkCircuit<F> = PlonkCircuit::new_in_prove_mode(true);
        let x_var = circuit.create_variable(x)?;
        let x_to_11_var = circuit.create_variable(x11)?;

        circuit.power_11_gate(x_var, x_to_11_var)?;
        assert!(circuit.check_circuit_satisfiability(&[]).is_ok());

        // Create an unsatisfied circuit
        let mut circuit: PlonkCircuit<F> = PlonkCircuit::new_in_prove_mode(true);
        let y_var = circuit.create_variable(y)?;
        let x_to_11_var = circuit.create_variable(x11)?;

        circuit.power_11_gate(y_var, x_to_11_var)?;
        assert!(circuit.check_circuit_satisfiability(&[]).is_err());

        // Create an unsatisfied circuit
        let mut circuit: PlonkCircuit<F> = PlonkCircuit::new_in_prove_mode(true);
        let x_var = circuit.create_variable(x)?;
        let y = circuit.create_variable(y)?;

        circuit.power_11_gate(x_var, y)?;
        assert!(circuit.check_circuit_satisfiability(&[]).is_err());

        Ok(())
    }

    #[test]
    fn test_arithmetization() -> Result<(), CircuitError> {
        test_arithmetization_helper::<FqEd254>()?;
        test_arithmetization_helper::<FqEd377>()?;
        test_arithmetization_helper::<FqEd381>()?;
        test_arithmetization_helper::<Fq377>()
    }

    fn test_arithmetization_helper<F: RawPrimeField>() -> Result<(), CircuitError> {
        // Create the circuit
        let mut circuit: PlonkCircuit<F> = PlonkCircuit::new_in_prove_mode(true);
        // is_equal gate
        let val = F::from(31415u32);
        let a = circuit.create_variable(val)?;
        let b = circuit.create_variable(val)?;
        circuit.is_equal(a, b)?;

        // lc gate
        let wire_in: Vec<_> = [
            F::from(23u32),
            F::from(8u32),
            F::from(1u32),
            -F::from(20u32),
        ]
        .iter()
        .map(|val| circuit.create_variable(*val).unwrap())
        .collect();
        let coeffs = [F::from(2u32), F::from(3u32), F::from(5u32), F::from(2u32)];
        circuit.lc(&wire_in.try_into().unwrap(), &coeffs)?;

        // conditional select gate
        let bit_true = circuit.create_boolean_variable(true)?;
        let x_0 = circuit.create_variable(F::from(23u32))?;
        let x_1 = circuit.create_variable(F::from(24u32))?;
        circuit.conditional_select(bit_true, x_0, x_1)?;

        // range gate
        let b = circuit.create_variable(F::from(1023u32))?;
        circuit.enforce_in_range(b, 10)?;

        // sum gate
        let mut vars = vec![];
        for i in 0..11 {
            vars.push(circuit.create_variable(F::from(i as u32))?);
        }
        circuit.sum(&vars[..vars.len()])?;

        // Finalize the circuit
        circuit.finalize_for_arithmetization()?;
        Ok(())
    }
}
