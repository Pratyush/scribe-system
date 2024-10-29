// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Definitions and constructions of plonk constraint system
use crate::{
    constants::{compute_coset_representatives, GATE_WIDTH, N_MUL_SELECTORS},
    gates::*,
    CircuitError,
    CircuitError::*,
};
use ark_ff::Field;
use ark_poly::{domain::Radix2EvaluationDomain, EvaluationDomain};
use ark_std::{boxed::Box, format, vec, vec::Vec};
use scribe_streams::{file_vec::FileVec, serialize::RawPrimeField};

/// An index to a gate in circuit.
pub type GateId = usize;
/// An index to the type of gate wires.
/// There are 4 different types of input gate wires (with indices 0..3),
/// 1 type of output gate wires (with index 4), and 1 type of lookup gate wires
/// (with index 5).
pub type WireId = usize;
/// An index to one of the witness values.
pub type Variable = usize;
/// An index to a witness value of boolean type.
#[derive(Debug, Clone, Copy)]
pub struct BoolVar(pub usize);

impl From<BoolVar> for Variable {
    fn from(bv: BoolVar) -> Self {
        bv.0
    }
}

impl BoolVar {
    /// Create a `BoolVar` without any check. Be careful!
    /// This is an internal API, shouldn't be used unless you know what you are
    /// doing. Normally you should only construct `BoolVar` through
    /// `Circuit::create_boolean_variable()`.
    pub(crate) fn new_unchecked(inner: usize) -> Self {
        Self(inner)
    }
}

/// An interface for Plonk constraint systems.
pub trait Circuit<F: Field> {
    /// The number of constraints.
    fn num_gates(&self) -> usize;

    /// The number of variables.
    fn num_vars(&self) -> usize;

    /// The number of public input variables.
    fn num_inputs(&self) -> usize;

    /// The number of wire types of the circuit.
    /// E.g., UltraPlonk has 4 different types of input wires, 1 type of output
    /// wires, and 1 type of lookup wires.
    fn num_wire_types(&self) -> usize;

    /// The list of public input values.
    fn public_input(&self) -> Result<Vec<F>, CircuitError>;

    /// Check circuit satisfiability against a public input.
    fn check_circuit_satisfiability(&self, pub_input: &[F]) -> Result<(), CircuitError>;

    /// Add a constant variable to the circuit; return the index of the
    /// variable.
    fn create_constant_variable(&mut self, val: F) -> Result<Variable, CircuitError>;

    /// Add a variable to the circuit; return the index of the variable.
    fn create_variable(&mut self, val: F) -> Result<Variable, CircuitError>;

    /// Add a bool variable to the circuit; return the index of the variable.
    fn create_boolean_variable(&mut self, val: bool) -> Result<BoolVar, CircuitError> {
        let val_scalar = if val { F::one() } else { F::zero() };
        let var = self.create_variable(val_scalar)?;
        self.enforce_bool(var)?;
        Ok(BoolVar(var))
    }

    /// Add a public input variable; return the index of the variable.
    fn create_public_variable(&mut self, val: F) -> Result<Variable, CircuitError>;

    /// Add a public bool variable to the circuit; return the index of the
    /// variable.
    fn create_public_boolean_variable(&mut self, val: bool) -> Result<BoolVar, CircuitError> {
        let val_scalar = if val { F::one() } else { F::zero() };
        let var = self.create_public_variable(val_scalar)?;
        Ok(BoolVar(var))
    }

    /// Set a variable to a public variable
    fn set_variable_public(&mut self, var: Variable) -> Result<(), CircuitError>;

    /// Return a default variable with value zero.
    fn zero(&self) -> Variable;

    /// Return a default variable with value one.
    fn one(&self) -> Variable;

    /// Return a default variable with value `false` (namely zero).
    fn false_var(&self) -> BoolVar {
        BoolVar::new_unchecked(self.zero())
    }

    /// Return a default variable with value `true` (namely one).
    fn true_var(&self) -> BoolVar {
        BoolVar::new_unchecked(self.one())
    }

    /// Return the witness value of variable `idx`.
    /// Return error if the input variable is invalid.
    fn witness(&self, idx: Variable) -> Result<F, CircuitError>;

    /// Common gates that should be implemented in any constraint systems.
    ///
    /// Constrain a variable to a constant.
    /// Return error if `var` is an invalid variable.
    fn enforce_constant(&mut self, var: Variable, constant: F) -> Result<(), CircuitError>;

    /// Constrain variable `c` to the addition of `a` and `b`.
    /// Return error if the input variables are invalid.
    fn add_gate(&mut self, a: Variable, b: Variable, c: Variable) -> Result<(), CircuitError>;

    /// Obtain a variable representing an addition.
    /// Return the index of the variable.
    /// Return error if the input variables are invalid.
    fn add(&mut self, a: Variable, b: Variable) -> Result<Variable, CircuitError>;

    /// Constrain variable `c` to the subtraction of `a` and `b`.
    /// Return error if the input variables are invalid.
    fn sub_gate(&mut self, a: Variable, b: Variable, c: Variable) -> Result<(), CircuitError>;

    /// Obtain a variable representing a subtraction.
    /// Return the index of the variable.
    /// Return error if the input variables are invalid.
    fn sub(&mut self, a: Variable, b: Variable) -> Result<Variable, CircuitError>;

    /// Constrain variable `c` to the multiplication of `a` and `b`.
    /// Return error if the input variables are invalid.
    fn mul_gate(&mut self, a: Variable, b: Variable, c: Variable) -> Result<(), CircuitError>;

    /// Obtain a variable representing a multiplication.
    /// Return the index of the variable.
    /// Return error if the input variables are invalid.
    fn mul(&mut self, a: Variable, b: Variable) -> Result<Variable, CircuitError>;

    /// Constrain a variable to a bool.
    /// Return error if the input is invalid.
    fn enforce_bool(&mut self, a: Variable) -> Result<(), CircuitError>;

    /// Constrain two variables to have the same value.
    /// Return error if the input variables are invalid.
    fn enforce_equal(&mut self, a: Variable, b: Variable) -> Result<(), CircuitError>;

    /// Pad the circuit with n dummy gates
    fn pad_gates(&mut self, n: usize);
}

/// Specifies whether the circuit is in setup or prove mode.
#[derive(Debug, Eq, PartialEq, Clone, Copy)]
pub enum Mode {
    /// The circuit is in setup mode.
    Setup,
    /// The circuit is in prove mode.
    /// If `construct_index` is `true`, we will also construct the index.
    /// Otherwise, we will only generate the witness.
    Prove {
        /// Whether to construct the index.
        index: bool,
    },
}

/// A specific Plonk circuit instantiation.
#[derive(Debug)]
pub struct PlonkCircuit<F>
where
    F: RawPrimeField + RawPrimeField,
{
    /// The number of variables.
    num_vars: usize,

    /// The number of variables.
    num_gates: usize,

    /// Which mode is the circuit in?
    mode: Mode,

    /// The gate of each (algebraic) constraint
    gates: Vec<Box<dyn Gate<F>>>,
    /// An in-memory buffer for the map from arithmetic/lookup gate wires to variables.
    /// When the vecs hit `BUFFER_SIZE`, the buffer is flushed to disk via `self.wire_variables`.
    wire_variables: [Vec<Variable>; GATE_WIDTH + 2],

    /// The IO gates for the list of public input variables.
    pub_input_gate_ids: Vec<GateId>,

    /// An in-memory buffer for witness values.
    /// Once this hits `BUFFER_SIZE`, the buffer is flushed to disk via `self.witness`.
    witness_buf: Vec<F>,

    /// A disk-backed vec for witness values.
    witness: FileVec<F>,

    /// The permutation over wires.
    /// Each algebraic gate has 5 wires, i.e., 4 input wires and an output
    /// wire; each lookup gate has a single wire that maps to a witness to
    /// be checked over the lookup table. In total there are 6 * n wires
    /// where n is the (padded) number of arithmetic/lookup gates.  
    /// We build a permutation over the set of wires so that each set of wires
    /// that map to the same witness forms a cycle.
    ///
    /// Each wire is represented by a pair (`WireId, GateId`) so that the wire
    /// is in the `GateId`-th arithmetic/lookup gate and `WireId` represents
    /// the wire type (e.g., 0 represents 1st input wires, 4 represents
    /// output wires, and 5 represents lookup wires).
    wire_permutation: Vec<(WireId, GateId)>,
    /// The extended identity permutation.
    extended_id_permutation: Vec<F>,
    /// The number of wire types. 5 for TurboPlonk and 6 for UltraPlonk.
    num_wire_types: usize,

    /// The evaluation domain for arithmetization of the circuit into various
    /// polynomials. This is only relevant after the circuit is finalized for
    /// arithmetization, by default it is a domain with size 1 (only with
    /// element 0).
    eval_domain: Radix2EvaluationDomain<F>,
}

impl<F: RawPrimeField + RawPrimeField> Default for PlonkCircuit<F> {
    fn default() -> Self {
        Self::new()
    }
}

impl<F: RawPrimeField + RawPrimeField> PlonkCircuit<F> {
    /// Construct a new circuit for indexing or setup.
    pub fn new_in_setup_mode() -> Self {
        let mut circuit = Self::new();
        circuit.mode = Mode::Setup;
        circuit
    }

    /// Construct a new circuit for proving.
    pub fn new_in_prove_mode(construct_index: bool) -> Self {
        let mut circuit = Self::new();
        circuit.mode = Mode::Prove {
            index: construct_index,
        };
        circuit
    }

    /// Construct a new circuit with type `plonk_type`.
    fn new() -> Self {
        let zero = F::zero();
        let one = F::one();
        let mut circuit = Self {
            mode: Mode::Setup,
            num_vars: 2,
            num_gates: 0,
            witness_buf: vec![zero, one],
            witness: FileVec::new(),
            gates: vec![],
            // size is `num_wire_types`
            wire_variables: Default::default(),
            pub_input_gate_ids: vec![],

            wire_permutation: vec![],
            extended_id_permutation: vec![],
            num_wire_types: GATE_WIDTH + 1,
            eval_domain: Radix2EvaluationDomain::new(1).unwrap(),
        };
        // Constrain variables `0`/`1` to have value 0/1.
        circuit.enforce_constant(0, zero).unwrap(); // safe unwrap
        circuit.enforce_constant(1, one).unwrap(); // safe unwrap
        circuit
    }

    /// Insert a general (algebraic) gate
    /// * `wire_vars` - wire variables. Each of these variables must be in range
    /// * `gate` - specific gate to be inserted
    /// * `returns` - an error if some verification fails
    pub fn insert_gate(
        &mut self,
        wire_vars: &[Variable; GATE_WIDTH + 1],
        gate: Box<dyn Gate<F>>,
    ) -> Result<(), CircuitError> {
        self.check_finalize_flag(false)?;
        self.num_gates += 1;
        if let Mode::Prove { index: false } = self.mode {
            return Ok(());
        }

        for (wire_var, wire_variable) in wire_vars
            .iter()
            .zip(self.wire_variables.iter_mut().take(GATE_WIDTH + 1))
        {
            wire_variable.push(*wire_var)
        }

        self.gates.push(gate);
        Ok(())
    }

    #[inline]
    /// Checks if a variable is strictly less than the number of variables.
    /// This function must be invoked for each gate as this check is not applied
    /// in the function `insert_gate`
    /// * `var` - variable to check
    /// * `returns` - Error if the variable is out of bound (i.e. >= number of
    ///   variables)
    pub fn check_var_bound(&self, var: Variable) -> Result<(), CircuitError> {
        if var >= self.num_vars {
            return Err(VarIndexOutOfBound(var, self.num_vars));
        }
        Ok(())
    }

    /// Check if a list of variables are strictly less than the number of
    /// variables.
    /// * `vars` - variables to check
    /// * `returns` - Error if the variable is out of bound (i.e. >= number of
    ///   variables)
    pub fn check_vars_bound(&self, vars: &[Variable]) -> Result<(), CircuitError> {
        for &var in vars {
            self.check_var_bound(var)?
        }
        Ok(())
    }

    /// Change the value of a variable. Only used for testing.
    // TODO: make this function test only.
    pub fn witness_mut(&mut self, idx: Variable) -> &mut F {
        if let Mode::Prove { index: true } = self.mode {
            &mut self.witness_buf[idx]
        } else {
            panic!("Cannot change witness in prove mode");
        }
    }

    /// creating a `BoolVar` without checking if `v` is a boolean value!
    /// You should absolutely sure about what you are doing.
    /// You should normally only use this API if you already enforce `v` to be a
    /// boolean value using other constraints.
    pub(crate) fn create_boolean_variable_unchecked(
        &mut self,
        a: F,
    ) -> Result<BoolVar, CircuitError> {
        let var = self.create_variable(a)?;
        Ok(BoolVar::new_unchecked(var))
    }
}

impl<F: RawPrimeField + RawPrimeField> Circuit<F> for PlonkCircuit<F> {
    fn num_gates(&self) -> usize {
        debug_assert_eq!(self.gates.len(), self.num_gates);
        self.num_gates
    }

    fn num_vars(&self) -> usize {
        self.num_vars
    }

    fn num_inputs(&self) -> usize {
        self.pub_input_gate_ids.len()
    }

    fn num_wire_types(&self) -> usize {
        self.num_wire_types
    }

    fn public_input(&self) -> Result<Vec<F>, CircuitError> {
        self.pub_input_gate_ids
            .iter()
            .map(|&gate_id| -> Result<F, CircuitError> {
                let var = self.wire_variables[GATE_WIDTH][gate_id];
                self.witness(var)
            })
            .collect::<Result<Vec<F>, CircuitError>>()
    }

    fn check_circuit_satisfiability(&self, pub_input: &[F]) -> Result<(), CircuitError> {
        if let Mode::Setup | Mode::Prove { index: false } = self.mode {
            return Err(CircuitError::IncorrectMode);
        }
        if pub_input.len() != self.num_inputs() {
            return Err(PubInputLenMismatch(
                pub_input.len(),
                self.pub_input_gate_ids.len(),
            ));
        }
        // Check public I/O gates
        for (i, gate_id) in self.pub_input_gate_ids.iter().enumerate() {
            let pi = pub_input[i];
            self.check_gate(*gate_id, &pi)?;
        }
        // Check rest of the gates
        for gate_id in 0..self.num_gates() {
            if !self.is_io_gate(gate_id) {
                let pi = F::zero();
                self.check_gate(gate_id, &pi)?;
            }
        }
        Ok(())
    }

    fn create_constant_variable(&mut self, val: F) -> Result<Variable, CircuitError> {
        let var = self.create_variable(val)?;
        self.enforce_constant(var, val)?;
        Ok(var)
    }

    fn create_variable(&mut self, val: F) -> Result<Variable, CircuitError> {
        self.check_finalize_flag(false)?;
        self.witness_buf.push(val);
        self.num_vars += 1;
        if (Mode::Prove { index: false } == self.mode)
            && (scribe_streams::BUFFER_SIZE == self.witness_buf.len())
        {
            self.witness.push_batch(&self.witness_buf);
            self.witness_buf.clear();
        }
        // the index is from `0` to `num_vars - 1`
        Ok(self.num_vars - 1)
    }

    fn create_public_variable(&mut self, val: F) -> Result<Variable, CircuitError> {
        let var = self.create_variable(val)?;
        self.set_variable_public(var)?;
        Ok(var)
    }

    fn set_variable_public(&mut self, var: Variable) -> Result<(), CircuitError> {
        self.check_finalize_flag(false)?;
        self.pub_input_gate_ids.push(self.num_gates());

        // Create an io gate that forces `witness[var] = public_input`.
        let wire_vars = &[0, 0, 0, 0, var];
        self.insert_gate(wire_vars, Box::new(IoGate))?;
        Ok(())
    }

    /// Default zero variable
    fn zero(&self) -> Variable {
        0
    }

    /// Default one variable
    fn one(&self) -> Variable {
        1
    }

    fn witness(&self, idx: Variable) -> Result<F, CircuitError> {
        self.check_var_bound(idx)?;
        if let Mode::Prove { index: true } = self.mode {
            Ok(self.witness_buf[idx])
        } else {
            panic!("No random access for witnesses if mode doesn't equal mode != `Prove` with `construct_index = true`");
        }
    }

    fn enforce_constant(&mut self, var: Variable, constant: F) -> Result<(), CircuitError> {
        self.check_var_bound(var)?;

        let wire_vars = &[0, 0, 0, 0, var];
        self.insert_gate(wire_vars, Box::new(ConstantGate(constant)))?;
        Ok(())
    }

    fn add_gate(&mut self, a: Variable, b: Variable, c: Variable) -> Result<(), CircuitError> {
        self.check_var_bound(a)?;
        self.check_var_bound(b)?;
        self.check_var_bound(c)?;

        let wire_vars = &[a, b, 0, 0, c];
        self.insert_gate(wire_vars, Box::new(AdditionGate))?;
        Ok(())
    }

    fn add(&mut self, a: Variable, b: Variable) -> Result<Variable, CircuitError> {
        self.check_var_bound(a)?;
        self.check_var_bound(b)?;
        let val = self.witness(a)? + self.witness(b)?;
        let c = self.create_variable(val)?;
        self.add_gate(a, b, c)?;
        Ok(c)
    }

    fn sub_gate(&mut self, a: Variable, b: Variable, c: Variable) -> Result<(), CircuitError> {
        self.check_var_bound(a)?;
        self.check_var_bound(b)?;
        self.check_var_bound(c)?;

        let wire_vars = &[a, b, 0, 0, c];
        self.insert_gate(wire_vars, Box::new(SubtractionGate))?;
        Ok(())
    }

    fn sub(&mut self, a: Variable, b: Variable) -> Result<Variable, CircuitError> {
        self.check_var_bound(a)?;
        self.check_var_bound(b)?;
        let val = self.witness(a)? - self.witness(b)?;
        let c = self.create_variable(val)?;
        self.sub_gate(a, b, c)?;
        Ok(c)
    }

    fn mul_gate(&mut self, a: Variable, b: Variable, c: Variable) -> Result<(), CircuitError> {
        self.check_var_bound(a)?;
        self.check_var_bound(b)?;
        self.check_var_bound(c)?;

        let wire_vars = &[a, b, 0, 0, c];
        self.insert_gate(wire_vars, Box::new(MultiplicationGate))?;
        Ok(())
    }

    fn mul(&mut self, a: Variable, b: Variable) -> Result<Variable, CircuitError> {
        self.check_var_bound(a)?;
        self.check_var_bound(b)?;
        let val = self.witness(a)? * self.witness(b)?;
        let c = self.create_variable(val)?;
        self.mul_gate(a, b, c)?;
        Ok(c)
    }

    fn enforce_bool(&mut self, a: Variable) -> Result<(), CircuitError> {
        self.check_var_bound(a)?;

        let wire_vars = &[a, a, 0, 0, a];
        self.insert_gate(wire_vars, Box::new(BoolGate))?;
        Ok(())
    }

    fn enforce_equal(&mut self, a: Variable, b: Variable) -> Result<(), CircuitError> {
        self.check_var_bound(a)?;
        self.check_var_bound(b)?;

        let wire_vars = &[a, b, 0, 0, 0];
        self.insert_gate(wire_vars, Box::new(EqualityGate))?;
        Ok(())
    }

    fn pad_gates(&mut self, n: usize) {
        // TODO: FIXME
        // this is interesting...
        // if we insert a PaddingGate
        // the padded gate does not have a gate_id, and will bug
        // when we check circuit satisfiability
        // we temporarily insert equality gate to by pass the issue
        let wire_vars = &[self.zero(), self.zero(), 0, 0, 0];
        for _ in 0..n {
            self.insert_gate(wire_vars, Box::new(EqualityGate)).unwrap();
        }
    }
}

/// Private helper methods
impl<F: RawPrimeField> PlonkCircuit<F> {
    fn is_finalized(&self) -> bool {
        self.eval_domain.size() != 1
    }

    /// Re-arrange the order of the gates so that:
    /// 1. io gates are in the front.
    /// 2. variable table lookup gate are at the rear so that they do not affect
    ///    the range gates when merging the lookup tables.
    ///
    /// Remember to pad gates before calling the method.
    fn rearrange_gates(&mut self) -> Result<(), CircuitError> {
        self.check_finalize_flag(true)?;
        if let Mode::Prove { index: false } = self.mode {
            return Ok(());
        }
        for (gate_id, io_gate_id) in self.pub_input_gate_ids.iter_mut().enumerate() {
            if *io_gate_id > gate_id {
                // Swap gate types
                self.gates.swap(gate_id, *io_gate_id);
                // Swap wire variables
                for i in 0..GATE_WIDTH + 1 {
                    self.wire_variables[i].swap(gate_id, *io_gate_id);
                }
                // Update io gate index
                *io_gate_id = gate_id;
            }
        }
        Ok(())
    }
    // use downcast to check whether a gate is of IoGate type
    fn is_io_gate(&self, gate_id: GateId) -> bool {
        self.gates[gate_id].as_any().is::<IoGate>()
    }

    // pad a finalized circuit to match the evaluation domain, prepared for
    // arithmetization.
    fn pad(&mut self) -> Result<(), CircuitError> {
        self.check_finalize_flag(true)?;
        if let Mode::Prove { index: false } = self.mode {
            return Ok(());
        }
        let n = self.eval_domain.size();
        for _ in self.num_gates()..n {
            self.gates.push(Box::new(PaddingGate));
        }
        for wire_id in 0..self.num_wire_types() {
            self.wire_variables[wire_id].resize(n, self.zero());
        }
        Ok(())
    }

    /// Check that the `gate_id`-th gate is satisfied by the circuit's witness
    /// and the public input value `pub_input`. `gate_id` is guaranteed to
    /// be in the range. The gate equation:
    /// qo * wo = pub_input + q_c +
    ///           q_mul0 * w0 * w1 + q_mul1 * w2 * w3 +
    ///           q_lc0 * w0 + q_lc1 * w1 + q_lc2 * w2 + q_lc3 * w3 +
    ///           q_hash0 * w0 + q_hash1 * w1 + q_hash2 * w2 + q_hash3 * w3 +
    ///           q_ecc * w0 * w1 * w2 * w3 * wo
    fn check_gate(&self, gate_id: Variable, pub_input: &F) -> Result<(), CircuitError> {
        if let Mode::Prove { index: false } = self.mode {
            return Err(CircuitError::IncorrectMode);
        }
        // Compute wire values

        let witness = &self.witness_buf;
        let w_vals: Vec<F> = (0..GATE_WIDTH + 1)
            .map(|i| witness[self.wire_variables[i][gate_id]])
            .collect();
        // Compute selector values.
        let q_lc: [F; GATE_WIDTH] = self.gates[gate_id].q_lc();
        let q_mul: [F; N_MUL_SELECTORS] = self.gates[gate_id].q_mul();
        let q_hash: [F; GATE_WIDTH] = self.gates[gate_id].q_hash();
        let q_c = self.gates[gate_id].q_c();
        let q_o = self.gates[gate_id].q_o();
        let q_ecc = self.gates[gate_id].q_ecc();

        // Compute the gate output
        let expected_gate_output = *pub_input
            + q_lc[0] * w_vals[0]
            + q_lc[1] * w_vals[1]
            + q_lc[2] * w_vals[2]
            + q_lc[3] * w_vals[3]
            + q_mul[0] * w_vals[0] * w_vals[1]
            + q_mul[1] * w_vals[2] * w_vals[3]
            + q_ecc * w_vals[0] * w_vals[1] * w_vals[2] * w_vals[3] * w_vals[4]
            + q_hash[0] * w_vals[0].pow([5])
            + q_hash[1] * w_vals[1].pow([5])
            + q_hash[2] * w_vals[2].pow([5])
            + q_hash[3] * w_vals[3].pow([5])
            + q_c;
        let gate_output = q_o * w_vals[4];
        if expected_gate_output != gate_output {
            return Err(
                GateCheckFailure(
                    gate_id,
                    format!(
                        "gate: {:?}, wire values: {:?}, pub_input: {}, expected_gate_output: {}, gate_output: {}",
                        self.gates[gate_id],
                        w_vals,
                        pub_input,
                        expected_gate_output,
                        gate_output
                    )
                ));
        }
        Ok(())
    }

    // Compute the permutation over wires.
    // The circuit is guaranteed to be padded before calling the method.
    #[inline]
    fn compute_wire_permutation(&mut self) {
        assert!(self.is_finalized());
        if let Mode::Prove { index: false } = self.mode {
            return;
        }
        let n = self.eval_domain.size();
        let m = self.num_vars();

        // Compute the mapping from variables to wires.
        // NOTE: we can use a vector as a map because our variable (the intended "key"
        // value type of the Map) is sorted and match exactly as the
        // non-negative integer ranged from 0 to m. Our current implementation should be
        // slightly faster than using a `HashMap<Variable, Vec<(WireId, GateId)>>` as we
        // avoid any constant overhead from the hashmap read/write.
        let mut variable_wires_map = vec![vec![]; m];
        for (gate_wire_id, variables) in self
            .wire_variables
            .iter()
            .take(self.num_wire_types())
            .enumerate()
        {
            for (gate_id, &var) in variables.iter().enumerate() {
                variable_wires_map[var].push((gate_wire_id, gate_id));
            }
        }

        // Compute the wire permutation
        self.wire_permutation = vec![(0usize, 0usize); self.num_wire_types * n];
        for wires_vec in variable_wires_map.iter_mut() {
            // The list of wires that map to the same variable forms a cycle.
            if !wires_vec.is_empty() {
                // push the first item so that window iterator will visit the last item
                // paired with the first item, forming a cycle
                wires_vec.push(wires_vec[0]);
                for window in wires_vec.windows(2) {
                    self.wire_permutation[window[0].0 * n + window[0].1] = window[1];
                }
                // remove the extra first item pushed at the beginning of the iterator
                wires_vec.pop();
            }
        }
    }

    // Check whether the circuit is finalized. Return an error if the finalizing
    // status is different from the expected status.
    #[inline]
    fn check_finalize_flag(&self, expect_finalized: bool) -> Result<(), CircuitError> {
        if !self.is_finalized() && expect_finalized {
            return Err(UnfinalizedCircuit);
        }
        if self.is_finalized() && !expect_finalized {
            return Err(ModifyFinalizedCircuit);
        }
        Ok(())
    }

    /// getter for all linear combination selector
    #[inline]
    fn q_lc(&self) -> [Vec<F>; GATE_WIDTH] {
        let mut result = [vec![], vec![], vec![], vec![]];
        for gate in &self.gates {
            let q_lc_vec = gate.q_lc();
            result[0].push(q_lc_vec[0]);
            result[1].push(q_lc_vec[1]);
            result[2].push(q_lc_vec[2]);
            result[3].push(q_lc_vec[3]);
        }
        result
    }

    /// getter for all multiplication selector
    #[inline]
    pub fn q_mul(&self) -> [Vec<F>; N_MUL_SELECTORS] {
        let mut result = [vec![], vec![]];
        for gate in &self.gates {
            let q_mul_vec = gate.q_mul();
            result[0].push(q_mul_vec[0]);
            result[1].push(q_mul_vec[1]);
        }
        result
    }

    /// getter for all hash selector
    #[inline]
    pub fn q_hash(&self) -> [Vec<F>; GATE_WIDTH] {
        let mut result = [vec![], vec![], vec![], vec![]];
        for gate in &self.gates {
            let q_hash_vec = gate.q_hash();
            result[0].push(q_hash_vec[0]);
            result[1].push(q_hash_vec[1]);
            result[2].push(q_hash_vec[2]);
            result[3].push(q_hash_vec[3]);
        }
        result
    }

    /// getter for all output selector
    #[inline]
    pub fn q_o(&self) -> Vec<F> {
        self.gates.iter().map(|g| g.q_o()).collect()
    }

    /// getter for all constant selector
    #[inline]
    pub fn q_c(&self) -> Vec<F> {
        self.gates.iter().map(|g| g.q_c()).collect()
    }

    /// getter for all ecc selector
    #[inline]
    pub fn q_ecc(&self) -> Vec<F> {
        self.gates.iter().map(|g| g.q_ecc()).collect()
    }

    // TODO: (alex) try return reference instead of expensive clone
    /// getter for all selectors in the following order:
    /// q_lc, q_mul, q_hash, q_o, q_c, q_ecc, [q_lookup (if support lookup)]
    #[inline]
    pub fn all_selectors(&self) -> Vec<Vec<F>> {
        let mut selectors = vec![];
        self.q_lc()
            .as_ref()
            .iter()
            .chain(self.q_mul().as_ref().iter())
            .chain(self.q_hash().as_ref().iter())
            .for_each(|s| selectors.push(s.clone()));
        selectors.push(self.q_o());
        selectors.push(self.q_c());
        selectors.push(self.q_ecc());
        selectors
    }
}

/// Private permutation related methods
impl<F: RawPrimeField> PlonkCircuit<F> {
    /// Copy constraints: precompute the extended permutation over circuit
    /// wires. Refer to Sec 5.2 and Sec 8.1 of https://eprint.iacr.org/2019/953.pdf for more details.
    #[inline]
    fn compute_extended_id_permutation(&mut self) {
        assert!(self.is_finalized());
        let n = self.eval_domain.size();

        // Compute the extended identity permutation
        // id[i*n+j] = k[i] * g^j
        let k: Vec<F> = compute_coset_representatives(self.num_wire_types, Some(n));
        // Precompute domain elements
        let group_elems: Vec<F> = self.eval_domain.elements().collect();
        // Compute extended identity permutation
        self.extended_id_permutation = vec![F::zero(); self.num_wire_types * n];
        for (i, &coset_repr) in k.iter().enumerate() {
            for (j, &group_elem) in group_elems.iter().enumerate() {
                self.extended_id_permutation[i * n + j] = coset_repr * group_elem;
            }
        }
    }
}

/// Methods for finalizing and merging the circuits.
impl<F: RawPrimeField> PlonkCircuit<F> {
    /// Finalize the setup of the circuit before arithmetization.
    pub fn finalize_for_arithmetization(&mut self) -> Result<(), CircuitError> {
        if self.is_finalized() {
            return Ok(());
        }
        let num_slots_needed = self.num_gates();
        self.eval_domain = Radix2EvaluationDomain::new(num_slots_needed)
            .ok_or(CircuitError::DomainCreationError)?;
        self.pad()?;
        self.rearrange_gates()?;
        self.compute_wire_permutation();
        self.compute_extended_id_permutation();
        Ok(())
    }
}
