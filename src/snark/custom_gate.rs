use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Valid};
use ark_std::cmp::max;

/// Customized gate is a list of tuples of
///     (coefficient, selector_index, wire_indices)
///
/// Example:
///     q_L(X) * W_1(X)^5 - W_2(X) = 0
/// is represented as
/// vec![
///     ( 1,    Some(id_qL),    vec![id_W1, id_W1, id_W1, id_W1, id_W1]),
///     (-1,    None,           vec![id_W2])
/// ]
///
/// CustomizedGates {
///     gates: vec![
///         (1, Some(0), vec![0, 0, 0, 0, 0]),
///         (-1, None, vec![1])
///     ],
/// };
/// where id_qL = 0 // first selector
/// id_W1 = 0 // first witness
/// id_w2 = 1 // second witness
///
/// NOTE: here coeff is a signed integer, instead of a field element
#[derive(Clone, Debug, Default, PartialEq, Eq, CanonicalDeserialize, CanonicalSerialize)]
pub struct CustomizedGates {
    pub(crate) gates: Vec<(I64, Option<usize>, Vec<usize>)>,
}

impl CustomizedGates {
    /// The degree of the algebraic customized gate
    pub fn degree(&self) -> usize {
        let mut res = 0;
        for x in self.gates.iter() {
            res = max(res, x.2.len() + (x.1.is_some() as usize))
        }
        res
    }

    /// The number of selectors in a customized gate
    pub fn num_selector_columns(&self) -> usize {
        let mut res = 0;
        for (_coeff, q, _ws) in self.gates.iter() {
            // a same selector must not be used for multiple monomials.
            if q.is_some() {
                res += 1;
            }
        }
        res
    }

    /// The number of witnesses in a customized gate
    pub fn num_witness_columns(&self) -> usize {
        let mut res = 0;
        for (_coeff, _q, ws) in self.gates.iter() {
            // witness list must be ordered
            // so we just need to compare with the last one
            if let Some(&p) = ws.last() {
                if res < p {
                    res = p
                }
            }
        }
        // add one here because index starts from 0
        res + 1
    }

    /// Return a vanilla plonk gate:
    /// ``` ignore
    ///   q_L w_1 + q_R w_2 + q_O w_3 + q_M w1w2 + q_C = 0
    /// ```
    /// which is
    /// ``` ignore
    ///     (1,    Some(id_qL),     vec![id_W1]),
    ///     (1,    Some(id_qR),     vec![id_W2]),
    ///     (1,    Some(id_qO),     vec![id_W3]),
    ///     (1,    Some(id_qM),     vec![id_W1, id_w2]),
    ///     (1,    Some(id_qC),     vec![]),
    /// ```
    pub fn vanilla_plonk_gate() -> Self {
        Self {
            gates: vec![
                (1.into(), Some(0), vec![0]),
                (1.into(), Some(1), vec![1]),
                (1.into(), Some(2), vec![2]),
                (1.into(), Some(3), vec![0, 1]),
                (1.into(), Some(4), vec![]),
            ],
        }
    }

    /// Return a jellyfish turbo plonk gate:
    /// ```ignore
    ///     q_1 w_1   + q_2 w_2   + q_3 w_3   + q_4 w4
    ///   + q_M1 w1w2 + q_M2 w3w4
    ///   + q_H1 w1^5 + q_H2 w2^5 + q_H3 w1^5 + q_H4 w2^5
    ///   + q_E w1w2w3w4
    ///   + q_O w5
    ///   + q_C
    ///   = 0
    /// ```
    /// with
    /// - w = [w1, w2, w3, w4, w5]
    /// - q = [ q_1, q_2, q_3, q_4, q_M1, q_M2, q_H1, q_H2, q_H3, q_H4, q_E,
    ///   q_O, q_c ]
    ///
    /// which is
    /// ```ignore
    ///     (1,    Some(q[0]),     vec![w[0]]),
    ///     (1,    Some(q[1]),     vec![w[1]]),
    ///     (1,    Some(q[2]),     vec![w[2]]),
    ///     (1,    Some(q[3]),     vec![w[3]]),
    ///     (1,    Some(q[4]),     vec![w[0], w[1]]),
    ///     (1,    Some(q[5]),     vec![w[2], w[3]]),
    ///     (1,    Some(q[6]),     vec![w[0], w[0], w[0], w[0], w[0]]),
    ///     (1,    Some(q[7]),     vec![w[1], w[1], w[1], w[1], w[1]]),
    ///     (1,    Some(q[8]),     vec![w[2], w[2], w[2], w[2], w[2]]),
    ///     (1,    Some(q[9]),     vec![w[3], w[3], w[3], w[3], w[3]]),
    ///     (1,    Some(q[10]),    vec![w[0], w[1], w[2], w[3]]),
    ///     (1,    Some(q[11]),    vec![w[4]]),
    ///     (1,    Some(q[12]),    vec![]),
    /// ```
    pub fn jellyfish_turbo_plonk_gate() -> Self {
        CustomizedGates {
            gates: vec![
                (1.into(), Some(0), vec![0]),
                (1.into(), Some(1), vec![1]),
                (1.into(), Some(2), vec![2]),
                (1.into(), Some(3), vec![3]),
                (1.into(), Some(4), vec![0, 1]),
                (1.into(), Some(5), vec![2, 3]),
                (1.into(), Some(6), vec![0, 0, 0, 0, 0]),
                (1.into(), Some(7), vec![1, 1, 1, 1, 1]),
                (1.into(), Some(8), vec![2, 2, 2, 2, 2]),
                (1.into(), Some(9), vec![3, 3, 3, 3, 3]),
                (1.into(), Some(10), vec![0, 1, 2, 3]),
                (1.into(), Some(11), vec![4]),
                (1.into(), Some(12), vec![]),
            ],
        }
    }

    /// Generate a random gate for `num_witness` with a highest degree =
    /// `degree`
    pub fn mock_gate(num_witness: usize, degree: usize) -> Self {
        let mut gates = vec![];

        let mut high_degree_term = vec![0; degree - 1];
        high_degree_term.push(1);

        gates.push((1.into(), Some(0), high_degree_term));
        for i in 0..num_witness {
            gates.push((1.into(), Some(i + 1), vec![i]))
        }
        gates.push((1.into(), Some(num_witness + 1), vec![]));

        CustomizedGates { gates }
    }

    /// Return a plonk gate where #selector > #witness * 2
    /// ``` ignore
    ///   q_1 w_1   + q_2 w_2   + q_3 w_3   +
    ///   q_4 w1w2  + q_5 w1w3  + q_6 w2w3  +
    ///   q_7 = 0
    /// ```
    /// which is
    /// ``` ignore
    ///     (1,    Some(id_qL),     vec![id_W1]),
    ///     (1,    Some(id_qR),     vec![id_W2]),
    ///     (1,    Some(id_qO),     vec![id_W3]),
    ///     (1,    Some(id_qM),     vec![id_W1, id_w2]),
    ///     (1,    Some(id_qC),     vec![]),
    /// ```
    pub fn super_long_selector_gate() -> Self {
        Self {
            gates: vec![
                (1.into(), Some(0), vec![0]),
                (1.into(), Some(1), vec![1]),
                (1.into(), Some(2), vec![2]),
                (1.into(), Some(3), vec![0, 1]),
                (1.into(), Some(4), vec![0, 2]),
                (1.into(), Some(5), vec![1, 2]),
                (1.into(), Some(6), vec![]),
            ],
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct I64(pub i64);

impl CanonicalSerialize for I64 {
    fn serialize_with_mode<W: std::io::Write>(
        &self,
        writer: W,
        compress: ark_serialize::Compress,
    ) -> Result<(), ark_serialize::SerializationError> {
        (self.0 as u64).serialize_with_mode(writer, compress)
    }

    fn serialized_size(&self, compress: ark_serialize::Compress) -> usize {
        (self.0 as u64).serialized_size(compress)
    }
}

impl CanonicalDeserialize for I64 {
    fn deserialize_with_mode<R: std::io::Read>(
        reader: R,
        compress: ark_serialize::Compress,
        validate: ark_serialize::Validate,
    ) -> Result<Self, ark_serialize::SerializationError> {
        Ok(Self(
            u64::deserialize_with_mode(reader, compress, validate)? as i64,
        ))
    }
}

impl Valid for I64 {
    fn check(&self) -> Result<(), ark_serialize::SerializationError> {
        Ok(())
    }
}

impl From<i64> for I64 {
    fn from(x: i64) -> Self {
        Self(x)
    }
}

impl I64 {
    pub fn into_fp<F: PrimeField>(self) -> F {
        if self.0.is_negative() {
            -F::from(self.0.unsigned_abs())
        } else {
            F::from(self.0.unsigned_abs())
        }
    }
}
