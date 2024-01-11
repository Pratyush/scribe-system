use core::{iter::Peekable, marker::PhantomData};
use std::{fs::File, io::{Read, Write}, ops::{Add, Sub, Mul}};
use ark_ff::{Field, BigInt};
use byteorder::{ByteOrder, LittleEndian};
use num_bigint::BigUint;


use ark_test_curves::
    bls12_381::Fr;

pub trait ReadStream: Send + Sync {
    type Item;

    fn read_next(&mut self) -> Option<Self::Item>;
}

pub trait WriteStream: Send + Sync {
    type Item;

    fn write_next(&mut self, field: Self::Item) -> Option<()>;
}


pub struct Proof<F: Field> {
    prover_messages: ProverMsgs<F>,
}

pub struct ProverMsgs<F: Field>(pub F, pub F);

pub struct DenseMLPolyStream<F: Field> {
    read_pointer: File,
    write_pointer: File,
    num_vars: usize,
    num_evals: usize,
    f: PhantomData<F>,
}

impl ReadStream for DenseMLPolyStream<Fr> {
    type Item = Fr;

    fn read_next(&mut self) -> Option<Fr> {
        let mut buffer = [0u8; 32]; // Buffer for 32 bytes
        match self.read_pointer.read_exact(&mut buffer) {
            Ok(_) => {
                println!("Read buffer: {:?}", buffer);
                Some(Fr::from(BigUint::from_bytes_le(&buffer)))
            },
            Err(_) => None, // Return None on error or EOF
        }
    }
}

impl WriteStream for DenseMLPolyStream<Fr> {
    type Item = Fr;

    fn write_next(&mut self, field: Self::Item) -> Option<()> {
        let data = field.0.0;
        let mut buffer = [0u8; 32]; // 4 u64s * 8 bytes each
        println!("Writing data: {:?}", data);

        LittleEndian::write_u64_into(&data, &mut buffer);
        self.write_pointer.write_all(&buffer).ok()?;
        Some(())
    }
}

impl<F: Field> DenseMLPolyStream<F> {
    pub fn new(num_vars: usize, num_evals: usize, read_path: &str, write_path: &str) -> Self {
        let read_pointer = File::open(read_path).unwrap();
        let write_pointer = File::create(write_path).unwrap();
        Self {
            read_pointer,
            write_pointer,
            num_vars,
            num_evals,
            f: PhantomData,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use ark_ff::Fp;
    use tempfile::NamedTempFile;
    use byteorder::{LittleEndian, ByteOrder};

    #[test]
    fn test_write_and_read() {
        // Create a temporary file
        let tempfile = NamedTempFile::new().unwrap();
        let path = tempfile.path().to_path_buf();

        // Create DenseMLPolyStream
        let mut stream = DenseMLPolyStream::<Fr>::new(
            0, 0, 
            path.to_str().unwrap(), 
            path.to_str().unwrap()
        );

        // Create a Fr instance to write
        let mock_field = Fr::from(12u128); // Example data

        // Write the Fr instance
        stream.write_next(mock_field).unwrap();

        // Read the data back
        if let Some(read_field) = stream.read_next() {
            assert_eq!(read_field, Fr::from(12u128));
        } else {
            panic!("Failed to read data");
        }
    }
}

pub trait MLPolyStream<F: Field>: Sized + Add<Self, Output = Self> + Sub<Self, Output = Self> + Mul<F, Output = Self>  + ReadStream<Item = F> + WriteStream<Item = F> {

}

pub struct DenseMLEStream<F: Field> {
    read_pointer: File,
    write_pointer: File,
    num_vars: usize,
    num_evals: usize,
    f: PhantomData<F>,
}

// pub struct SumcheckEvaluations<'a, F, I> {
//     challenges: &'a [F],
//     evaluations: Peekable<I>,
// }

// impl<'a, F, I> SumcheckEvaluations<'a, F, I>
// where
//     F: Field,
//     I: Iterator,
//     I::Item: Borrow<F>,
// {
//     fn new(challenges: &'a [F], evaluations: I) -> Self {
//         Self {
//             challenges,
//             evaluations,
//         }
//     }
// }

// impl<'a, F, I> ReadStream for SumcheckEvaluations<'a, F, I>
// where
//     F: Field,
//     I: Iterator,
//     I::Item: Borrow<F>,
// {
//     type Item = F;

//     fn read_next(&mut self) -> Option<<Self as Iterator>::Item> {
//         self.evaluations.next()?
//     }

//     // try not to use this method as it consumes the iterator and goes through each element and isn't efficient
//     // fn len(&self) -> usize {
//     //     self.evaluations.count()
//     // }

//     // fn is_empty(&self) -> bool {
//     //     self.evaluations.peek().is_none()
//     // }

//     // fn restart(&mut self) {

//     // }

// }

// /// Stream implementation of foleded polynomial.
// #[derive(Clone, Copy)]
// pub struct FoldedPolynomialStream<'a, F, S>(FoldedPolynomialTree<'a, F, S>, usize);
// /// Iterator implementation of foleded polynomial.
// pub struct FoldedPolynomialStreamIter<'a, F, I> {
//     challenges: &'a [F],
//     iterator: I,
//     stack: Vec<(usize, F)>,
// }

// impl<'a, F, S> FoldedPolynomialStream<'a, F, S>
// where
//     S: Iterable,
//     F: Field,
//     S::Item: Borrow<F>,
// {
//     /// Initialize a new folded polynomial stream.
//     pub fn new(coefficients: &'a S, challenges: &'a [F]) -> Self {
//         let tree = FoldedPolynomialTree::new(coefficients, challenges);
//         let len = challenges.len();
//         Self(tree, len)
//     }
// }

// impl<'a, F, S> Iterable for FoldedPolynomialStream<'a, F, S>
// where
//     S: Iterable,
//     F: Field,
//     S::Item: Borrow<F>,
// {
//     type Item = F;
//     type Iter = FoldedPolynomialStreamIter<'a, F, S::Iter>;

//     fn iter(&self) -> Self::Iter {
//         let iterator = self.0.coefficients.iter();
//         let challenges = self.0.challenges;
//         let stack = init_stack(self.0.coefficients.len(), challenges.len());
//         FoldedPolynomialStreamIter {
//             iterator,
//             challenges,
//             stack,
//         }
//     }

//     fn len(&self) -> usize {
//         ceil_div(self.0.len(), 1 << self.0.challenges.len())
//     }
// }
