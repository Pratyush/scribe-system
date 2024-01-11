use core::{iter::Peekable, marker::PhantomData};
use std::{fs::File, io::{Read, Write}, ops::{Add, Sub, Mul}};
use ark_ff::{Field, BigInt};
use byteorder::{ByteOrder, LittleEndian};
use num_bigint::BigUint;

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

impl<F: Field> ReadStream for DenseMLPolyStream<F> {
    type Item = F;

    fn read_next(&mut self) -> Option<F> {
        match F::deserialize_uncompressed_unchecked(&mut self.read_pointer) {
            Ok(field) => {
                println!("Deserialized field: {:?}", field);
                Some(field)
            },
            Err(_) => {
                // Handle error or EOF
                None
            }
        }
    }
}

impl<F: Field> WriteStream for DenseMLPolyStream<F> {
    type Item = F;

    fn write_next(&mut self, field: Self::Item) -> Option<()> {
        match field.serialize_uncompressed(&mut self.write_pointer) {
            Ok(_) => {
                println!("Field serialized and written successfully.");
                Some(())
            },
            Err(_) => {
                // Handle serialization or write error
                None
            }
        }
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
    use ark_ff::One;
    use ark_std::{test_rng, UniformRand};
    use ark_test_curves::bls12_381::Fr;
    use std::fs::File;
    use std::io::{Seek, SeekFrom};
    use std::marker::PhantomData;
    use tempfile::tempfile;

    use ark_std::rand::{Rng, SeedableRng}; // Import Rng trait and SeedableRng for deterministic rng in tests
    use ark_std::rand::rngs::StdRng; // Using StdRng for the example
    use ark_std::rand::distributions::{Distribution, Standard};

    #[test]
    fn test_one_field() {
        let mut rng = StdRng::seed_from_u64(42); // Seed for reproducibility

        // Sample a random Fp<P, N> value
        let random_value: Fr = Standard.sample(&mut rng);

        // Create a temporary file for the stream
        let file = tempfile().expect("Failed to create a temporary file");
        let file_clone = file.try_clone().expect("Failed to clone the file handle");

        let mut stream = DenseMLPolyStream {
            read_pointer: file,
            write_pointer: file_clone,
            num_vars: 0, // example value
            num_evals: 0, // example value
            f: PhantomData,
        };

        // Write to stream
        stream.write_next(random_value).expect("Failed to write");

        // Seek to the beginning of the file for reading
        stream.read_pointer.seek(SeekFrom::Start(0)).expect("Failed to seek");

        // Read from stream
        let read_value = stream.read_next().expect("Failed to read");
        assert_eq!(read_value, random_value, "The read value should match the written value");
    }
}

pub trait MLPolyStream<F: Field>: Sized + Add<Self, Output = Self> + Sub<Self, Output = Self> + Mul<F, Output = Self>  + ReadStream<Item = F> + WriteStream<Item = F> {

}

// pub struct DenseMLEStream<F: Field> {
//     read_pointer: File,
//     write_pointer: File,
//     num_vars: usize,
//     num_evals: usize,
//     f: PhantomData<F>,
// }

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
