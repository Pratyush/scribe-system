use ark_bls12_381::Fr;
use ark_ff::Field;
use ark_std::{end_timer, start_timer};

use super::*;

#[test]
fn vec_file_vec_consistency() {
    for size in [1, 2, 4, 8, 16] {
        let size = BUFFER_SIZE * size;
        let fv = FileVec::from_iter((0..size).map(|i| i));
        println!("created file vec for size {size}");
        let vec: Vec<_> = (0..size).map(|i| i).collect();
        let vec2 = fv.iter().to_vec();
        assert_eq!(vec.len(), vec2.len());
        for (i, (fv, vec)) in vec2.iter().zip(vec).enumerate() {
            assert_eq!(*fv, vec, "failed at index {i}");
        }
    }
}

#[test]
fn file_vec_for_each() {
    for size in [1, 2, 4, 8, 16, 32, 64, 128] {
        let start = start_timer!(|| format!("file_vec_for_each size={size}"));
        let size = ((1 << 16) * size) as u64;
        let mut fv = FileVec::from_iter((0..size).map(Fr::from));
        fv.for_each(|x| {
            x.square_in_place();
        });
        let vec: Vec<_> = (0..size).map(|i| Fr::from(i).square()).collect();
        let vec2 = fv.into_iter().to_vec();
        dbg!(&vec2.len());
        for (fv, vec) in vec2.iter().zip(vec) {
            assert_eq!(*fv, vec);
        }
        end_timer!(start);
    }
}
