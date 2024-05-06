use super::*;

#[test]
fn vec_file_vec_consistency() {
    for size in [1, 2, 4, 8, 16] {
        let size = BUFFER_SIZE * size;
        let fv = FileVec::from_iter((0..size).map(|i| i));
        println!("created file vec");
        let vec: Vec<_> = (0..size).map(|i| i).collect();
        let vec2 = fv.iter().to_vec();
        for (fv, vec) in vec2.iter().zip(vec) {
            assert_eq!(*fv, vec);
        }
    }
}