use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Read};
use rayon::prelude::*;

use crate::streams::BUFFER_SIZE;

pub(super) fn par_deserialize<T: CanonicalSerialize + CanonicalDeserialize + Sync + Send>(
    mut file: &mut impl Read,
    work_buffer: &mut Vec<u8>,
    result_buffer: &mut Vec<T>,
) -> Option<()> {
    work_buffer.clear();
    result_buffer.clear();
    let val = T::deserialize_uncompressed_unchecked(&mut file).ok()?;
    let size = val.uncompressed_size();
    file.take((size * (BUFFER_SIZE - 1)) as u64)
        .read_to_end(work_buffer)
        .ok()?;
    result_buffer.push(val);
    result_buffer.extend(
        work_buffer
            .chunks(size)
            .map(|chunk| T::deserialize_uncompressed_unchecked(chunk).unwrap()),
    );
    Some(())
}
