use crate::serialize::{DeserializeRaw, SerializeRaw};
use rayon::{iter::MinLen, prelude::*, vec::IntoIter as VecIntoIter};

use crate::{iterator::BatchedIterator, BUFFER_SIZE};

use super::{avec, backend::InnerFile, AVec};

pub enum IntoIter<T: SerializeRaw + DeserializeRaw + 'static> {
    File { file: InnerFile, work_buffer: AVec },
    Buffer { buffer: Vec<T> },
}

impl<T: SerializeRaw + DeserializeRaw> IntoIter<T> {
    #[inline]
    pub fn new_file(file: InnerFile) -> Self {
        let mut work_buffer = avec![];
        work_buffer.reserve(T::SIZE * BUFFER_SIZE);
        Self::File { file, work_buffer }
    }

    #[inline]
    pub fn new_buffer(buffer: Vec<T>) -> Self {
        Self::Buffer { buffer }
    }
}

impl<T: 'static + SerializeRaw + DeserializeRaw + Send + Sync + Copy> BatchedIterator
    for IntoIter<T>
{
    type Item = T;
    type Batch = MinLen<VecIntoIter<T>>;

    #[inline]
    fn next_batch(&mut self) -> Option<Self::Batch> {
        match self {
            IntoIter::File {
                file, work_buffer, ..
            } => {
                let mut result = Vec::with_capacity(BUFFER_SIZE);
                T::deserialize_raw_batch(&mut result, work_buffer, BUFFER_SIZE, file).ok()?;

                if result.is_empty() {
                    None
                } else {
                    Some(result.into_par_iter().with_min_len(1 << 7))
                }
            },
            IntoIter::Buffer { buffer } => {
                if buffer.is_empty() {
                    None
                } else {
                    Some(std::mem::take(buffer).into_par_iter().with_min_len(1 << 7))
                }
            },
        }
    }

    fn len(&self) -> Option<usize> {
        let len = match self {
            IntoIter::File { file, .. } => file.len() / T::SIZE,
            IntoIter::Buffer { buffer } => buffer.len(),
        };
        Some(len)
    }
}

impl<T: SerializeRaw + DeserializeRaw> Drop for IntoIter<T> {
    fn drop(&mut self) {
        match self {
            Self::File { file, .. } => match std::fs::remove_file(&file.path) {
                Ok(_) => (),
                Err(e) => eprintln!("IntoIter: Failed to remove file at path {:?}: {e:?}", &file.path),
            },
            Self::Buffer { .. } => (),
        }
    }
}
