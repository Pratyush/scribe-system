use crate::serialize::{DeserializeRaw, SerializeRaw};
use rayon::{iter::MinLen, prelude::*, vec::IntoIter};
use std::{fmt::Debug, marker::PhantomData};

use crate::{iterator::BatchedIterator, BUFFER_SIZE};

use super::{avec, backend::InnerFile, AVec};

pub enum Iter<'a, T: SerializeRaw + DeserializeRaw + 'static> {
    File {
        file: InnerFile,
        lifetime: PhantomData<&'a T>,
        work_buffer: AVec,
    },
    Buffer {
        buffer: Vec<T>,
    },
}

impl<'a, T: SerializeRaw + DeserializeRaw> Iter<'a, T> {
    pub fn new_file(file: InnerFile) -> Self {
        let mut work_buffer = avec![];
        work_buffer.reserve(T::SIZE * BUFFER_SIZE);
        Self::File {
            file,
            lifetime: PhantomData,
            work_buffer,
        }
    }

    pub fn new_buffer(buffer: Vec<T>) -> Self {
        Self::Buffer { buffer }
    }
}

impl<'a, T: 'static + SerializeRaw + DeserializeRaw + Send + Sync + Copy + Debug> BatchedIterator
    for Iter<'a, T>
{
    type Item = T;
    type Batch = MinLen<IntoIter<T>>;

    #[inline]
    fn next_batch(&mut self) -> Option<Self::Batch> {
        match self {
            Iter::File {
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
            Iter::Buffer { buffer } => {
                if buffer.is_empty() {
                    None
                } else {
                    Some(
                        std::mem::replace(buffer, Vec::new())
                            .into_par_iter()
                            .with_min_len(1 << 7),
                    )
                }
            },
        }
    }
}
