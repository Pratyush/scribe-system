use std::{
    ffi::OsStr,
    fmt::{Debug, Display},
    hash::{Hash, Hasher},
    io::{Seek, Write},
    mem,
};

use crate::serialize::{DeserializeRaw, SerializeRaw};

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Valid};
use derivative::Derivative;
use rayon::prelude::*;

pub use self::iter::Iter;
pub use self::{
    array_chunks::ArrayChunks, into_iter::IntoIter, iter_chunk_mapped::IterChunkMapped,
};

use super::{
    iterator::{BatchAdapter, BatchedIterator, IntoBatchedIterator},
    BUFFER_SIZE,
};

mod array_chunks;
pub mod backend;
pub use backend::*;
mod into_iter;
mod iter;
mod iter_chunk_mapped;

#[macro_use]
mod macros;

#[cfg(test)]
mod test;

#[derive(Derivative)]
#[derivative(Debug(bound = "T: core::fmt::Debug"))]
#[must_use]
pub enum FileVec<T: SerializeRaw + DeserializeRaw> {
    File(InnerFile),
    Buffer { buffer: Vec<T> },
}

impl<T: SerializeRaw + DeserializeRaw> FileVec<T> {
    #[inline(always)]
    fn new_file(file: InnerFile) -> Self {
        Self::File(file)
    }

    #[inline(always)]
    pub fn new_buffer(buffer: Vec<T>) -> Self {
        Self::Buffer { buffer }
    }

    #[inline(always)]
    pub fn new() -> Self {
        let file = InnerFile::new_temp("");
        Self::File(file)
    }

    #[inline(always)]
    pub fn with_space(n: usize) -> Self {
        let mut file = InnerFile::new_temp("");
        file.allocate_space(n * T::SIZE).unwrap();
        Self::File(file)
    }

    pub fn len(&self) -> usize {
        match self {
            Self::File(file) => file.len() / T::SIZE,
            Self::Buffer { buffer } => buffer.len(),
        }
    }

    // #[inline(always)]
    // pub fn with_prefix(prefix: impl AsRef<OsStr>) -> Self {
    //     let file = InnerFile::new_temp(prefix);
    //     Self::File(file)
    // }

    #[inline(always)]
    pub fn with_prefix_and_space(prefix: impl AsRef<OsStr>, n: usize) -> Self {
        let mut file = InnerFile::new_temp(prefix);
        file.allocate_space(n * T::SIZE).unwrap();
        Self::File(file)
    }

    #[inline(always)]
    pub fn clone(a: &Self) -> Self
    where
        T: Clone,
    {
        match a {
            Self::File(file) => Self::File(file.reopen_read_by_ref().unwrap()),
            Self::Buffer { buffer } => Self::Buffer {
                buffer: buffer.clone(),
            },
        }
    }

    #[inline(always)]
    pub fn convert_to_buffer_in_place(&mut self)
    where
        T: Send + Sync,
    {
        if let Self::Buffer { .. } = self {
            let mut buffer = Vec::with_capacity(BUFFER_SIZE);
            process_file!(self, |b: &mut Vec<T>| {
                buffer.par_extend(b.par_drain(..));
                Some(())
            });
            *self = FileVec::Buffer { buffer };
        }
    }

    #[inline]
    pub fn convert_to_buffer(&self) -> Self
    where
        T: Send + Sync + Clone,
    {
        match self {
            Self::File(file) => {
                let file_2 = file.reopen_read_by_ref().expect("failed to reopen file");
                let mut fv = FileVec::File(file_2);
                fv.convert_to_buffer_in_place();
                fv
            },
            Self::Buffer { buffer } => FileVec::Buffer {
                buffer: buffer.clone(),
            },
        }
    }

    #[inline(always)]
    pub fn iter(&self) -> Iter<'_, T>
    where
        T: Clone,
    {
        match self {
            Self::File(file) => {
                let file = file.reopen_read_by_ref().expect("failed to reopen file");
                Iter::new_file(file)
            },
            Self::Buffer { buffer } => Iter::new_buffer(buffer.clone()),
        }
    }

    pub fn iter_chunk_mapped_in_place<const N: usize, F>(&mut self, f: F)
    where
        T: 'static + SerializeRaw + DeserializeRaw + Send + Sync + Copy,
        F: for<'b> Fn(&[T]) -> T + Sync + Send,
    {
        let mut result_buffer = Vec::with_capacity(BUFFER_SIZE);
        process_file!(self, |buffer: &mut Vec<T>| {
            buffer
                .par_chunks(N)
                .map(|chunk| f(chunk))
                .collect_into_vec(&mut result_buffer);
            mem::swap(buffer, &mut result_buffer);
            Some(())
        })
    }

    #[inline(always)]
    pub fn iter_chunk_mapped<const N: usize, F, U>(&self, f: F) -> IterChunkMapped<'_, T, U, F, N>
    where
        T: 'static + SerializeRaw + DeserializeRaw + Send + Sync + Copy,
        F: for<'b> Fn(&[T]) -> U + Sync + Send,
        U: 'static + SerializeRaw + DeserializeRaw + Send + Sync + Copy,
    {
        match self {
            Self::File(file) => {
                let file = file.reopen_read_by_ref().expect(&format!(
                    "failed to open file, {}",
                    file.path.to_str().unwrap()
                ));
                IterChunkMapped::new_file(file, f)
            },
            Self::Buffer { buffer } => IterChunkMapped::new_buffer(buffer.clone(), f),
        }
    }

    pub fn array_chunks<const N: usize>(&self) -> ArrayChunks<T, N>
    where
        T: 'static + SerializeRaw + DeserializeRaw + Send + Sync + Copy,
    {
        match self {
            Self::File(file) => {
                let file = file.reopen_read_by_ref().expect(&format!(
                    "failed to open file, {}",
                    file.path.to_str().unwrap()
                ));
                ArrayChunks::new_file(file)
            },
            Self::Buffer { buffer } => ArrayChunks::new_buffer(buffer.clone()),
        }
    }

    #[inline(always)]
    pub fn into_iter(mut self) -> IntoIter<T>
    where
        T: Clone,
    {
        match &mut self {
            Self::File(file) => {
                let file = std::mem::replace(file, InnerFile::empty())
                    .reopen_read()
                    .unwrap();
                IntoIter::new_file(file)
            },
            Self::Buffer { buffer } => {
                let buffer = core::mem::take(buffer);
                IntoIter::new_buffer(buffer)
            },
        }
    }

    #[inline(always)]
    pub fn from_iter(iter: impl IntoIterator<Item = T>) -> Self
    where
        T: Send + Sync + Debug,
    {
        Self::from_batched_iter(BatchAdapter::from(iter.into_iter()))
    }

    #[inline(always)]
    pub fn from_iter_with_prefix(
        iter: impl IntoIterator<Item = T>,
        prefix: impl AsRef<OsStr>,
    ) -> Self
    where
        T: Send + Sync + Debug,
    {
        Self::from_batched_iter_with_prefix(BatchAdapter::from(iter.into_iter()), prefix)
    }

    pub fn from_batched_iter_with_prefix(
        iter: impl IntoBatchedIterator<Item = T>,
        prefix: impl AsRef<OsStr>,
    ) -> Self
    where
        T: Send + Sync + Debug,
    {
        let prefix = [prefix.as_ref().to_str().unwrap(), "from_batched_iter"].join("_");
        let mut iter = iter.into_batched_iter();
        let mut buffer = Vec::with_capacity(2 * BUFFER_SIZE);
        let mut file = None;
        let size = T::SIZE;
        let file_length = iter.len().map(|s| s * T::SIZE);

        let mut byte_buffer = None;
        let mut more_than_one_batch = false;
        let mut batch_is_larger_than_buffer = false;
        if let Some(batch) = iter.next_batch() {
            buffer.par_extend(batch);

            // If the first batch is larger than BUFFER_SIZE,
            // (e.g., if the batch is the output of a FlatMap that doubles the length)
            // then our output FileVec should go to disk.
            // So, we initialize the byte_buffer and file here.
            if buffer.len() > BUFFER_SIZE {
                batch_is_larger_than_buffer = true;
                byte_buffer = Some(avec![0u8; buffer.len() * size]);
                let mut f = InnerFile::new_temp(&prefix);
                file_length.map(|l| f.allocate_space(l).unwrap());
                file = Some(f);
            }
        } else {
            // We are done
            return FileVec::Buffer { buffer };
        }
        assert!(!buffer.is_empty());

        // Read from iterator and write to file.
        // If the iterator contains more than `BUFFER_SIZE` elements
        // (that is, more than one batch),
        // we write the first batch to the file
        while let Some(batch) = iter.next_batch() {
            if buffer.len() < BUFFER_SIZE {
                buffer.par_extend(batch);
            } else {
                if !more_than_one_batch {
                    byte_buffer = Some(avec![0u8; buffer.len() * size]);
                }
                if file.is_none() {
                    let mut f = InnerFile::new_temp(&prefix);
                    file_length.map(|l| f.allocate_space(l).unwrap());
                    file = Some(f);
                }
                let byte_buffer = byte_buffer.as_mut().unwrap();
                let file = file.as_mut().unwrap();

                more_than_one_batch = true;
                byte_buffer
                    .par_chunks_mut(size)
                    .zip(&buffer)
                    .with_min_len(1 << 10)
                    .try_for_each(|(chunk, item)| item.serialize_raw(chunk))
                    .unwrap();
                let buf_len = buffer.len();
                buffer.clear();
                rayon::join(
                    || file.write_all(&byte_buffer[..buf_len * size]).unwrap(),
                    || buffer.par_extend(batch),
                );
            }
        }

        // Write the last batch to the file.
        if more_than_one_batch || batch_is_larger_than_buffer {
            let byte_buffer = byte_buffer.as_mut().unwrap();
            let mut file = file.unwrap();
            byte_buffer
                .par_chunks_mut(size)
                .zip(&buffer)
                .with_min_len(1 << 10)
                .try_for_each(|(chunk, item)| item.serialize_raw(chunk))
                .unwrap();
            file.write_all(&byte_buffer[..buffer.len() * size])
                .expect("failed to write to file");
            file.flush().expect("failed to flush file");
            file.rewind().expect("failed to seek file");
            Self::File(file)
        } else {
            FileVec::Buffer { buffer }
        }
    }

    pub fn from_batched_iter(iter: impl IntoBatchedIterator<Item = T>) -> Self
    where
        T: Send + Sync + Debug,
    {
        Self::from_batched_iter_with_prefix(iter, "")
    }

    /// Pushes a batch of elements to the end of the `FileVec`.
    ///
    /// # Note
    ///
    /// Should only be used when `b` is sufficiently large.
    pub fn push_batch(&mut self, b: &[T])
    where
        T: Send + Sync + Copy,
    {
        match self {
            Self::File(ref mut file) => {
                let mut work_buffer = avec![0u8; T::SIZE * b.len()];
                T::serialize_raw_batch(b, &mut work_buffer, file).unwrap();
            },
            Self::Buffer { ref mut buffer } => {
                buffer.extend_from_slice(b);
                if buffer.len() > BUFFER_SIZE {
                    let buffer = mem::take(buffer);
                    *self = Self::from_iter(buffer.into_iter())
                }
            },
        }
    }

    pub fn for_each(&mut self, f: impl Fn(&mut T) + Send + Sync)
    where
        T: Send + Sync,
    {
        process_file!(self, |buffer: &mut Vec<T>| {
            buffer.par_iter_mut().for_each(|t| f(t));
            Some(())
        })
    }

    pub fn reinterpret_type<U>(mut self) -> FileVec<U>
    where
        T: Send + Sync + 'static,
        U: SerializeRaw + DeserializeRaw + Send + Sync + 'static,
    {
        match &mut self {
            Self::File(file) => {
                let f = FileVec::File(file.try_clone().unwrap());
                mem::forget(self);
                f
            },
            Self::Buffer { buffer } => {
                let size_equal = T::SIZE == U::SIZE;
                let mem_size_equal = std::mem::size_of::<T>() == std::mem::size_of::<U>();
                let align_equal = std::mem::align_of::<T>() == std::mem::align_of::<U>();
                if size_equal && mem_size_equal && align_equal {
                    let mut new_buffer = vec![];
                    mem::swap(buffer, &mut new_buffer);
                    let buffer = unsafe {
                        // Ensure the original vector is not dropped.
                        let mut new_buffer = std::mem::ManuallyDrop::new(new_buffer);
                        Vec::from_raw_parts(
                            new_buffer.as_mut_ptr() as *mut U,
                            new_buffer.len(),
                            new_buffer.capacity(),
                        )
                    };
                    FileVec::Buffer { buffer }
                } else {
                    let mut byte_buffer = avec![0u8; buffer.len() * T::SIZE];
                    byte_buffer
                        .par_chunks_mut(T::SIZE)
                        .zip(buffer)
                        .for_each(|(chunk, item)| {
                            item.serialize_raw(chunk).unwrap();
                        });

                    let mut file = InnerFile::new_temp("");
                    file.write_all(&byte_buffer)
                        .expect("failed to write to file");
                    FileVec::File(file)
                }
            },
        }
    }

    pub fn batched_for_each(&mut self, f: impl Fn(&mut Vec<T>) + Send + Sync)
    where
        T: Send + Sync,
    {
        process_file!(self, |buffer: &mut Vec<T>| {
            f(buffer);
            Some(())
        })
    }

    pub(crate) fn unzip_helper<A, B>(
        mut iter: impl BatchedIterator<Item = (A, B)>,
    ) -> (FileVec<A>, FileVec<B>)
    where
        A: SerializeRaw + DeserializeRaw + Send + Sync,
        B: SerializeRaw + DeserializeRaw + Send + Sync,
    {
        let buffer_a = Vec::<A>::with_capacity(BUFFER_SIZE);
        let buffer_b = Vec::<B>::with_capacity(BUFFER_SIZE);
        let mut bufs = (buffer_a, buffer_b);
        let mut file_1 = InnerFile::new_temp("unzip_1");
        let mut file_2 = InnerFile::new_temp("unzip_2");
        let iter_len = iter.len();

        let size_a = A::SIZE;
        let size_b = B::SIZE;
        let mut writer_1 = avec![0u8; size_a * BUFFER_SIZE];
        let mut writer_2 = avec![0u8; size_b * BUFFER_SIZE];

        if let Some(batch) = iter.next_batch() {
            bufs.par_extend(batch);
        } else {
            return (
                FileVec::Buffer { buffer: vec![] },
                FileVec::Buffer { buffer: vec![] },
            );
        }
        assert!(!bufs.0.is_empty());
        assert_eq!(bufs.0.len(), bufs.1.len());

        // Read from iterator and write to file.
        // If the iterator contains more than `BUFFER_SIZE` elements
        // (that is, more than one batch),
        // we write the first batch to the file
        let mut more_than_one_batch = false;
        while let Some(batch) = iter.next_batch() {
            if bufs.0.len() < BUFFER_SIZE {
                bufs.par_extend(batch);
            } else {
                more_than_one_batch = true;
                let a = writer_1.par_chunks_mut(size_a).zip(&bufs.0);
                let b = writer_2.par_chunks_mut(size_b).zip(&bufs.1);

                a.zip(b)
                    .try_for_each(|((c_a, a), (c_b, b))| {
                        a.serialize_raw(c_a)?;
                        b.serialize_raw(c_b)
                    })
                    .unwrap();
                let buf_a_len = bufs.0.len();
                let buf_b_len = bufs.1.len();
                iter_len.map(|s| {
                    file_1.allocate_space(s * A::SIZE).unwrap();
                    file_2.allocate_space(s * B::SIZE).unwrap();
                });
                rayon::join(
                    || file_1.write_all(&writer_1[..buf_a_len * size_a]).unwrap(),
                    || file_2.write_all(&writer_2[..buf_b_len * size_b]).unwrap(),
                );
                bufs.0.clear();
                bufs.1.clear();
                bufs.par_extend(batch);
            }
        }

        // Write the last batch to the file.
        if more_than_one_batch {
            writer_1
                .par_chunks_mut(size_a)
                .zip(&bufs.0)
                .try_for_each(|(chunk, a)| a.serialize_raw(chunk))
                .unwrap();
            writer_2
                .par_chunks_mut(size_b)
                .zip(&bufs.1)
                .try_for_each(|(chunk, b)| b.serialize_raw(chunk))
                .unwrap();
            let buf_a_len = bufs.0.len();
            let buf_b_len = bufs.1.len();
            iter_len.map(|s| {
                file_1.allocate_space(s * A::SIZE).unwrap();
                file_2.allocate_space(s * B::SIZE).unwrap();
            });
            rayon::join(
                || file_1.write_all(&writer_1[..buf_a_len * size_a]).unwrap(),
                || file_2.write_all(&writer_2[..buf_b_len * size_b]).unwrap(),
            );
            file_1.flush().expect("failed to flush file");
            file_2.flush().expect("failed to flush file");
            file_1.rewind().expect("failed to seek file");
            file_2.rewind().expect("failed to seek file");
            let v1: FileVec<A> = FileVec::new_file(file_1);
            let v2: FileVec<B> = FileVec::new_file(file_2);
            (v1, v2)
        } else {
            let _ = file_1.remove();
            let _ = file_2.remove();
            let v1 = FileVec::Buffer { buffer: bufs.0 };
            let v2 = FileVec::Buffer { buffer: bufs.1 };
            (v1, v2)
        }
    }

    /// Zips the elements of this `FileVec` with the elements of another `BatchedIterator`,
    /// and applies the function `f` to each pair of elements.
    /// The contents of this `FileVec` are updated in place.
    ///
    /// The `BatchedIterator` must have the same number of elements as this `FileVec`.
    pub fn zipped_for_each<I>(&mut self, mut other: I, f: impl Fn(&mut T, I::Item) + Send + Sync)
    where
        T: Send + Sync,
        I: BatchedIterator,
        I::Item: Send + Sync,
        I::Batch: IndexedParallelIterator,
    {
        process_file!(self, |buffer: &mut Vec<T>| {
            let next_batch = other.next_batch()?;
            buffer
                .par_iter_mut()
                .zip(next_batch)
                .for_each(|(t, u)| f(t, u));
            Some(())
        })
    }

    #[inline(always)]
    pub fn deep_copy(&self) -> Self
    where
        T: Send + Sync + Copy + std::fmt::Debug + 'static,
    {
        Self::from_batched_iter(self.iter())
    }
}

impl<T: SerializeRaw + DeserializeRaw> Drop for FileVec<T> {
    #[inline(always)]
    fn drop(&mut self) {
        match self {
            Self::File(file) => match std::fs::remove_file(&file.path) {
                Ok(_) => (),
                Err(e) => eprintln!("Failed to remove file at path {:?}: {e:?}", file.path),
            },
            Self::Buffer { .. } => (),
        }
    }
}

impl<T: SerializeRaw + DeserializeRaw + Hash> Hash for FileVec<T> {
    #[inline(always)]
    fn hash<H: Hasher>(&self, state: &mut H) {
        match self {
            Self::File(file) => file.path.hash(state),
            Self::Buffer { buffer } => buffer.hash(state),
        }
    }
}

impl<T: SerializeRaw + DeserializeRaw + PartialEq> PartialEq for FileVec<T> {
    #[inline(always)]
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::File(f1), Self::File(f2)) => f1.path == f2.path,
            (Self::Buffer { buffer: b1 }, Self::Buffer { buffer: b2 }) => b1 == b2,
            _ => false,
        }
    }
}

impl<T: SerializeRaw + DeserializeRaw + Eq> Eq for FileVec<T> {}

// T has same representation in memory for our format and canonical
// T has different reprsetnation in disk for our format for efficiency

// serialize:
// File: use our local serialization to read the entire file to a Vec<T>, and call T::serialize_uncompressed on Vec<T>
// Buffer: call T::serialize_uncompressed directly on the inner content (automatically writes length first)
impl<
        T: SerializeRaw + DeserializeRaw + Valid + Sync + Send + CanonicalSerialize + Debug + Display,
    > CanonicalSerialize for FileVec<T>
{
    fn serialize_with_mode<W: Write>(
        &self,
        mut writer: W,
        _compress: ark_serialize::Compress,
    ) -> Result<(), ark_serialize::SerializationError> {
        match self {
            Self::Buffer { buffer } => buffer.serialize_uncompressed(&mut writer),
            Self::File(file) => {
                let mut file = file.reopen_read_by_ref().expect(&format!(
                    "failed to open file, {}",
                    file.path.to_str().unwrap()
                ));
                let size = T::SIZE;
                let mut final_result = vec![];
                let mut work_buffer: AVec = avec![0u8; size * BUFFER_SIZE];

                let mut result_buffer = Vec::with_capacity(BUFFER_SIZE);
                loop {
                    T::deserialize_raw_batch(
                        &mut result_buffer,
                        &mut work_buffer,
                        BUFFER_SIZE,
                        &mut file,
                    )
                    .unwrap();

                    // need to store result_buffer len first or append removes all elements from result buffer
                    let result_buffer_len = result_buffer.len();

                    final_result.append(&mut result_buffer);

                    // if we have read less than BUFFER_SIZE items, we've reached EOF
                    if result_buffer_len < BUFFER_SIZE {
                        break;
                    }
                }

                // size of final_result vec (not byte size) should be serialized as a u64 as a part of this API
                final_result.serialize_uncompressed(&mut writer)
            },
        }
    }

    fn serialized_size(&self, _compress: ark_serialize::Compress) -> usize {
        todo!()
    }
}

// deserialize:
// read the length first
// if length greater than buffer size, it's a file
//        a. create a new file
//        b. read a batch of T at a time using canonicaldeserialize (call T::deserialize_uncompressed_unchecked from Canonical)
//        c. use SerializeRaw to write each T to the File
// if the length less than buffer size, it's a buffer
//        a. read one buffer batch and return it directly (just a Vec) Vec<T>::deserialize_uncompressed_unchecked
impl<T: SerializeRaw + DeserializeRaw + Valid + Sync + Send + CanonicalDeserialize + Debug>
    CanonicalDeserialize for FileVec<T>
{
    fn deserialize_with_mode<R: ark_serialize::Read>(
        reader: R,
        _compress: ark_serialize::Compress,
        _validate: ark_serialize::Validate,
    ) -> Result<Self, ark_serialize::SerializationError> {
        Self::deserialize_with_mode_and_prefix(reader, "", _compress, _validate)
    }
}

impl<T: SerializeRaw + DeserializeRaw + Valid + Sync + Send + CanonicalDeserialize + Debug>
    FileVec<T>
{
    pub fn deserialize_with_mode_and_prefix<R: ark_serialize::Read>(
        mut reader: R,
        prefix: impl AsRef<OsStr>,
        _compress: ark_serialize::Compress,
        _validate: ark_serialize::Validate,
    ) -> Result<Self, ark_serialize::SerializationError> {
        let size = usize::deserialize_uncompressed_unchecked(&mut reader)?;
        let mut buffer = Vec::with_capacity(BUFFER_SIZE);
        if size > BUFFER_SIZE {
            let mut file = InnerFile::new_temp(prefix);
            file.allocate_space(size * T::SIZE).unwrap();
            let mut remaining = size;

            let mut work_buffer = avec![0u8; T::SIZE * BUFFER_SIZE];
            while remaining > 0 {
                for _ in 0..std::cmp::min(remaining, BUFFER_SIZE) {
                    let item = T::deserialize_uncompressed_unchecked(&mut reader).unwrap();
                    buffer.push(item);
                }
                remaining = remaining.saturating_sub(BUFFER_SIZE);
                T::serialize_raw_batch(&buffer, &mut work_buffer, &mut file).unwrap();
                buffer.clear();
                work_buffer.clear();
            }

            Ok(FileVec::new_file(file))
        } else {
            for _ in 0..size {
                let item = T::deserialize_uncompressed_unchecked(&mut reader).unwrap();
                buffer.push(item);
            }

            Ok(FileVec::Buffer { buffer })
        }
    }
}

impl<T: SerializeRaw + DeserializeRaw + Valid> Valid for FileVec<T> {
    fn check(&self) -> Result<(), ark_serialize::SerializationError> {
        unimplemented!()
    }

    fn batch_check<'a>(
        _batch: impl Iterator<Item = &'a Self> + Send,
    ) -> Result<(), ark_serialize::SerializationError>
    where
        Self: 'a,
    {
        unimplemented!()
    }
}

impl<T: SerializeRaw + DeserializeRaw + Display> Display for FileVec<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::File(file) => {
                writeln!(f, "FileVec at {}: [", file.path.display())?;
                let file = file.reopen_read_by_ref().unwrap();
                let mut reader = std::io::BufReader::new(file);
                while let Ok(item) = T::deserialize_raw(&mut reader) {
                    writeln!(f, "  {},", item)?;
                }
                writeln!(f, "]")?;
                Ok(())
            },
            Self::Buffer { buffer } => {
                writeln!(f, "FileVec: [")?;
                for item in buffer {
                    writeln!(f, "  {},", item)?;
                }
                writeln!(f, "]")?;
                Ok(())
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use ark_bls12_381::Fr;
    use ark_serialize::CanonicalSerialize;
    use ark_std::test_rng;
    use ark_std::UniformRand;
    use std::fs::File;

    use super::*;

    // Currently works for BUFFER_SIZE or below
    #[test]
    fn test_file_vec_canonical_serialize() {
        let mut rng = test_rng();
        let vec1 = (0..(BUFFER_SIZE * 2))
            .map(|_| Fr::rand(&mut rng))
            .collect::<Vec<Fr>>();
        let file_vec = FileVec::from_iter(vec1.clone().into_iter());
        let mut buffer = File::create("srs.params").unwrap();
        file_vec.serialize_uncompressed(&mut buffer).unwrap();

        let mut f = File::open("srs.params").unwrap();
        let file_vec2 = FileVec::<Fr>::deserialize_uncompressed_unchecked(&mut f).unwrap();

        match (&file_vec, &file_vec2) {
            (FileVec::Buffer { .. }, FileVec::Buffer { .. }) => {
                panic!("should both be File enums"); // size is both greater than BUFFER_SIZE, so should be File
            },
            (FileVec::File { .. }, FileVec::File { .. }) => {
                let vec1 = file_vec.iter().to_vec();
                let vec2 = file_vec2.iter().to_vec();
                assert_eq!(vec1, vec2);
            },
            _ => panic!("file_vec and file_vec2 are different types"),
        }
    }
}
