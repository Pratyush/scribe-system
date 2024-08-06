use std::{
    ffi::OsStr,
    fmt::Debug,
    fs::{File, OpenOptions},
    hash::{Hash, Hasher},
    io::{BufWriter, Seek, Write},
    mem,
    path::{Path, PathBuf},
};

use crate::streams::serialize::{DeserializeRaw, SerializeRaw};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Valid};
use derivative::Derivative;
use rayon::prelude::*;
use tempfile::NamedTempFile;

pub use self::iter::Iter;
use self::{array_chunks::ArrayChunks, into_iter::IntoIter, iter_chunk_mapped::IterChunkMapped};

use super::{
    iterator::{BatchAdapter, BatchedIterator, IntoBatchedIterator},
    BUFFER_SIZE,
};

mod array_chunks;
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
    File { path: PathBuf, file: File },
    Buffer { buffer: Vec<T> },
}

impl<T: SerializeRaw + DeserializeRaw> FileVec<T> {
    #[inline(always)]
    fn new_file(file: File, path: PathBuf) -> Self {
        Self::File { path, file }
    }

    #[inline(always)]
    pub fn with_name(path: impl AsRef<Path>) -> Self {
        let path = path.as_ref().to_path_buf();
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(&path)
            .expect("failed to open file");
        Self::new_file(file, path)
    }

    #[inline(always)]
    pub fn new() -> Self {
        let (file, path) = NamedTempFile::new()
            .expect("failed to create temp file")
            .keep()
            .expect("failed to keep temp file");
        Self::new_file(file, path)
    }

    #[inline(always)]
    pub fn with_prefix(prefix: impl AsRef<OsStr>) -> Self {
        let (file, path) = NamedTempFile::with_prefix(prefix)
            .expect("failed to create temp file")
            .keep()
            .expect("failed to keep temp file");
        Self::new_file(file, path)
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
            Self::File { path, .. } => {
                let file_2 = File::open(&path).unwrap();
                let mut fv = FileVec::File {
                    file: file_2,
                    path: path.clone(),
                };
                fv.convert_to_buffer_in_place();
                fv
            }
            Self::Buffer { buffer } => FileVec::Buffer {
                buffer: buffer.clone(),
            },
        }
    }

    #[inline(always)]
    pub fn iter<'a>(&'a self) -> Iter<'a, T>
    where
        T: Clone,
    {
        match self {
            Self::File { path, .. } => {
                let file = OpenOptions::new()
                    .read(true)
                    .open(&path)
                    .expect(&format!("failed to open file, {}", path.to_str().unwrap()));
                Iter::new_file(file)
            }
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
    pub fn iter_chunk_mapped<'a, const N: usize, F, U>(
        &'a self,
        f: F,
    ) -> IterChunkMapped<'a, T, U, F, N>
    where
        T: 'static + SerializeRaw + DeserializeRaw + Send + Sync + Copy,
        F: for<'b> Fn(&[T]) -> U + Sync + Send,
        U: 'static + SerializeRaw + DeserializeRaw + Send + Sync + Copy,
    {
        match self {
            Self::File { path, .. } => {
                let file = OpenOptions::new()
                    .read(true)
                    .open(&path)
                    .expect(&format!("failed to open file, {}", path.to_str().unwrap()));
                IterChunkMapped::new_file(file, f)
            }
            Self::Buffer { buffer } => IterChunkMapped::new_buffer(buffer.clone(), f),
        }
    }

    pub fn array_chunks<const N: usize>(&self) -> ArrayChunks<T, N>
    where
        T: 'static + SerializeRaw + DeserializeRaw + Send + Sync + Copy,
    {
        match self {
            Self::File { path, .. } => {
                let file = OpenOptions::new()
                    .read(true)
                    .open(&path)
                    .expect(&format!("failed to open file, {}", path.to_str().unwrap()));
                ArrayChunks::new_file(file)
            }
            Self::Buffer { buffer } => ArrayChunks::new_buffer(buffer.clone()),
        }
    }

    #[inline(always)]
    pub fn into_iter(mut self) -> IntoIter<T>
    where
        T: Clone,
    {
        match &mut self {
            Self::File { path, .. } => {
                let iter = IntoIter::new_file(File::open(&path).unwrap(), path.clone());
                mem::forget(self);
                iter
            }
            Self::Buffer { buffer } => {
                let buffer = core::mem::replace(buffer, Vec::new());
                IntoIter::new_buffer(buffer)
            }
        }
    }

    #[inline(always)]
    pub fn from_iter(iter: impl IntoIterator<Item = T>) -> Self
    where
        T: Send + Sync + Debug,
    {
        Self::from_batched_iter(BatchAdapter::from(iter.into_iter()))
    }

    pub fn from_batched_iter(iter: impl IntoBatchedIterator<Item = T>) -> Self
    where
        T: Send + Sync + Debug,
    {
        let mut iter = iter.into_batched_iter();
        let mut buffer = Vec::with_capacity(BUFFER_SIZE);
        let (mut file, mut path) = (None, None);
        let size = T::SIZE;

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
                byte_buffer = Some(vec![0u8; buffer.len() * size]);
                let (f, p) = NamedTempFile::with_prefix("from_batched_iter")
                    .expect("failed to create temp file")
                    .keep()
                    .expect("failed to keep temp file");
                (file, path) = (Some(f), Some(p));
            }
        }

        // Read from iterator and write to file.
        // If the iterator contains more than `BUFFER_SIZE` elements
        // (that is, more than one batch),
        // we write the first batch to the file
        while let Some(batch) = iter.next_batch() {
            if !more_than_one_batch {
                byte_buffer = Some(vec![0u8; buffer.len() * size]);
            }
            if file.is_none() {
                assert!(path.is_none());
                let (f, p) = NamedTempFile::with_prefix("from_batched_iter")
                    .expect("failed to create temp file")
                    .keep()
                    .expect("failed to keep temp file");
                (file, path) = (Some(f), Some(p));
            }
            let byte_buffer = byte_buffer.as_mut().unwrap();
            let file = file.as_mut().unwrap();

            more_than_one_batch = true;
            byte_buffer
                .par_chunks_mut(size)
                .zip(&buffer)
                .with_min_len(1 << 10)
                .for_each(|(chunk, item)| {
                    item.serialize_raw(chunk).unwrap();
                });
            let buffer_length = buffer.len();
            rayon::join(
                || {
                    file.write_all(&byte_buffer[..buffer_length * size])
                        .expect("failed to write to file");
                },
                || {
                    buffer.clear();
                    buffer.par_extend(batch);
                },
            );
        }

        // Write the last batch to the file.
        if more_than_one_batch || batch_is_larger_than_buffer {
            let byte_buffer = byte_buffer.as_mut().unwrap();
            let mut file = file.unwrap();
            let path = path.unwrap();
            byte_buffer
                .par_chunks_mut(size)
                .zip(&buffer)
                .with_min_len(1 << 10)
                .for_each(|(chunk, item)| {
                    item.serialize_raw(chunk).unwrap();
                });
            file.write_all(&byte_buffer[..buffer.len() * size])
                .expect("failed to write to file");
            file.flush().expect("failed to flush file");
            file.rewind().expect("failed to seek file");
            Self::new_file(file, path)
        } else {
            FileVec::Buffer { buffer }
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

    #[inline(always)]
    pub fn fold_odd_even_in_place(&mut self, f: impl Fn(&T, &T) -> T + Sync)
    where
        T: Send + Sync,
    {
        process_file!(self, |buffer: &mut Vec<T>| {
            *buffer = buffer
                .par_chunks(2)
                .map(|chunk| f(&chunk[0], &chunk[1]))
                .collect();
            Some(())
        })
    }

    pub fn reinterpret_type<U: SerializeRaw + DeserializeRaw>(mut self) -> FileVec<U>
    where
        T: Send + Sync + 'static,
        U: Send + Sync + 'static,
    {
        assert_eq!(T::SIZE % U::SIZE, 0);
        match &mut self {
            Self::File { file, path } => {
                let f = FileVec::File {
                    file: file.try_clone().unwrap(),
                    path: path.clone(),
                };
                mem::forget(self);
                f
            }
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
                    let mut byte_buffer = vec![0u8; buffer.len() * T::SIZE];
                    byte_buffer
                        .par_chunks_mut(T::SIZE)
                        .zip(buffer)
                        .for_each(|(chunk, item)| {
                            item.serialize_raw(chunk).unwrap();
                        });
                    let (mut file, path) = NamedTempFile::new()
                        .expect("failed to create temp file")
                        .keep()
                        .expect("failed to keep temp file");
                    file.write_all(&byte_buffer)
                        .expect("failed to write to file");
                    FileVec::File { file, path }
                }
            }
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
        let mut buffer = Vec::<(A, B)>::with_capacity(BUFFER_SIZE);
        let (mut file_1, path_1) = NamedTempFile::with_prefix("unzip_1")
            .expect("failed to create temp file")
            .keep()
            .expect("failed to keep temp file");
        let (mut file_2, path_2) = NamedTempFile::with_prefix("unzip_2")
            .expect("failed to create temp file")
            .keep()
            .expect("failed to keep temp file");
        let size = core::mem::size_of::<A>();
        let mut writer_1 = BufWriter::with_capacity(size * BUFFER_SIZE, &mut file_1);
        let mut writer_2 = BufWriter::with_capacity(size * BUFFER_SIZE, &mut file_2);

        if let Some(batch) = iter.next_batch() {
            buffer.par_extend(batch)
        }

        // Read from iterator and write to file.
        // If the iterator contains more than `BUFFER_SIZE` elements
        // (that is, more than one batch),
        // we write the first batch to the file
        let mut more_than_one_batch = false;
        while let Some(batch) = iter.next_batch() {
            more_than_one_batch = true;
            for (item_1, item_2) in &buffer {
                item_1
                    .serialize_raw(&mut writer_1)
                    .expect("failed to write to file");
                item_2
                    .serialize_raw(&mut writer_2)
                    .expect("failed to write to file");
            }
            buffer.clear();
            buffer.par_extend(batch);
        }

        // Write the last batch to the file.
        if more_than_one_batch {
            for (item_1, item_2) in &buffer {
                item_1
                    .serialize_raw(&mut writer_1)
                    .expect("failed to write to file");
                item_2
                    .serialize_raw(&mut writer_2)
                    .expect("failed to write to file");
            }
            writer_1.flush().expect("failed to flush file");
            writer_2.flush().expect("failed to flush file");
            drop(writer_1);
            drop(writer_2);
            file_1.rewind().expect("failed to seek file");
            file_2.rewind().expect("failed to seek file");
            let v1: FileVec<A> = FileVec::new_file(file_1, path_1);
            let v2: FileVec<B> = FileVec::new_file(file_2, path_2);
            (v1, v2)
        } else {
            let _ = std::fs::remove_file(&path_1);
            let _ = std::fs::remove_file(&path_2);
            let (b1, b2) = buffer.into_par_iter().unzip();
            (
                FileVec::Buffer { buffer: b1 },
                FileVec::Buffer { buffer: b2 },
            )
        }
    }

    pub(crate) fn unzip_helper_when_indexed<A, B, I>(mut iter: I) -> (FileVec<A>, FileVec<B>)
    where
        I: BatchedIterator<Item = (A, B)>,
        I::Batch: IndexedParallelIterator,
        A: SerializeRaw + DeserializeRaw + Send + Sync,
        B: SerializeRaw + DeserializeRaw + Send + Sync,
    {
        let mut buffer_a = Vec::<A>::with_capacity(BUFFER_SIZE);
        let mut buffer_b = Vec::<B>::with_capacity(BUFFER_SIZE);
        let (mut file_1, path_1) = NamedTempFile::with_prefix("unzip_1")
            .expect("failed to create temp file")
            .keep()
            .expect("failed to keep temp file");
        let (mut file_2, path_2) = NamedTempFile::with_prefix("unzip_2")
            .expect("failed to create temp file")
            .keep()
            .expect("failed to keep temp file");
        let size = core::mem::size_of::<A>();
        let mut writer_1 = BufWriter::with_capacity(size * BUFFER_SIZE, &mut file_1);
        let mut writer_2 = BufWriter::with_capacity(size * BUFFER_SIZE, &mut file_2);

        if let Some(batch) = iter.next_batch() {
            batch.unzip_into_vecs(&mut buffer_a, &mut buffer_b);
        }

        // Read from iterator and write to file.
        // If the iterator contains more than `BUFFER_SIZE` elements
        // (that is, more than one batch),
        // we write the first batch to the file
        let mut more_than_one_batch = false;
        while let Some(batch) = iter.next_batch() {
            more_than_one_batch = true;
            for a in &buffer_a {
                a.serialize_raw(&mut writer_1).unwrap();
            }
            for b in &buffer_b {
                b.serialize_raw(&mut writer_2).unwrap();
            }
            buffer_a.clear();
            buffer_b.clear();
            batch.unzip_into_vecs(&mut buffer_a, &mut buffer_b);
        }

        // Write the last batch to the file.
        if more_than_one_batch {
            for a in buffer_a {
                a.serialize_raw(&mut writer_1).unwrap();
            }
            for b in buffer_b {
                b.serialize_raw(&mut writer_2).unwrap();
            }
            writer_1.flush().expect("failed to flush file");
            writer_2.flush().expect("failed to flush file");
            drop(writer_1);
            drop(writer_2);
            file_1.rewind().expect("failed to seek file");
            file_2.rewind().expect("failed to seek file");
            let v1: FileVec<A> = FileVec::new_file(file_1, path_1);
            let v2: FileVec<B> = FileVec::new_file(file_2, path_2);
            (v1, v2)
        } else {
            let _ = std::fs::remove_file(&path_1);
            let _ = std::fs::remove_file(&path_2);
            (
                FileVec::Buffer { buffer: buffer_a },
                FileVec::Buffer { buffer: buffer_b },
            )
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
            let next_batch = other.next_batch();
            if next_batch.is_none() {
                return None;
            }
            buffer
                .par_iter_mut()
                .zip(next_batch.unwrap())
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
            Self::File { path, .. } => match std::fs::remove_file(&path) {
                Ok(_) => (),
                Err(e) => eprintln!("Failed to remove file at path {path:?}: {e:?}"),
            },
            Self::Buffer { .. } => (),
        }
    }
}

impl<T: SerializeRaw + DeserializeRaw + Hash> Hash for FileVec<T> {
    #[inline(always)]
    fn hash<H: Hasher>(&self, state: &mut H) {
        match self {
            Self::File { path, .. } => path.hash(state),
            Self::Buffer { buffer } => buffer.hash(state),
        }
    }
}

impl<T: SerializeRaw + DeserializeRaw + PartialEq> PartialEq for FileVec<T> {
    #[inline(always)]
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::File { path: p1, .. }, Self::File { path: p2, .. }) => p1 == p2,
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
impl<T: SerializeRaw + DeserializeRaw + Valid + Sync + Send + CanonicalSerialize + Debug>
    CanonicalSerialize for FileVec<T>
{
    fn serialize_with_mode<W: Write>(
        &self,
        mut writer: W,
        _compress: ark_serialize::Compress,
    ) -> Result<(), ark_serialize::SerializationError> {
        match self {
            Self::Buffer { buffer } => {
                println!("Here in serializing buffer");
                buffer.serialize_uncompressed(&mut writer)},
            Self::File { path, file } => {
                let size = T::SIZE;
                let mut final_result = vec![];
                let mut work_buffer = vec![0u8; size * BUFFER_SIZE];

                let mut result_buffer = Vec::with_capacity(BUFFER_SIZE);
                loop {
                    T::deserialize_raw_batch(
                        &mut result_buffer,
                        &mut work_buffer,
                        BUFFER_SIZE,
                        file,
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
                dbg!(final_result.len());
                final_result.serialize_uncompressed(&mut writer)
            }
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
        mut reader: R,
        _compress: ark_serialize::Compress,
        _validate: ark_serialize::Validate,
    ) -> Result<Self, ark_serialize::SerializationError> {
        let size = usize::deserialize_uncompressed_unchecked(&mut reader)?;
        dbg!(size);
        let mut buffer = Vec::with_capacity(BUFFER_SIZE);
        if size > BUFFER_SIZE {
            let (mut file, path) = NamedTempFile::new()
                .expect("failed to create temp file")
                .keep()
                .expect("failed to keep temp file");
            let mut remaining = size;

            let mut work_buffer = vec![0u8; T::SIZE * BUFFER_SIZE];
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
            
            Ok(FileVec::new_file(file, path))
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
        batch: impl Iterator<Item = &'a Self> + Send,
    ) -> Result<(), ark_serialize::SerializationError>
    where
        Self: 'a,
    {
        unimplemented!()
    }
}

#[cfg(test)]
mod tests {
    use ark_bls12_381::Fr;
    use ark_serialize::CanonicalSerialize;
    use ark_std::test_rng;
    use ark_std::UniformRand;

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
            (FileVec::Buffer { buffer: b1 }, FileVec::Buffer { buffer: b2 }) => {
                panic!("should both be File enums"); // size is both greater than BUFFER_SIZE, so should be File
            }
            (FileVec::File { .. }, FileVec::File { .. }) => {
                let vec1 = file_vec.iter().to_vec();
                let vec2 = file_vec2.iter().to_vec();
                assert_eq!(vec1, vec2);
            }
            _ => panic!("file_vec and file_vec2 are different types"),
        }
    }
}
