use std::{
    fs::{File, OpenOptions},
    hash::{Hash, Hasher},
    io::{BufReader, BufWriter, Seek},
    path::{Path, PathBuf},
};

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Write};
use rayon::iter::{
    IndexedParallelIterator, IntoParallelIterator, IntoParallelRefMutIterator, ParallelExtend,
    ParallelIterator,
};
use tempfile::NamedTempFile;

use self::into_iter::IntoIter;
pub use self::iter::Iter;

use super::{
    iterator::{BatchAdapter, BatchedIterator, IntoBatchedIterator},
    BUFFER_SIZE,
};

mod into_iter;
mod iter;
mod utils;

#[macro_use]
mod macros;

#[cfg(test)]
mod test;

#[derive(Debug)]
pub enum FileVec<T: CanonicalSerialize + CanonicalDeserialize> {
    File { path: PathBuf, file: File },
    Buffer { buffer: Vec<T> },
}

// impl<T: CanonicalSerialize + CanonicalDeserialize> CanonicalSerialize for FileVec<T> {
//     fn seriali–ze_with_mode<W: Write>(
//             &self,
//             writer: W,
//             compress: ark_serialize::Compress,
//         ) -> Result<(), ark_serialize::SerializationError> {
//             todo!()
//     }

//     fn serialized_size(&self, compress: ark_serialize::Compress) -> usize {
//         todo!()
//     }
// }

impl<T: CanonicalSerialize + CanonicalDeserialize> FileVec<T> {
    pub fn with_name(path: impl AsRef<Path>) -> Self {
        let path = path.as_ref().to_path_buf();
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(&path)
            .expect("failed to open file");
        Self::File { path, file }
    }

    pub fn new() -> Self {
        let (file, path) = NamedTempFile::new()
            .expect("failed to create temp file")
            .keep()
            .expect("failed to keep temp file");
        Self::File { path, file }
    }

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

    pub fn into_iter(mut self) -> IntoIter<T>
    where
        T: Clone,
    {
        match &mut self {
            Self::File { path, .. } => IntoIter::new_file(File::open(&path).unwrap(), path.clone()),
            Self::Buffer { buffer } => {
                let buffer = core::mem::replace(buffer, Vec::new());
                IntoIter::new_buffer(buffer)
            }
        }
    }

    pub fn from_iter(iter: impl IntoIterator<Item = T>) -> Self
    where
        T: Send + Sync,
    {
        Self::from_batched_iter(BatchAdapter::from(iter.into_iter()))
    }

    pub fn from_batched_iter(iter: impl IntoBatchedIterator<Item = T>) -> Self
    where
        T: Send + Sync,
    {
        let mut iter = iter.into_batched_iter();
        let mut buffer = Vec::with_capacity(BUFFER_SIZE);
        let (mut file, path) = NamedTempFile::new()
            .expect("failed to create temp file")
            .keep()
            .expect("failed to keep temp file");
        let mut writer = BufWriter::new(&mut file);

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
            for item in &buffer {
                item.serialize_uncompressed(&mut writer)
                    .expect("failed to write to file");
            }
            buffer.clear();
            buffer.par_extend(batch);
        }

        // Write the last batch to the file.
        if more_than_one_batch {
            for item in &buffer {
                item.serialize_uncompressed(&mut writer)
                    .expect("failed to write to file");
            }
            writer.flush().expect("failed to flush file");
            drop(writer);
            file.rewind().expect("failed to seek file");
            Self::File { path, file }
        } else {
            let _ = std::fs::remove_file(&path);
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
        A: CanonicalSerialize + CanonicalDeserialize + Send + Sync,
        B: CanonicalSerialize + CanonicalDeserialize + Send + Sync,
    {
        let mut buffer = Vec::<(A, B)>::with_capacity(BUFFER_SIZE);
        let (mut file_1, path_1) = NamedTempFile::new()
            .expect("failed to create temp file")
            .keep()
            .expect("failed to keep temp file");
        let (mut file_2, path_2) = NamedTempFile::new()
            .expect("failed to create temp file")
            .keep()
            .expect("failed to keep temp file");
        let mut writer_1 = BufWriter::new(&mut file_1);
        let mut writer_2 = BufWriter::new(&mut file_2);

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
                    .serialize_uncompressed(&mut writer_1)
                    .expect("failed to write to file");
                item_2
                    .serialize_uncompressed(&mut writer_2)
                    .expect("failed to write to file");
            }
            buffer.clear();
            buffer.par_extend(batch);
        }

        // Write the last batch to the file.
        if more_than_one_batch {
            for (item_1, item_2) in &buffer {
                item_1
                    .serialize_uncompressed(&mut writer_1)
                    .expect("failed to write to file");
                item_2
                    .serialize_uncompressed(&mut writer_2)
                    .expect("failed to write to file");
            }
            writer_1.flush().expect("failed to flush file");
            writer_2.flush().expect("failed to flush file");
            drop(writer_1);
            drop(writer_2);
            file_1.rewind().expect("failed to seek file");
            file_2.rewind().expect("failed to seek file");
            let v1: FileVec<A> = FileVec::File {
                path: path_1,
                file: file_1,
            };
            let v2: FileVec<B> = FileVec::File {
                path: path_2,
                file: file_2,
            };
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

    pub fn deep_copy(&self) -> Self
    where
        T: Send + Sync + Copy + 'static,
    {
        Self::from_batched_iter(self.iter())
    }
}

impl<T: CanonicalSerialize + CanonicalDeserialize> Drop for FileVec<T> {
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

impl<T: CanonicalSerialize + CanonicalDeserialize + Hash> Hash for FileVec<T> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        match self {
            Self::File { path, .. } => path.hash(state),
            Self::Buffer { buffer } => buffer.hash(state),
        }
    }
}

impl<T: CanonicalSerialize + CanonicalDeserialize + PartialEq> PartialEq for FileVec<T> {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::File { path: p1, .. }, Self::File { path: p2, .. }) => p1 == p2,
            (Self::Buffer { buffer: b1 }, Self::Buffer { buffer: b2 }) => b1 == b2,
            _ => false,
        }
    }
}

impl<T: CanonicalSerialize + CanonicalDeserialize + Eq> Eq for FileVec<T> {}
