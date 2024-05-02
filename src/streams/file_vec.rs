use std::{
    fs::{File, OpenOptions},
    hash::{Hash, Hasher},
    io::{BufReader, BufWriter, Seek},
    marker::PhantomData,
    path::{Path, PathBuf},
};

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Write};
use rayon::iter::{
    IndexedParallelIterator, IntoParallelRefMutIterator, ParallelExtend, ParallelIterator,
};
use tempfile::NamedTempFile;

pub use self::iter::Iter;

use super::{
    iterator::{BatchedIterator, IntoBatchedIterator},
    BUFFER_SIZE,
};

mod iter;
#[macro_use]
mod macros;

#[derive(Debug)]
pub struct FileVec<T: CanonicalSerialize + CanonicalDeserialize> {
    path: PathBuf,
    file: File,
    phantom: PhantomData<T>,
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
        Self {
            path,
            file,
            phantom: PhantomData,
        }
    }

    pub fn new() -> Self {
        let (file, path) = NamedTempFile::new()
            .expect("failed to create temp file")
            .keep()
            .expect("failed to keep temp file");
        Self {
            path,
            file,
            phantom: PhantomData,
        }
    }

    pub fn iter<'a>(&'a self) -> Iter<'a, T> {
        let file = OpenOptions::new()
            .read(true)
            .open(&self.path)
            .expect(&format!(
                "failed to open file, {}",
                self.path.to_str().unwrap()
            ));
        Iter::new(file)
    }

    pub fn from_iter(iter: impl IntoIterator<Item = T>) -> Self
    where
        T: Send + Sync,
    {
        let mut file_vec = Self::new();
        let mut writer = BufWriter::new(&mut file_vec.file);
        let mut iter = iter.into_iter();

        // Read from iterator and write to file.
        while let Some(e) = iter.next() {
            e.serialize_uncompressed(&mut writer)
                .expect("failed to write to file");
        }
        writer.flush().expect("failed to flush file");
        drop(writer);

        // Reset file cursor to beginning.
        file_vec.file.rewind().expect("failed to seek file");
        file_vec
    }

    pub fn from_batched_iter(iter: impl IntoBatchedIterator<Item = T>) -> Self
    where
        T: Send + Sync,
    {
        let mut file_vec = Self::new();
        let mut writer = BufWriter::new(&mut file_vec.file);
        let mut buffer = Vec::with_capacity(BUFFER_SIZE);
        let mut iter = iter.into_batched_iter();

        // Read from iterator and write to file.
        while let Some(batch) = iter.next_batch() {
            buffer.clear();
            buffer.par_extend(batch);
            for item in &buffer {
                item.serialize_uncompressed(&mut writer)
                    .expect("failed to write to file");
            }
        }
        writer.flush().expect("failed to flush file");
        drop(writer);

        // Reset file cursor to beginning.
        file_vec.file.rewind().expect("failed to seek file");
        file_vec
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
        let mut vec_1 = FileVec::new();
        let mut vec_2 = FileVec::new();
        let mut writer_1 = BufWriter::new(&mut vec_1.file);
        let mut writer_2 = BufWriter::new(&mut vec_2.file);
        let mut buffer = Vec::with_capacity(BUFFER_SIZE);

        // Read from iterator and write to file.
        while let Some(batch) = iter.next_batch() {
            buffer.clear();
            buffer.par_extend(batch);
            for (item_1, item_2) in &buffer {
                item_1
                    .serialize_uncompressed(&mut writer_1)
                    .expect("failed to write to file");
                item_2
                    .serialize_uncompressed(&mut writer_2)
                    .expect("failed to write to file");
            }
        }
        writer_1.flush().expect("failed to flush file");
        writer_2.flush().expect("failed to flush file");
        drop(writer_1);
        drop(writer_2);

        // Reset file cursor to beginning.
        vec_1.file.rewind().expect("failed to seek file");
        vec_2.file.rewind().expect("failed to seek file");
        (vec_1, vec_2)
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
        match std::fs::remove_file(&self.path) {
            Ok(_) => (),
            Err(e) => eprintln!("Failed to remove file at path {:?}: {:?}", self.path, e),
        }
    }
}

impl<T: CanonicalSerialize + CanonicalDeserialize> Hash for FileVec<T> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.path.hash(state);
    }
}

impl<T: CanonicalSerialize + CanonicalDeserialize> PartialEq for FileVec<T> {
    fn eq(&self, other: &Self) -> bool {
        self.path == other.path
    }
}

impl<T: CanonicalSerialize + CanonicalDeserialize> Eq for FileVec<T> {}
