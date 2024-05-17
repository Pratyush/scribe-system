macro_rules! process_file {
    ($self:ident, $extra:expr) => {{
        match $self {
            FileVec::File {
                ref mut file, path, ..
            } => {
                let size = core::mem::size_of::<T>();
                let mut reader = BufReader::with_capacity(size * BUFFER_SIZE, &mut *file);
                let mut buffer = Vec::with_capacity(BUFFER_SIZE);
                let mut byte_buffer = Vec::with_capacity(BUFFER_SIZE * 8);
                let tmp = NamedTempFile::new().expect("failed to create temp file");
                let mut writer = BufWriter::with_capacity(size * BUFFER_SIZE, tmp);

                loop {
                    buffer.clear();
                    byte_buffer.clear();
                    if T::deserialize_raw_batch(
                        &mut buffer,
                        &mut byte_buffer,
                        BUFFER_SIZE,
                        &mut reader,
                    )
                    .is_err()
                    {
                        break;
                    }

                    if buffer.is_empty() {
                        break;
                    }

                    if $extra(&mut buffer).is_none() {
                        break;
                    }

                    byte_buffer.clear();
                    T::serialize_raw_batch(&buffer, &mut byte_buffer, &mut writer)
                        .expect("failed to write to file");
                }
                std::fs::remove_file(&path).expect("failed to remove file");

                let new_file = writer.into_inner().expect("failed to get writer");
                let (mut new_file, new_path) = new_file.keep().expect("failed to keep temp file");
                new_file.rewind().expect("could not rewind file");
                *path = new_path;
                *file = new_file;
            }
            FileVec::Buffer { buffer } => {
                $extra(&mut *buffer);
            }
        }
    }};
}
