macro_rules! process_file {
    ($self:ident, $extra:expr) => {{
        match $self {
            FileVec::File {
                ref mut file, path, ..
            } => {
                let mut reader = &mut *file;

                let mut read_buffer = Vec::with_capacity(BUFFER_SIZE);
                let mut read_byte_buffer = Vec::with_capacity(T::SIZE * BUFFER_SIZE);

                let mut write_buffer = Vec::with_capacity(BUFFER_SIZE);
                let mut write_byte_buffer = vec![0u8; T::SIZE * BUFFER_SIZE];

                let mut writer = NamedTempFile::new().expect("failed to create temp file");

                loop {
                    read_byte_buffer.clear();
                    write_buffer.clear();
                    // Now read_buffer is empty, and
                    // write_buffer contains the previous contents of read_buffer
                    std::mem::swap(&mut read_buffer, &mut write_buffer);
                    assert!(read_buffer.is_empty());
                    let deser_result =
                        $crate::streams::serialize::serialize_and_deserialize_raw_batch(
                            &write_buffer,
                            &mut write_byte_buffer,
                            &mut writer,
                            &mut read_buffer,
                            &mut read_byte_buffer,
                            &mut reader,
                            BUFFER_SIZE,
                        );

                    if deser_result.is_err() {
                        break;
                    }

                    if read_buffer.is_empty() {
                        break;
                    }

                    if $extra(&mut read_buffer).is_none() {
                        break;
                    }
                }
                std::fs::remove_file(&path).expect("failed to remove file");

                let (mut new_file, new_path) = writer.keep().expect("failed to keep temp file");
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
