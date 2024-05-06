macro_rules! process_file {
    ($self:ident, $extra:expr) => {{
        match $self {
            FileVec::File { ref mut file, path } => {
                let mut reader = BufReader::new(&mut *file);
                let mut buffer = Vec::with_capacity(BUFFER_SIZE);
                let mut byte_buffer = Vec::new();
                let tmp = NamedTempFile::new().expect("failed to create temp file");
                let mut writer = BufWriter::new(tmp);
                loop {
                    buffer.clear();
                    byte_buffer.clear();
                    if utils::par_deserialize(&mut reader, &mut byte_buffer, &mut buffer).is_none()
                    {
                        break;
                    }

                    if buffer.is_empty() {
                        break;
                    }

                    if $extra(&mut buffer).is_none() {
                        break;
                    }

                    for item in &buffer {
                        item.serialize_uncompressed(&mut writer)
                            .expect("failed to write to file");
                    }
                }

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
