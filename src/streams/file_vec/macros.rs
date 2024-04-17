macro_rules! process_file {
    ($self:ident, $extra:expr) => {{
        let mut reader = BufReader::new(&mut $self.file);
        let mut buffer = Vec::with_capacity(BUFFER_SIZE);
        let tmp = NamedTempFile::new().expect("failed to create temp file");
        let mut writer = BufWriter::new(tmp);
        loop {
            buffer.clear();
            for _ in 0..BUFFER_SIZE {
                match T::deserialize_uncompressed_unchecked(&mut reader) {
                    Ok(val) => buffer.push(val),
                    Err(_) => break,
                }
            }

            if buffer.is_empty() {
                break;
            }

            if $extra(&mut buffer).is_none() {
                break;
            }

            for item in &buffer {
                item.serialize_uncompressed(&mut writer).expect("failed to write to file");
            }
        }

        let new_file = writer.into_inner().expect("failed to get writer");
        let (new_file, new_path) = new_file.keep().expect("failed to keep temp file");
        $self.path = new_path;
        $self.file = new_file;
        $self.file.rewind().expect("could not rewind file");
    }};
}