macro_rules! process_file {
    ($self:ident, $extra:expr) => {{
        match $self {
            FileVec::File(file) => {
                let file_len = file.metadata().unwrap().len();
                let reader = &*file;

                let mut read_buffer = Vec::with_capacity(BUFFER_SIZE);
                let mut read_byte_buffer = AVec::with_capacity(PAGE_SIZE, T::SIZE * BUFFER_SIZE);

                let mut write_buffer = Vec::with_capacity(BUFFER_SIZE);
                let mut write_byte_buffer = avec![0u8; T::SIZE * BUFFER_SIZE];

                let mut writer = InnerFile::new_temp("");
                writer
                    .allocate_space(file_len as usize)
                    .expect("could not allocate space for file");

                let mut num_iters = 0;
                loop {
                    num_iters += 1;
                    read_byte_buffer.clear();
                    write_buffer.clear();
                    // Now read_buffer is empty, and
                    // write_buffer contains the previous contents of read_buffer
                    std::mem::swap(&mut read_buffer, &mut write_buffer);
                    assert!(read_buffer.is_empty());
                    let deser_result = $crate::serialize::serialize_and_deserialize_raw_batch(
                        &write_buffer,
                        &mut write_byte_buffer,
                        &writer,
                        &mut read_buffer,
                        &mut read_byte_buffer,
                        reader,
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
                if num_iters == 1 {
                    assert!(read_buffer.len() <= BUFFER_SIZE);
                    *$self = FileVec::Buffer {
                        buffer: read_buffer,
                    };
                } else {
                    writer.rewind().expect("could not rewind file");
                    *file = writer;
                }
            },
            FileVec::Buffer { buffer } => {
                $extra(&mut *buffer);
            },
        }
    }};
}
