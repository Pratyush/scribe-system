use crate::{
    BUFFER_SIZE,
    serialize::{DeserializeRaw, SerializeRaw},
};

use super::{AVec, avec};

pub struct BuffersRef<'a, T> {
    pub(super) t_s: &'a mut Vec<T>, // capacity = BUFFER_SIZE
    pub(super) bytes: AVec,         // capacity = BUFFER_SIZE * T::SIZE
}

impl<'a, T: SerializeRaw + DeserializeRaw> BuffersRef<'a, T> {
    #[inline]
    pub(super) fn new(t_s: &'a mut Vec<T>) -> Self {
        let mut bytes = avec![];
        bytes.reserve(T::SIZE * BUFFER_SIZE);

        Self { t_s, bytes }
    }

    #[inline]
    pub(super) fn clear(&mut self) {
        self.t_s.clear();
        self.bytes.clear();
    }
}

pub struct Buffers<T> {
    pub(super) t_s: Vec<T>, // capacity = BUFFER_SIZE
    pub(super) bytes: AVec, // capacity = BUFFER_SIZE * T::SIZE
}

impl<T: SerializeRaw + DeserializeRaw> Buffers<T> {
    #[inline]
    pub(super) fn new() -> Self {
        let mut bytes = avec![];
        bytes.reserve(T::SIZE * BUFFER_SIZE);
        let t_s = Vec::with_capacity(BUFFER_SIZE);

        Self { t_s, bytes }
    }

    #[inline]
    pub(super) fn clear(&mut self) {
        self.t_s.clear();
        self.bytes.clear();
    }
}
