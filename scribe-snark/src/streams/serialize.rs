use rayon::prelude::*;
use std::{
    io,
    mem::{self, MaybeUninit},
};

use ark_ec::{
    short_weierstrass::{Affine as SWAffine, SWCurveConfig},
    twisted_edwards::{Affine as TEAffine, TECurveConfig},
    AffineRepr,
};
use ark_ff::{BigInt, Field, Fp, FpConfig, PrimeField};
use ark_serialize::{Read, Write};

pub trait SerializeRaw: Sized {
    const SIZE: usize = mem::size_of::<Self>();

    fn serialize_raw<W: Write>(&self, writer: W) -> Result<(), io::Error>;

    fn serialize_raw_batch(
        result_buffer: &[Self],
        work_buffer: &mut Vec<u8>,
        mut file: impl Write,
    ) -> Result<(), io::Error>
    where
        Self: Sync + Send + Sized,
    {
        if result_buffer.is_empty() {
            return Ok(());
        }
        work_buffer.clear();

        work_buffer.par_extend(result_buffer.par_chunks(1 << 10).flat_map(|v| {
            let mut buffer = Vec::with_capacity((1 << 10) * Self::SIZE);
            for val in v {
                val.serialize_raw(&mut buffer).unwrap();
            }
            buffer
        }));
        file.write_all(work_buffer)?;
        Ok(())
    }
}

pub trait DeserializeRaw: SerializeRaw + Sized {
    fn deserialize_raw<R: Read>(reader: R) -> Result<Self, io::Error>;

    fn deserialize_raw_batch(
        result_buffer: &mut Vec<Self>,
        work_buffer: &mut Vec<u8>,
        batch_size: usize,
        mut file: impl Read,
    ) -> Result<(), io::Error>
    where
        Self: Sync + Send,
    {
        work_buffer.clear();
        result_buffer.clear();
        let size = Self::SIZE;
        (&mut file)
            .take((size * batch_size) as u64)
            .read_to_end(work_buffer)?;

        if rayon::current_num_threads() == 1 {
            result_buffer.extend(
                work_buffer
                    .chunks(size)
                    .map(|chunk| Self::deserialize_raw(chunk).unwrap()),
            );
        } else {
            result_buffer.par_extend(
                work_buffer
                    .par_chunks(size)
                    .with_min_len(1 << 10)
                    .map(|chunk| Self::deserialize_raw(chunk).unwrap()),
            );
        }

        Ok(())
    }
}

pub(crate) fn serialize_and_deserialize_raw_batch<
    T: SerializeRaw + DeserializeRaw + Sync + Send,
>(
    write_buffer: &[T],
    write_work_buffer: &mut Vec<u8>,
    mut write_file: impl Write + Send,
    read_buffer: &mut Vec<T>,
    read_work_buffer: &mut Vec<u8>,
    mut read_file: impl Read + Send,
    batch_size: usize,
) -> Result<(), io::Error> {
    // Serialize
    let (write_to_buf, read_to_buf) = rayon::join(
        || -> Result<(), io::Error> {
            if write_buffer.is_empty() {
                return Ok(());
            }
            write_work_buffer
                .par_chunks_mut(T::SIZE)
                .zip(write_buffer.par_iter())
                .with_min_len(1 << 10)
                .for_each(|(chunk, val)| val.serialize_raw(chunk).unwrap());
            Ok(())
        },
        || -> Result<(), io::Error> {
            read_work_buffer.clear();
            read_buffer.clear();
            (&mut read_file)
                .take((T::SIZE * batch_size) as u64)
                .read_to_end(read_work_buffer)?;
            Ok(())
        },
    );
    write_to_buf?;
    read_to_buf?;
    let (write_to_file, read_from_buf) = rayon::join(
        || write_file.write_all(&write_work_buffer[..write_buffer.len() * T::SIZE]),
        || -> Result<(), io::Error> {
            if rayon::current_num_threads() == 1 {
                read_buffer.extend(
                    read_work_buffer
                        .chunks(T::SIZE)
                        .map(|chunk| T::deserialize_raw(chunk).unwrap()),
                );
                Ok(())
            } else {
                read_buffer.par_extend(
                    read_work_buffer
                        .par_chunks(T::SIZE)
                        .with_min_len(1 << 10)
                        .map(|chunk| T::deserialize_raw(chunk).unwrap()),
                );
                Ok(())
            }
        },
    );
    write_to_file?;
    read_from_buf?;
    Ok(())
}

pub trait RawField: SerializeRaw + DeserializeRaw + Field {}
pub trait RawPrimeField: RawField + PrimeField {}

pub trait RawAffine: SerializeRaw + DeserializeRaw + AffineRepr {}

macro_rules! impl_uint {
    ($type:ty) => {
        impl SerializeRaw for $type {
            #[inline(always)]
            fn serialize_raw<W: Write>(&self, mut writer: W) -> Result<(), io::Error> {
                writer.write_all(&self.to_le_bytes())
            }
        }

        impl DeserializeRaw for $type {
            #[inline(always)]
            fn deserialize_raw<R: Read>(mut reader: R) -> Result<Self, io::Error> {
                let mut bytes = [0u8; core::mem::size_of::<$type>()];
                reader.read_exact(&mut bytes)?;
                Ok(<$type>::from_le_bytes(bytes))
            }
        }
    };
}

impl_uint!(u8);
impl_uint!(u16);
impl_uint!(u32);
impl_uint!(u64);

impl SerializeRaw for bool {
    const SIZE: usize = 1;
    #[inline(always)]
    fn serialize_raw<W: Write>(&self, mut writer: W) -> Result<(), io::Error> {
        writer.write_all(&[*self as u8])
    }
}

impl DeserializeRaw for bool {
    #[inline(always)]
    fn deserialize_raw<R: Read>(mut reader: R) -> Result<Self, io::Error> {
        let mut byte = [0u8; 1];
        reader.read_exact(&mut byte)?;
        Ok(byte[0] != 0)
    }
}

impl SerializeRaw for usize {
    const SIZE: usize = core::mem::size_of::<u64>();
    #[inline(always)]
    fn serialize_raw<W: Write>(&self, mut writer: W) -> Result<(), io::Error> {
        writer.write_all(&(*self as u64).to_le_bytes())
    }
}

impl DeserializeRaw for usize {
    #[inline(always)]
    fn deserialize_raw<R: Read>(mut reader: R) -> Result<Self, io::Error> {
        let mut bytes = [0u8; core::mem::size_of::<u64>()];
        reader.read_exact(&mut bytes)?;
        Ok(<u64>::from_le_bytes(bytes) as usize)
    }
}

impl<T: SerializeRaw, const N: usize> SerializeRaw for [T; N] {
    const SIZE: usize = T::SIZE * N;

    #[inline(always)]
    fn serialize_raw<W: Write>(&self, mut writer: W) -> Result<(), io::Error> {
        for item in self.iter() {
            item.serialize_raw(&mut writer)?;
        }
        Ok(())
    }
}

impl<T: DeserializeRaw, const N: usize> DeserializeRaw for [T; N] {
    #[inline(always)]
    fn deserialize_raw<R: Read>(mut reader: R) -> Result<Self, io::Error> {
        let mut array = [(); N].map(|_| MaybeUninit::uninit());
        for a in array.iter_mut().take(N) {
            let item = T::deserialize_raw(&mut reader)?;
            *a = MaybeUninit::new(item);
        }
        Ok(array.map(|item| unsafe { item.assume_init() }))
    }
}

// Implement Serialization for tuples
macro_rules! impl_tuple {
    ($( $ty: ident : $no: tt, )*) => {
        #[allow(unused)]
        impl<$($ty, )*> SerializeRaw for ($($ty,)*) where
            $($ty: SerializeRaw,)*
        {
            const SIZE: usize = {
                0 $( + $ty::SIZE)*
            };

            #[inline(always)]
            fn serialize_raw<W: Write>(&self, mut writer: W) -> Result<(), io::Error> {
                $(self.$no.serialize_raw(&mut writer)?;)*
                Ok(())
            }
        }

        impl<$($ty, )*> DeserializeRaw for ($($ty,)*) where
            $($ty: DeserializeRaw,)*
        {
            #[inline(always)]
            fn deserialize_raw<R: Read>(
                #[allow(unused)]
                mut reader: R
            ) -> Result<Self, io::Error> {
                Ok(($(
                    $ty::deserialize_raw(&mut reader)?,
                )*))
            }
        }
    }
}

impl_tuple!();
impl_tuple!(A:0,);
impl_tuple!(A:0, B:1,);
impl_tuple!(A:0, B:1, C:2,);
impl_tuple!(A:0, B:1, C:2, D:3,);
impl_tuple!(A:0, B:1, C:2, D:3, E:4,);

impl<const N: usize> SerializeRaw for BigInt<N> {
    const SIZE: usize = N * 8;
    #[inline(always)]
    fn serialize_raw<W: Write>(&self, writer: W) -> Result<(), io::Error> {
        self.0.serialize_raw(writer)
    }
}

impl<const N: usize> DeserializeRaw for BigInt<N> {
    #[inline(always)]
    fn deserialize_raw<R: Read>(reader: R) -> Result<Self, io::Error> {
        <[u64; N]>::deserialize_raw(reader).map(BigInt)
    }
}

impl<P: FpConfig<N>, const N: usize> RawField for Fp<P, N> {}
impl<P: FpConfig<N>, const N: usize> RawPrimeField for Fp<P, N> {}

impl<P: FpConfig<N>, const N: usize> SerializeRaw for Fp<P, N> {
    const SIZE: usize = N * 8;

    #[inline(always)]
    fn serialize_raw<W: Write>(&self, writer: W) -> Result<(), io::Error> {
        self.0.serialize_raw(writer)
    }
}

impl<P: FpConfig<N>, const N: usize> DeserializeRaw for Fp<P, N> {
    #[inline(always)]
    fn deserialize_raw<R: Read>(reader: R) -> Result<Self, io::Error> {
        BigInt::deserialize_raw(reader).map(|b| Fp(b, core::marker::PhantomData))
    }
}

impl<P: SWCurveConfig> SerializeRaw for SWAffine<P>
where
    P::BaseField: SerializeRaw,
{
    const SIZE: usize = 2 * P::BaseField::SIZE;

    #[inline(always)]
    fn serialize_raw<W: Write>(&self, mut writer: W) -> Result<(), io::Error> {
        self.x.serialize_raw(&mut writer)?;
        self.y.serialize_raw(writer)
    }
}

impl<P: SWCurveConfig> DeserializeRaw for SWAffine<P>
where
    P::BaseField: DeserializeRaw,
{
    #[inline(always)]
    fn deserialize_raw<R: Read>(mut reader: R) -> Result<Self, io::Error> {
        let x = P::BaseField::deserialize_raw(&mut reader)?;
        let y = P::BaseField::deserialize_raw(reader)?;
        Ok(Self::new_unchecked(x, y))
    }
}

impl<P: TECurveConfig> SerializeRaw for TEAffine<P>
where
    P::BaseField: SerializeRaw,
{
    const SIZE: usize = 2 * P::BaseField::SIZE;

    #[inline(always)]
    fn serialize_raw<W: Write>(&self, mut writer: W) -> Result<(), io::Error> {
        self.x.serialize_raw(&mut writer)?;
        self.y.serialize_raw(writer)
    }
}

impl<P: TECurveConfig> DeserializeRaw for TEAffine<P>
where
    P::BaseField: DeserializeRaw,
{
    #[inline(always)]
    fn deserialize_raw<R: Read>(mut reader: R) -> Result<Self, io::Error> {
        let x = P::BaseField::deserialize_raw(&mut reader)?;
        let y = P::BaseField::deserialize_raw(reader)?;
        Ok(Self::new_unchecked(x, y))
    }
}

impl<P: SWCurveConfig> RawAffine for SWAffine<P> where P::BaseField: SerializeRaw + DeserializeRaw {}
impl<P: TECurveConfig> RawAffine for TEAffine<P> where P::BaseField: SerializeRaw + DeserializeRaw {}

#[cfg(test)]
mod tests {
    use crate::streams::BUFFER_SIZE;

    use super::*;
    use ark_bls12_381::Fr;
    use ark_std::UniformRand;
    fn test_serialize<T: PartialEq + core::fmt::Debug + SerializeRaw + DeserializeRaw>(data: T) {
        let mut serialized = vec![0; T::SIZE];
        data.serialize_raw(&mut serialized[..]).unwrap();
        let de = T::deserialize_raw(&serialized[..]).unwrap();
        assert_eq!(data, de);
    }

    fn test_serialize_batch<
        T: Sync + Send + Clone + PartialEq + core::fmt::Debug + SerializeRaw + DeserializeRaw,
    >(
        data: &[T],
    ) {
        let size = T::SIZE;
        let mut serialized = vec![0u8; size * data.len()];
        let mut buffer = serialized.clone();
        T::serialize_raw_batch(data, &mut buffer, &mut serialized[..]).unwrap();
        let mut final_result = vec![];
        let mut result_buf = vec![];
        while final_result.len() < data.len() {
            T::deserialize_raw_batch(
                &mut result_buf,
                &mut buffer,
                BUFFER_SIZE,
                &serialized[(final_result.len() * size)..],
            )
            .unwrap();
            buffer.clear();
            final_result.extend(result_buf.clone());
            result_buf.clear();
        }
        assert_eq!(&data, &final_result);
    }

    #[test]
    fn test_uint() {
        test_serialize(192830918usize);
        test_serialize(192830918u64);
        test_serialize(192830918u32);
        test_serialize(22313u16);
        test_serialize(123u8);
        let mut rng = ark_std::test_rng();
        for size in [1, 2, 4, 8, 16] {
            let data = (0..size).map(|_| u8::rand(&mut rng)).collect::<Vec<_>>();
            test_serialize_batch(&data);
        }
    }
    #[test]
    fn test_array() {
        test_serialize([1u64, 2, 3, 4, 5]);
        test_serialize([1u8; 33]);
        let mut rng = ark_std::test_rng();
        for size in [1, 2, 4, 8, 16] {
            let data = (0..size)
                .map(|_| [u64::rand(&mut rng); 10])
                .collect::<Vec<_>>();
            test_serialize_batch(&data);
        }
    }

    #[test]
    fn test_field() {
        let mut rng = ark_std::test_rng();
        for _ in 0..100 {
            test_serialize(Fr::rand(&mut rng));
        }
        for size in [1, 2, 4, 8, 16] {
            let data = (0..(BUFFER_SIZE * size))
                .map(|_| Fr::rand(&mut rng))
                .collect::<Vec<_>>();
            test_serialize_batch(&data);
        }
    }
}
