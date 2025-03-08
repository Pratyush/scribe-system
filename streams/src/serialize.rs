use rayon::prelude::*;
use std::{io, mem::{self, MaybeUninit}};

use ark_ec::{
    short_weierstrass::{Affine as SWAffine, SWCurveConfig},
    twisted_edwards::{Affine as TEAffine, TECurveConfig},
    AffineRepr,
};
use ark_ff::{BigInt, Field, Fp, FpConfig, PrimeField};
use ark_serialize::{Read, Write};

use crate::file_vec::backend::ReadN;

use super::file_vec::AVec;

pub trait SerializeRaw: Sized {
    const SIZE: usize = mem::size_of::<Self>();

    fn serialize_raw(&self, writer: &mut &mut [u8]) -> Option<()>;

    fn serialize_raw_batch(
        result_buffer: &[Self],
        work_buffer: &mut AVec,
        mut file: impl Write,
    ) -> Result<(), io::Error>
    where
        Self: Sync + Send + Sized,
    {
        if result_buffer.is_empty() {
            return Ok(());
        }
        work_buffer.clear();
        let n = result_buffer.len() * Self::SIZE;
        work_buffer.reserve(n);
        // Safety: `work_buffer` is empty and has capacity at least `n`.
        unsafe {
            work_buffer.set_len(n);
        }
        work_buffer.fill(0);

        work_buffer
            .par_chunks_mut(Self::SIZE)
            .zip(result_buffer)
            .with_min_len(1 << 8)
            .for_each(|(mut chunk, val)| {
                val.serialize_raw(&mut chunk).unwrap();
            });
        file.write_all(work_buffer)?;
        Ok(())
    }
}

pub trait DeserializeRaw: SerializeRaw + Sized + std::fmt::Debug + Copy {
    fn deserialize_raw(reader: &mut &[u8]) -> Option<Self>;

    fn deserialize_raw_batch(
        result_buffer: &mut Vec<Self>,
        work_buffer: &mut AVec,
        batch_size: usize,
        mut file: impl ReadN,
    ) -> Result<(), io::Error>
    where
        Self: Sync + Send,
    {
        work_buffer.clear();
        result_buffer.clear();
        let size = Self::SIZE;
        (&mut file).read_n(work_buffer, size * batch_size)?;

        if rayon::current_num_threads() == 1 {
            result_buffer.extend(
                work_buffer
                    .chunks(size)
                    .map(|mut chunk| Self::deserialize_raw(&mut chunk).unwrap()),
            );
        } else {
            result_buffer.par_extend(
                work_buffer
                    .par_chunks(size)
                    .with_min_len(1 << 10)
                    .map(|mut chunk| Self::deserialize_raw(&mut chunk).unwrap()),
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
    read_work_buffer: &mut AVec,
    mut read_file: impl ReadN + Send,
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
                .zip(write_buffer)
                .with_min_len(1 << 10)
                .for_each(|(mut chunk, val)| val.serialize_raw(&mut chunk).unwrap());
            Ok(())
        },
        || -> Result<(), io::Error> {
            read_work_buffer.clear();
            read_buffer.clear();
            (&mut read_file).read_n(read_work_buffer, T::SIZE * batch_size)?;
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
                        .map(|mut chunk| T::deserialize_raw(&mut chunk).unwrap()),
                );
                Ok(())
            } else {
                read_buffer.par_extend(
                    read_work_buffer
                        .par_chunks(T::SIZE)
                        .with_min_len(1 << 10)
                        .map(|mut chunk| T::deserialize_raw(&mut chunk).unwrap()),
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

            fn serialize_raw(&self, writer: &mut &mut [u8]) -> Option<()> {
                writer.write_all(&self.to_le_bytes()).ok()
            }
        }

        impl DeserializeRaw for $type {
            #[inline(always)]
            fn deserialize_raw(reader: &mut &[u8]) -> Option<Self> {
                let mut bytes = [0u8; core::mem::size_of::<$type>()];
                reader.read_exact(&mut bytes).ok()?;
                Some(<$type>::from_le_bytes(bytes))
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
    fn serialize_raw(&self, writer: &mut &mut [u8]) -> Option<()> {
        writer.write_all(&[*self as u8]).ok()
    }
}

impl DeserializeRaw for bool {
    #[inline(always)]
    fn deserialize_raw(reader: &mut &[u8]) -> Option<Self> {
        let mut byte = [0u8; 1];
        reader.read_exact(&mut byte).ok()?;
        Some(byte[0] != 0)
    }
}

impl SerializeRaw for usize {
    const SIZE: usize = core::mem::size_of::<u64>();
    #[inline(always)]
    fn serialize_raw(&self, writer: &mut &mut [u8]) -> Option<()> {
        writer.write_all(&(*self as u64).to_le_bytes()).ok()
    }
}

impl DeserializeRaw for usize {
    #[inline(always)]
    fn deserialize_raw(reader: &mut &[u8]) -> Option<Self> {
        let mut bytes = [0u8; core::mem::size_of::<u64>()];
        reader.read_exact(&mut bytes).unwrap();
        Some(<u64>::from_le_bytes(bytes) as usize)
    }
}

impl<T: SerializeRaw, const N: usize> SerializeRaw for [T; N] {
    const SIZE: usize = T::SIZE * N;

    #[inline(always)]
    fn serialize_raw(&self, mut writer: &mut &mut [u8]) -> Option<()> {
        for item in self.iter() {
            item.serialize_raw(&mut writer)?;
        }
        Some(())
    }
}

impl<T: DeserializeRaw + Copy, const N: usize> DeserializeRaw for [T; N] {
    #[inline(always)]
    fn deserialize_raw(mut reader: &mut &[u8]) -> Option<Self> {
        let mut array = [MaybeUninit::uninit(); N];
        for a in array.iter_mut().take(N) {
            *a = MaybeUninit::new(T::deserialize_raw(&mut reader)?);
        }
        Some(array.map(|item| unsafe { item.assume_init() }))
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
            fn serialize_raw(&self, mut writer: &mut &mut [u8]) -> Option<()> {
                $(self.$no.serialize_raw(&mut writer)?;)*
                Some(())
            }
        }

        impl<$($ty, )*> DeserializeRaw for ($($ty,)*) where
            $($ty: DeserializeRaw,)*
        {
            #[inline(always)]

            fn deserialize_raw(
                #[allow(unused_variables, unused_mut)]
                mut reader: &mut &[u8]
            ) -> Option<Self> {
                Some(($(
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
    fn serialize_raw(&self, writer: &mut &mut [u8]) -> Option<()> {
        self.0.serialize_raw(writer)
    }
}

impl<const N: usize> DeserializeRaw for BigInt<N> {
    #[inline(always)]
    fn deserialize_raw(reader: &mut &[u8]) -> Option<Self> {
        <[u64; N]>::deserialize_raw(reader).map(BigInt)
    }
    
    fn deserialize_raw_batch(
        result_buffer: &mut Vec<Self>,
        work_buffer: &mut AVec,
        batch_size: usize,
        mut file: impl ReadN,
    ) -> Result<(), io::Error>
    where
        Self: Sync + Send,
    {

        work_buffer.clear();
        result_buffer.clear();
        let size = Self::SIZE;
        (&mut file).read_n(work_buffer, size * batch_size)?;
        let (head, mid, tail) = unsafe { work_buffer.align_to::<BigInt<N>>() };
        assert!(head.is_empty());
        assert!(tail.is_empty());
        result_buffer.extend_from_slice(mid);

        // if rayon::current_num_threads() == 1 {
        //     result_buffer.extend(
        //         work_buffer
        //             .chunks(size)
        //             .map(|mut chunk| Self::deserialize_raw(&mut chunk).unwrap()),
        //     );
        // } else {
        //     result_buffer.par_extend(
        //         work_buffer
        //             .par_chunks(size)
        //             .with_min_len(1 << 10)
        //             .map(|mut chunk| Self::deserialize_raw(&mut chunk).unwrap()),
        //     );
        // }

        Ok(())
    }
}

impl<P: FpConfig<N>, const N: usize> RawField for Fp<P, N> {}
impl<P: FpConfig<N>, const N: usize> RawPrimeField for Fp<P, N> {}

impl<P: FpConfig<N>, const N: usize> SerializeRaw for Fp<P, N> {
    const SIZE: usize = N * 8;

    #[inline(always)]
    fn serialize_raw(&self, writer: &mut &mut [u8]) -> Option<()> {
        self.0.serialize_raw(writer)
    }
}

impl<P: FpConfig<N>, const N: usize> DeserializeRaw for Fp<P, N> {
    #[inline(always)]
    fn deserialize_raw(reader: &mut &[u8]) -> Option<Self> {
        BigInt::deserialize_raw(reader).map(|x| Fp(x, core::marker::PhantomData))
    }
    
    fn deserialize_raw_batch(
        result_buffer: &mut Vec<Self>,
        work_buffer: &mut AVec,
        batch_size: usize,
        mut file: impl ReadN,
    ) -> Result<(), io::Error>
    where
        Self: Sync + Send,
    {
        work_buffer.clear();
        result_buffer.clear();
        let size = Self::SIZE;
        (&mut file).read_n(work_buffer, size * batch_size)?;
        let (head, mid, tail) = unsafe { work_buffer.align_to::<Fp<P, N>>() };
        assert!(head.is_empty());
        assert!(tail.is_empty());
        if rayon::current_num_threads() == 1 {
            result_buffer.extend_from_slice(mid);
        } else {
            result_buffer.par_extend(
                mid.par_iter()
                    .with_min_len(1 << 10)
                    .map(|x| Fp(x.0, core::marker::PhantomData)),
            );
        }

        Ok(())
    }
}

impl<P: SWCurveConfig> SerializeRaw for SWAffine<P>
where
    P::BaseField: SerializeRaw,
{
    const SIZE: usize = 2 * P::BaseField::SIZE;

    #[inline(always)]
    fn serialize_raw(&self, mut writer: &mut &mut [u8]) -> Option<()> {
        self.x.serialize_raw(&mut writer)?;
        self.y.serialize_raw(writer)
    }
}

impl<P: SWCurveConfig> DeserializeRaw for SWAffine<P>
where
    P::BaseField: DeserializeRaw,
{
    #[inline(always)]
    fn deserialize_raw(mut reader: &mut &[u8]) -> Option<Self> {
        let x = P::BaseField::deserialize_raw(&mut reader)?;
        let y = P::BaseField::deserialize_raw(reader)?;
        Some(Self::new_unchecked(x, y))
    }
}

impl<P: TECurveConfig> SerializeRaw for TEAffine<P>
where
    P::BaseField: SerializeRaw,
{
    const SIZE: usize = 2 * P::BaseField::SIZE;

    #[inline(always)]
    fn serialize_raw(&self, mut writer: &mut &mut [u8]) -> Option<()> {
        self.x.serialize_raw(&mut writer)?;
        self.y.serialize_raw(writer)
    }
}

impl<P: TECurveConfig> DeserializeRaw for TEAffine<P>
where
    P::BaseField: DeserializeRaw,
{
    #[inline(always)]
    fn deserialize_raw(mut reader: &mut &[u8]) -> Option<Self> {
        let x = P::BaseField::deserialize_raw(&mut reader)?;
        let y = P::BaseField::deserialize_raw(reader)?;
        Some(Self::new_unchecked(x, y))
    }
}

impl<P: SWCurveConfig> RawAffine for SWAffine<P> where P::BaseField: SerializeRaw + DeserializeRaw {}
impl<P: TECurveConfig> RawAffine for TEAffine<P> where P::BaseField: SerializeRaw + DeserializeRaw {}

#[cfg(test)]
mod tests {
    use crate::{file_vec::backend::avec, BUFFER_SIZE};

    use super::*;
    use ark_bls12_381::Fr;
    use ark_std::UniformRand;
    fn test_serialize<T: PartialEq + core::fmt::Debug + SerializeRaw + DeserializeRaw>(data: T) {
        let mut serialized = vec![0; T::SIZE];
        data.serialize_raw(&mut &mut serialized[..]).unwrap();
        let de = T::deserialize_raw(&mut &serialized[..]).unwrap();
        assert_eq!(data, de);
    }

    fn test_serialize_batch<
        T: Sync + Send + Clone + PartialEq + core::fmt::Debug + SerializeRaw + DeserializeRaw,
    >(
        data: &[T],
    ) {
        let size = T::SIZE;
        let mut serialized = avec![0u8; size * data.len()];
        let mut buffer = serialized.clone();
        T::serialize_raw_batch(data, &mut buffer, &mut serialized[..]).unwrap();
        let mut final_result = vec![];
        let mut result_buf = vec![];
        let mut buffer_2 = avec![];
        buffer_2.extend_from_slice(&buffer);
        while final_result.len() < data.len() {
            T::deserialize_raw_batch(
                &mut result_buf,
                &mut buffer_2,
                BUFFER_SIZE,
                &serialized[(final_result.len() * size)..],
            )
            .unwrap();
            buffer_2.clear();
            final_result.extend(result_buf.drain(..));
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
