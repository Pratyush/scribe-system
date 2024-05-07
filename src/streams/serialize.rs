use std::{borrow::Borrow, io, mem::MaybeUninit};
use rayon::prelude::*;

use ark_ec::{short_weierstrass::{Affine as SWAffine, SWCurveConfig}, twisted_edwards::{TECurveConfig, Affine as TEAffine}, AffineRepr};
use ark_ff::{BigInt, Field, Fp, FpConfig, PrimeField};
use ark_serialize::{Read, Write};
use ark_std::{end_timer, start_timer};

pub trait SerializeRaw {
    const SIZE: Option<usize>;
    fn serialize_raw<W: Write>(&self, writer: W) -> Result<(), io::Error>;
    
    fn serialize_raw_batch(
        result_buffer: &[Self],
        work_buffer: &mut Vec<u8>,
        mut file: impl Write,
    ) -> Result<(), io::Error>
        where Self: Sync + Send + Sized
    {
        work_buffer.clear();
        let size = result_buffer[0].serialized_size();
        
        let time = start_timer!(|| "Serializing");
        work_buffer.par_extend(result_buffer.par_chunks(1024).flat_map(|v| {
            let mut buffer = Vec::with_capacity(1024 * size);
            for val in v {
                val.serialize_raw(&mut buffer).unwrap();
            }
            buffer
        }));
        end_timer!(time);
        let write_time = start_timer!(|| "Writing");
        file.write_all(&work_buffer)?;
        end_timer!(write_time);
        Ok(())
    }
    
    fn serialized_size(&self) -> usize {
        Self::SIZE.unwrap()
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
        where Self: Sync + Send
    {
        work_buffer.clear();
        result_buffer.clear();
        let val = Self::deserialize_raw(&mut file)?;
        let size = val.serialized_size();
        result_buffer.push(val);
        let read_time = start_timer!(|| "Reading");
        (&mut file).take((size * (batch_size - 1)) as u64)
                .read_to_end(work_buffer)?;
        end_timer!(read_time);
        let time = start_timer!(|| "Deserializing");
         result_buffer.extend(
            work_buffer
                .chunks(size)
                .map(|chunk| Self::deserialize_raw(chunk).unwrap()),
        );               
        dbg!(result_buffer.len());
        end_timer!(time);
        
        Ok(())
    }
}

pub trait RawField: SerializeRaw + DeserializeRaw + Field {}
pub trait RawPrimeField: RawField + PrimeField {}

pub trait RawAffine: SerializeRaw + DeserializeRaw + AffineRepr {}



macro_rules! impl_uint {
    ($type:ty) => {
        impl SerializeRaw for $type {
            const SIZE: Option<usize> = Some(core::mem::size_of::<$type>());
            #[inline]
            fn serialize_raw<W: Write>(
                &self,
                mut writer: W,
            ) -> Result<(), io::Error> {
                Ok(writer.write_all(&self.to_le_bytes())?)
            }
        }

        impl DeserializeRaw for $type {
            #[inline]
            fn deserialize_raw<R: Read>(
                mut reader: R,
            ) -> Result<Self, io::Error> {
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
    const SIZE: Option<usize> = Some(1);
    #[inline]
    fn serialize_raw<W: Write>(
        &self,
        mut writer: W,
    ) -> Result<(), io::Error> {
        writer.write(&[*self as u8])?;
        Ok(())
    }
}

impl DeserializeRaw for bool {
    #[inline]
    fn deserialize_raw<R: Read>(
        mut reader: R,
    ) -> Result<Self, io::Error> {
        let mut byte = [0u8; 1];
        reader.read_exact(&mut byte)?;
        Ok(byte[0] != 0)
    }
}

impl SerializeRaw for usize {
    const SIZE: Option<usize> = Some(core::mem::size_of::<u64>());
    #[inline]
    fn serialize_raw<W: Write>(
        &self,
        mut writer: W,
    ) -> Result<(), io::Error> {
        Ok(writer.write_all(&(*self as u64).to_le_bytes())?)
    }
}

impl DeserializeRaw for usize {
    #[inline]
    fn deserialize_raw<R: Read>(
        mut reader: R,
    ) -> Result<Self, io::Error> {
        let mut bytes = [0u8; core::mem::size_of::<u64>()];
        reader.read_exact(&mut bytes)?;
        Ok(<u64>::from_le_bytes(bytes) as usize)
    }
}

impl<T: SerializeRaw, const N: usize> SerializeRaw for [T; N] {
    const SIZE: Option<usize> = match T::SIZE {
        Some(size) => Some(size * N),
        None => None,
    };
     
    #[inline]
    fn serialize_raw<W: Write>(
        &self,
        mut writer: W,
    ) -> Result<(), io::Error> {
        for item in self.iter() {
            item.serialize_raw(&mut writer)?;
        }
        Ok(())
    }
}

impl<T: DeserializeRaw, const N: usize> DeserializeRaw for [T; N] {
    #[inline]
    fn deserialize_raw<R: Read>(
        mut reader: R,
    ) -> Result<Self, io::Error> {
        let mut array = [(); N].map(|_| MaybeUninit::uninit());
        for i in 0..N {
            let item = T::deserialize_raw(&mut reader)?;
            array[i] = MaybeUninit::new(item);
        }
        Ok(array.map(|item| unsafe { item.assume_init() }))
    }
}






// Helper function. Serializes any sequential data type to the format
//     n as u64 || data[0].serialize() || ... || data[n].serialize()
#[inline]
fn serialize_seq<T, B, W>(
    seq: impl ExactSizeIterator<Item = B>,
    mut writer: W,
) -> Result<(), io::Error>
where
    T: SerializeRaw,
    B: Borrow<T>,
    W: Write,
{
    let len = seq.len() as u64;
    len.serialize_raw(&mut writer)?;
    for item in seq {
        item.borrow().serialize_raw(&mut writer)?;
    }
    Ok(())
}

// Helper function. Describes the size of any data serialized using the above function
#[inline]
fn get_serialized_size_of_seq<T, B>(
    seq: impl ExactSizeIterator<Item = B>,
) -> usize
where
    T: SerializeRaw,
    B: Borrow<T>,
{
    8 + seq
        .map(|item| item.borrow().serialized_size())
        .sum::<usize>()
}

impl<T: SerializeRaw> SerializeRaw for Vec<T> {
    const SIZE: Option<usize> = None;
    #[inline]
    fn serialize_raw<W: Write>(
        &self,
        writer: W,
    ) -> Result<(), io::Error> {
        serialize_seq::<T, _, _>(self.iter(), writer)
    }

    #[inline]
    fn serialized_size(&self) -> usize {
        get_serialized_size_of_seq::<T, _>(self.iter())
    }
}

impl<'a, T: SerializeRaw> SerializeRaw for &'a [T] {
    const SIZE: Option<usize> = None;
    #[inline]
    fn serialize_raw<W: Write>(
        &self,
        mut writer: W,
    ) -> Result<(), io::Error> {
        (*self).serialize_raw(&mut writer)
    }

    #[inline]
    fn serialized_size(&self) -> usize {
        (*self).serialized_size()
    }
}

impl<T: SerializeRaw> SerializeRaw for [T] {
    const SIZE: Option<usize> = None;
    #[inline]
    fn serialize_raw<W: Write>(
        &self,
        writer: W,
    ) -> Result<(), io::Error> {
        serialize_seq::<T, _, _>(self.iter(), writer)
    }

    #[inline]
    fn serialized_size(&self) -> usize {
        get_serialized_size_of_seq::<T, _>(self.iter())
    }
}



// Implement Serialization for tuples
macro_rules! impl_tuple {
    ($( $ty: ident : $no: tt, )*) => {
        #[allow(unused)]
        impl<$($ty, )*> SerializeRaw for ($($ty,)*) where
            $($ty: SerializeRaw,)*
        {
            const SIZE: Option<usize> = {
                let mut sum = None;
                let sizes = [$($ty::SIZE,)*];
                let num_items = sizes.len();
                let mut i = 0;
                while i < num_items {
                    match sizes[i] {
                        Some(s) => {
                            if sum.is_none() {
                                sum = Some(s);
                            }
                        },
                        None => break,
                    }
                    i += 1;
                }
                sum
            };

            #[inline]
            fn serialize_raw<W: Write>(&self, mut writer: W) -> Result<(), io::Error> {
                $(self.$no.serialize_raw(&mut writer)?;)*
                Ok(())
            }

            #[inline]
            fn serialized_size(&self) -> usize {
                [$(
                    self.$no.serialized_size(),
                )*].iter().sum()
            }
        }

        impl<$($ty, )*> DeserializeRaw for ($($ty,)*) where
            $($ty: DeserializeRaw,)*
        {
            #[inline]
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
    const SIZE: Option<usize> = Some(N * 8);
    fn serialize_raw<W: Write>(
        &self,
        writer: W,
    ) -> Result<(), io::Error> {
        self.0.serialize_raw(writer)
    }
}


impl<const N: usize> DeserializeRaw for BigInt<N> {
    fn deserialize_raw<R: Read>(
        reader: R,
    ) -> Result<Self, io::Error> {
        <[u64; N]>::deserialize_raw(reader).map(BigInt)
    }
}

impl<P: FpConfig<N>, const N: usize> RawField for Fp<P, N> {}
impl<P: FpConfig<N>, const N: usize> RawPrimeField for Fp<P, N> {}

impl<P: FpConfig<N>, const N: usize> SerializeRaw for Fp<P, N> {
    const SIZE: Option<usize> = Some(N * 8);
    fn serialize_raw<W: Write>(
        &self,
        writer: W,
    ) -> Result<(), io::Error> {
        self.0.serialize_raw(writer)
    }
}

impl<P: FpConfig<N>, const N: usize> DeserializeRaw for Fp<P, N> {
    fn deserialize_raw<R: Read>(
        reader: R,
    ) -> Result<Self, io::Error> {
        BigInt::deserialize_raw(reader).map(|b| {
            Fp(b, core::marker::PhantomData)
        })
    }
}

impl<P: SWCurveConfig> SerializeRaw for SWAffine<P> 
where P::BaseField: SerializeRaw
{
    const SIZE: Option<usize> = match P::BaseField::SIZE {
        Some(size) => Some(2usize * size),
        None => None,
    };
    fn serialize_raw<W: Write>(
        &self,
        mut writer: W,
    ) -> Result<(), io::Error> {
        self.x.serialize_raw(&mut writer)?;
        self.y.serialize_raw(writer)
    }
}

impl<P: SWCurveConfig> DeserializeRaw for SWAffine<P> 
where P::BaseField: DeserializeRaw
{
    fn deserialize_raw<R: Read>(
        mut reader: R,
    ) -> Result<Self, io::Error> {
        let x = P::BaseField::deserialize_raw(&mut reader)?;
        let y = P::BaseField::deserialize_raw(reader)?;
        Ok(Self::new(x, y))
    }
}

impl<P: TECurveConfig> SerializeRaw for TEAffine<P> 
where P::BaseField: SerializeRaw
{
    const SIZE: Option<usize> = match P::BaseField::SIZE {
        Some(size) => Some(2usize * size),
        None => None,
    };
    fn serialize_raw<W: Write>(
        &self,
        mut writer: W,
    ) -> Result<(), io::Error> {
        self.x.serialize_raw(&mut writer)?;
        self.y.serialize_raw(writer)
    }
}

impl<P: TECurveConfig> DeserializeRaw for TEAffine<P> 
where P::BaseField: DeserializeRaw
{
    fn deserialize_raw<R: Read>(
        mut reader: R,
    ) -> Result<Self, io::Error> {
        let x = P::BaseField::deserialize_raw(&mut reader)?;
        let y = P::BaseField::deserialize_raw(reader)?;
        Ok(Self::new(x, y))
    }
}

impl<P: SWCurveConfig> RawAffine for SWAffine<P> 
where P::BaseField: SerializeRaw + DeserializeRaw
{}
impl<P: TECurveConfig> RawAffine for TEAffine<P> 
where P::BaseField: SerializeRaw + DeserializeRaw
{}

#[cfg(test)]
mod tests {
    use crate::streams::BUFFER_SIZE;

    use super::*;
    use ark_bls12_381::Fr;
    use ark_std::UniformRand;
    fn test_serialize<T: PartialEq + core::fmt::Debug + SerializeRaw + DeserializeRaw>(
        data: T,
    ) {
        let mut serialized = vec![0; data.serialized_size()];
        data.serialize_raw(&mut serialized[..]).unwrap();
        let de = T::deserialize_raw(&serialized[..]).unwrap();
        assert_eq!(data, de);
    }
    
    fn test_serialize_batch<T: Sync + Send + Clone + PartialEq + core::fmt::Debug + SerializeRaw + DeserializeRaw>(
        data: &[T],
    ) {
        let size = data[0].serialized_size();
        let mut serialized = vec![0u8; size * data.len()];
        let mut buffer = serialized.clone();
        T::serialize_raw_batch(data, &mut buffer, &mut serialized[..]).unwrap();
        let mut final_result = vec![];
        let mut result_buf = vec![];
        dbg!(serialized.len());
        while final_result.len() < data.len() {
            T::deserialize_raw_batch(&mut result_buf, &mut buffer, BUFFER_SIZE, &serialized[(final_result.len() * size)..]).unwrap();           
            buffer.clear();
            dbg!(final_result.len());
            dbg!(data.len());
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
            let data = (0..size).map(|_| [u64::rand(&mut rng); 10]).collect::<Vec<_>>();
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
            let data = (0..(BUFFER_SIZE * size)).map(|_| Fr::rand(&mut rng)).collect::<Vec<_>>();
            test_serialize_batch(&data);
        }
    }
}