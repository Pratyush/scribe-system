// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Prelude. Also provides sample instantiations of merkle trees.

pub use crate::{
    append_only::MerkleTree,
    impl_to_traversal_path_biguint, impl_to_traversal_path_primitives,
    internal::{MerkleNode, MerklePath, MerkleProof},
    universal_merkle_tree::UniversalMerkleTree,
    AppendableMerkleTreeScheme, DigestAlgorithm, Element, ForgetableMerkleTreeScheme,
    ForgetableUniversalMerkleTreeScheme, Index, LookupResult, MerkleCommitment, MerkleTreeScheme,
    NodeValue, ToTraversalPath, UniversalMerkleTreeScheme,
};

use crate::errors::MerkleTreeError;
use ark_serialize::{
    CanonicalDeserialize, CanonicalSerialize, Compress, Read, SerializationError, Valid, Validate,
    Write,
};
use ark_std::{marker::PhantomData, vec::Vec};
use jf_rescue::{crhf::RescueCRHF, RescueParameter};

/// Wrapper for rescue hash function
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RescueHash<F: RescueParameter> {
    phantom_f: PhantomData<F>,
}

impl<I: Index, F: RescueParameter + From<I>> DigestAlgorithm<F, I, F> for RescueHash<F> {
    fn digest(data: &[F]) -> Result<F, MerkleTreeError> {
        Ok(RescueCRHF::<F>::sponge_no_padding(data, 1)?[0])
    }

    fn digest_leaf(pos: &I, elem: &F) -> Result<F, MerkleTreeError> {
        let data = [F::zero(), F::from(pos.clone()), *elem];
        Ok(RescueCRHF::<F>::sponge_no_padding(&data, 1)?[0])
    }
}

/// A standard merkle tree using RATE-3 rescue hash function
pub type RescueMerkleTree<F> = MerkleTree<F, RescueHash<F>, u64, 3, F>;

// /// A standard light merkle tree using RATE-3 rescue hash function
// pub type RescueLightWeightMerkleTree<F> = LightWeightMerkleTree<F, RescueHash<F>, u64, 3, F>;

/// Example instantiation of a SparseMerkleTree indexed by I
pub type RescueSparseMerkleTree<I, F> = UniversalMerkleTree<F, RescueHash<F>, I, 3, F>;

/// Update the array length here
#[derive(Default, Eq, PartialEq, Clone, Copy, Debug, Ord, PartialOrd, Hash)]
pub struct Sha3Node(pub(crate) [u8; 32]);

impl AsRef<[u8]> for Sha3Node {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl CanonicalSerialize for Sha3Node {
    fn serialize_with_mode<W: Write>(
        &self,
        mut writer: W,
        _compress: Compress,
    ) -> Result<(), SerializationError> {
        writer.write_all(&self.0)?;
        Ok(())
    }

    fn serialized_size(&self, _compress: Compress) -> usize {
        32
    }
}
impl CanonicalDeserialize for Sha3Node {
    fn deserialize_with_mode<R: Read>(
        mut reader: R,
        _compress: Compress,
        _validate: Validate,
    ) -> Result<Self, SerializationError> {
        let mut ret = [0u8; 32];
        reader.read_exact(&mut ret)?;
        Ok(Sha3Node(ret))
    }
}

impl Valid for Sha3Node {
    fn check(&self) -> Result<(), SerializationError> {
        Ok(())
    }
}
