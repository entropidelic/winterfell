// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use super::{ByteDigest, ElementHasher, Hasher};
use core::{convert::TryInto, fmt::Debug, marker::PhantomData};
use math::{FieldElement, StarkField};
use utils::ByteWriter;
//use blake2::{Blake2b};
//use blake2::blake2b::blake2b;
use blake2::blake2b::{Blake2b, blake2b};
// use blake2::as_bytes::AsBytes;


#[cfg(test)]
mod tests;


fn blake2b_hash(bytes: &[u8]) ->  [u8; 32] {
    return blake2b(32, &[], bytes).as_bytes().try_into().expect("slice with incorrect length")
}

// BLAKE2b 256-BIT OUTPUT
// ================================================================================================

/// Implementation of the [Hasher](super::Hasher) trait for BLAKE2b hash function with 256-bit
/// output.
#[derive(Debug, PartialEq, Eq)]
pub struct Blake2b_256<B: StarkField>(PhantomData<B>);

impl<B: StarkField> Hasher for Blake2b_256<B> {
    type Digest = ByteDigest<32>;

    fn hash(bytes: &[u8]) -> Self::Digest {
        ByteDigest(blake2b_hash(bytes))
    }

    fn merge(values: &[Self::Digest; 2]) -> Self::Digest {
        ByteDigest(blake2b_hash(ByteDigest::digests_as_bytes(values)).into())
    }

    fn merge_with_int(seed: Self::Digest, value: u64) -> Self::Digest {
        let mut data = [0; 40];
        data[..32].copy_from_slice(&seed.0);
        data[32..].copy_from_slice(&value.to_le_bytes());
        ByteDigest(blake2b_hash(&data))
    }
}

impl<B: StarkField> ElementHasher for Blake2b_256<B> {
    type BaseField = B;

    fn hash_elements<E: FieldElement<BaseField = Self::BaseField>>(elements: &[E]) -> Self::Digest {
        if B::IS_CANONICAL {
            // when element's internal and canonical representations are the same, we can hash
            // element bytes directly
            let bytes = E::elements_as_bytes(elements);
            ByteDigest(blake2b_hash(bytes))
        } else {
            // when elements' internal and canonical representations differ, we need to serialize
            // them before hashing
            let mut hasher = Blake2bHasher::new();
            hasher.write(elements);
            ByteDigest(hasher.finalize())
        }
    }
}

// BLAKE2b 192-BIT OUTPUT
// ================================================================================================

/// Implementation of the [Hasher](super::Hasher) trait for BLAKE2b hash function with 192-bit
/// output.
#[derive(Debug, PartialEq, Eq)]
pub struct Blake2b_192<B: StarkField>(PhantomData<B>);

impl<B: StarkField> Hasher for Blake2b_192<B> {
    type Digest = ByteDigest<24>;

    fn hash(bytes: &[u8]) -> Self::Digest {
        let result = blake2b_hash(bytes);
        ByteDigest(result[..24].try_into().unwrap())
    }

    fn merge(values: &[Self::Digest; 2]) -> Self::Digest {
        let result = blake2b_hash(ByteDigest::digests_as_bytes(values));
        ByteDigest(result[..24].try_into().unwrap())
    }

    fn merge_with_int(seed: Self::Digest, value: u64) -> Self::Digest {
        let mut data = [0; 32];
        data[..24].copy_from_slice(&seed.0);
        data[24..].copy_from_slice(&value.to_le_bytes());

        let result = blake2b_hash(&data);
        ByteDigest(result[..24].try_into().unwrap())
    }
}

impl<B: StarkField> ElementHasher for Blake2b_192<B> {
    type BaseField = B;

    fn hash_elements<E: FieldElement<BaseField = Self::BaseField>>(elements: &[E]) -> Self::Digest {
        if B::IS_CANONICAL {
            // when element's internal and canonical representations are the same, we can hash
            // element bytes directly
            let bytes = E::elements_as_bytes(elements);
            let result = blake2b_hash(bytes);
            ByteDigest(result[..24].try_into().unwrap())
        } else {
            // when elements' internal and canonical representations differ, we need to serialize
            // them before hashing
            let mut hasher = Blake2bHasher::new();
            hasher.write(elements);
            let result = hasher.finalize();
            ByteDigest(result[..24].try_into().unwrap())
        }
    }
}

// BLAKE HASHER
// ================================================================================================

/// Wrapper around BLAKE2b hasher to implement [ByteWriter] trait for it.
struct Blake2bHasher(Blake2b);

impl Blake2bHasher {
    pub fn new() -> Self {
        Self(Blake2b::new(32))
    }

    pub fn finalize(&self) -> [u8; 32] {
        let binding = self.0.clone().finalize();
        let bytes = binding.as_bytes();
        bytes.try_into().expect("yoa")
    }
}

impl ByteWriter for Blake2bHasher {
    fn write_u8(&mut self, value: u8) {
        self.0.update(&[value]);
    }

    fn write_u8_slice(&mut self, values: &[u8]) {
        self.0.update(values);
    }
}
