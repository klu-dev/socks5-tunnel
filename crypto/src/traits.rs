// Copyright (c) The Libra Core Contributors
// SPDX-License-Identifier: Apache-2.0

//! This module provides a generic set of traits for dealing with cryptographic primitives.
//!
//! For examples on how to use these traits, see the implementations of the [`ed25519`] or
//! [`bls12381`] modules.

use anyhow::Result;
use std::convert::{From, TryFrom};
use serde::{de::DeserializeOwned, Serialize};
use std::{fmt::Debug, hash::Hash};
use thiserror::Error;

/// An error type for key and signature validation issues, see [`ValidKey`][ValidKey].
///
/// This enum reflects there are two interesting causes of validation
/// failure for the ingestion of key or signature material: deserialization errors
/// (often, due to mangled material or curve equation failure for ECC) and
/// validation errors (material recognizable but unacceptable for use,
/// e.g. unsafe).
#[derive(Clone, Debug, PartialEq, Eq, Error)]
#[error("{:?}", self)]
pub enum CryptoMaterialError {
    /// Key or signature material does not deserialize correctly.
    DeserializationError,
    /// Key or signature material deserializes, but is otherwise not valid.
    ValidationError,
    /// Key, threshold or signature material does not have the expected size.
    WrongLengthError,
    /// Part of the signature or key is not canonical resulting to malleability issues.
    CanonicalRepresentationError,
    /// A curve point (i.e., a public key) lies on a small group.
    SmallSubgroupError,
    /// A curve point (i.e., a public key) does not satisfy the curve equation.
    PointNotOnCurveError,
    /// BitVec errors in accountable multi-sig schemes.
    BitVecError(String),
}

/// The serialized length of the data that enables macro derived serialization and deserialization.
pub trait Length {
    /// The serialized length of the data
    fn length(&self) -> usize;
}

/// Key or more generally crypto material with a notion of byte validation.
///
/// A type family for material that knows how to serialize and
/// deserialize, as well as validate byte-encoded material. The
/// validation must be implemented as a [`TryFrom`][TryFrom] which
/// classifies its failures against the above
/// [`CryptoMaterialError`][CryptoMaterialError].
///
/// This provides an implementation for a validation that relies on a
/// round-trip to bytes and corresponding [`TryFrom`][TryFrom].
pub trait ValidKey:
    // The for<'a> exactly matches the assumption "deserializable from any lifetime".
    for<'a> TryFrom<&'a [u8], Error = CryptoMaterialError> + Serialize + DeserializeOwned
{
    /// Convert the valid key to bytes.
    fn to_bytes(&self) -> Vec<u8>;
}

/// An extension to to/from Strings for [`ValidKey`][ValidKey].
///
/// Relies on [`hex`][::hex] for string encoding / decoding.
/// No required fields, provides a default implementation.
pub trait ValidKeyStringExt: ValidKey {
    /// When trying to convert from bytes, we simply decode the string into
    /// bytes before checking if we can convert.
    fn from_encoded_string(encoded_str: &str) -> std::result::Result<Self, CryptoMaterialError> {
        let bytes_out = ::hex::decode(encoded_str);
        // We defer to `try_from` to make sure we only produce valid keys.
        bytes_out
            // We reinterpret a failure to serialize: key is mangled someway.
            .or(Err(CryptoMaterialError::DeserializationError))
            .and_then(|ref bytes| Self::try_from(bytes))
    }
    /// A function to encode into hex-string after serializing.
    fn to_encoded_string(&self) -> Result<String> {
        Ok(::hex::encode(&self.to_bytes()))
    }
}

// There's nothing required in this extension, so let's just derive it
// for anybody that has a ValidKey.
impl<T: ValidKey> ValidKeyStringExt for T {}

/// A type family for key material that should remain secret and has an
/// associated type of the [`PublicKey`][PublicKey] family.
pub trait PrivateKey: Sized {
    /// We require public / private types to be coupled, i.e. their
    /// associated type is each other.
    type PublicKeyMaterial: PublicKey<PrivateKeyMaterial=Self>;

    /// Returns the associated public key
    fn public_key(&self) -> Self::PublicKeyMaterial {
        self.into()
    }
}

/// A type for key material that can be publicly shared, and in asymmetric
/// fashion, can be obtained from a [`PrivateKey`][PrivateKey]
/// reference.
/// This convertibility requirement ensures the existence of a
/// deterministic, canonical public key construction from a private key.
pub trait PublicKey: Sized + Clone + Eq + Hash +
    // This unsightly turbofish type parameter is the precise constraint
    // needed to require that there exists an
    //
    // ```
    // impl From<&MyPrivateKeyMaterial> for MyPublicKeyMaterial
    // ```
    //
    // declaration, for any `MyPrivateKeyMaterial`, `MyPublicKeyMaterial`
    // on which we register (respectively) `PublicKey` and `PrivateKey`
    // implementations.
    for<'a> From<&'a <Self as PublicKey>::PrivateKeyMaterial> {
    /// We require public / private types to be coupled, i.e. their
    /// associated type is each other.
    type PrivateKeyMaterial: PrivateKey<PublicKeyMaterial = Self>;
}

