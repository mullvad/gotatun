// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// This file incorporates work covered by the following copyright and
// permission notice:
//
//   Copyright (c) Mullvad VPN AB. All rights reserved.
//
// SPDX-License-Identifier: MPL-2.0

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, TryFromBytes};

use crate::packet::Packet;

use super::PoD;

/// A trait that enables byte-wise conversion from one packet type to another through zerocopy.
/// See [`crate::packet::Ipv4Decoder`] for an example.
///
/// # Validation
/// This trait asserts, at minimum, that `Src` can be soundly transmuted into `Dst`, but
/// does not necessarily assert that the value resulting from the conversion is sane.
pub trait Decoder<Src, Dst>
where
    Src: IntoBytes + Immutable + KnownLayout + ?Sized,
    Dst: TryFromBytes + Immutable + KnownLayout + ?Sized,
{
    /// Validate that the `Src` is a valid instance of `Dst`.
    ///
    /// The returned `usize` indicated the byte-wise length of `Dst`,
    /// since it may be smaller than `Src`.
    fn validate(&self, s: &Src) -> Result<usize, DecodeError>;

    /// Try to decode the `&Src` packet as `&Dst`.
    /// See also: [`Decoder::decode_mut`], [`Decoder::decode_owned`].
    fn decode_ref<'a>(&self, source: &'a Src) -> Result<&'a Dst, DecodeError> {
        let len = self.validate(source)?;
        let bytes = &source.as_bytes()[..len];
        Ok(Dst::try_ref_from_bytes(bytes)?)
    }

    /// Try to decode the `&mut Src` packet as `&mut Dst`.
    ///
    /// See also: [`Self::decode_ref`], [`Self::decode_owned`].
    fn decode_mut<'a>(&self, source: &'a mut Src) -> Result<&'a mut Dst, DecodeError>
    where
        Src: FromBytes,
        Dst: IntoBytes,
    {
        let len = self.validate(source)?;
        let bytes = &mut source.as_mut_bytes()[..len];
        Ok(Dst::try_mut_from_bytes(bytes)?)
    }

    /// Try to decode the `Packet<Src>` packet as `Packet<Dst>`.
    ///
    /// See also: [`Self::decode_ref`], [`Self::decode_mut`].
    fn decode_owned(&self, source: Packet<Src>) -> Result<Packet<Dst>, DecodeError>
    where
        Src: PoD,
        Dst: PoD,
    {
        let len = self.validate(&*source)?;
        let mut source = source.into_bytes();
        source.truncate(len);
        Ok(source.cast())
    }
}

/// An error returned by [`Decoder::decode_ref`] and friends.
#[derive(Debug, thiserror::Error)]
pub enum DecodeError {
    /// Invalid value.
    #[error("Invalid value for {0}")]
    InvalidValue(&'static str),
    // zerocopy errors
    /// Bad alignment.
    #[error("Bad alignment")]
    BadAlignment,
    /// Invalid source size.
    #[error("Invalid source size")]
    InvalidSourceSize,
    /// Invalid source data.
    #[error("Invalid source data")]
    InvalidSourceData,
}

impl<S, D: ?Sized + TryFromBytes> From<zerocopy::TryCastError<S, D>> for DecodeError {
    fn from(value: zerocopy::TryCastError<S, D>) -> Self {
        match value {
            zerocopy::TryCastError::Alignment(..) => DecodeError::BadAlignment,
            zerocopy::TryCastError::Size(..) => DecodeError::InvalidSourceSize,
            zerocopy::TryCastError::Validity(..) => DecodeError::InvalidSourceData,
        }
    }
}
