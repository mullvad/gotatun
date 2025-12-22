// Copyright (c) 2025 Mullvad VPN AB. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use std::net::IpAddr;

use bitfield_struct::bitfield;
use either::Either;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::packet::{Ipv4, Ipv6};

/// A packet bitfield-struct containing the `version`-field that is shared between IPv4 and IPv6.
#[bitfield(u8)]
#[derive(FromBytes, IntoBytes, KnownLayout, Unaligned, Immutable, PartialEq, Eq)]
pub struct IpvxVersion {
    #[bits(4)]
    pub _unknown: u8,
    #[bits(4)]
    pub version: u8,
}

/// An IP packet, including headers, that may be either IPv4 or IPv6.
#[repr(C, packed)]
#[derive(FromBytes, IntoBytes, KnownLayout, Unaligned, Immutable)]
pub struct Ip {
    /// The IP version field. [Read more](IpvxVersion)
    pub header: IpvxVersion,

    /// The rest of the IP packet,
    /// i.e. everything in the header that comes after the first byte, and the payload.
    ///
    /// You probably don't want to access this directly.
    pub rest: [u8],
}

impl Ip {
    fn as_v4_or_v6(&self) -> Option<Either<&Ipv4, &Ipv6>> {
        let b = self.as_bytes();
        match self.header.version() {
            4 => Ipv4::<[u8]>::ref_from_bytes(b).ok().map(Either::Left),
            6 => Ipv6::<[u8]>::ref_from_bytes(b).ok().map(Either::Right),
            _ => None,
        }
    }
    /// Try to extract the source [`IpAddr`].
    ///
    /// Returns `None` if the version field is not `4` or `6`, or if the packet is too small.
    /// Other than that, no checks are done to ensure this is a valid ip packet.
    pub fn source(&self) -> Option<IpAddr> {
        Some(match self.as_v4_or_v6()? {
            Either::Left(ipv4) => ipv4.header.source().into(),
            Either::Right(ipv6) => ipv6.header.source().into(),
        })
    }

    /// Try to extract the destination [`IpAddr`].
    ///
    /// Returns `None` if the version field is not `4` or `6`, or if the packet is too small.
    /// Other than that, no checks are done to ensure this is a valid ip packet.
    pub fn destination(&self) -> Option<IpAddr> {
        Some(match self.as_v4_or_v6()? {
            Either::Left(ipv4) => ipv4.header.destination().into(),
            Either::Right(ipv6) => ipv6.header.destination().into(),
        })
    }
}
