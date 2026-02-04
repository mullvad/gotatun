// Copyright (c) 2025 Mullvad VPN AB. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use std::fmt;

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned, big_endian};

use super::util::size_must_be;

/// A UDP packet.
///
/// This is a dynamically sized zerocopy type, which means you can compose packet types like
/// `Ipv6<Udp<WgData>>` and cast them to/from byte slices using [`FromBytes`] and [`IntoBytes`].
/// [Read more](crate::packet)
#[repr(C)]
#[derive(Debug, FromBytes, IntoBytes, KnownLayout, Unaligned, Immutable)]
pub struct Udp<Payload: ?Sized = [u8]> {
    /// UDP header.
    pub header: UdpHeader,
    /// UDP payload. The type of this is `[u8]` by default, but it may be any zerocopy type,
    /// e.g. a `WgData`.
    pub payload: Payload,
}

/// A UDP header.
#[repr(C, packed)]
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Unaligned, Immutable)]
pub struct UdpHeader {
    /// UDP source port.
    pub source_port: big_endian::U16,
    /// UDP destination port.
    pub destination_port: big_endian::U16,
    /// Length of the UDP packet (including header) in bytes.
    pub length: big_endian::U16,
    /// Checksum of the UDP packet
    pub checksum: big_endian::U16,
}

impl UdpHeader {
    /// Length of a [`UdpHeader`], in bytes.
    #[allow(dead_code)]
    pub const LEN: usize = size_must_be::<UdpHeader>(8);
}

impl fmt::Debug for UdpHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UdpHeader")
            .field("source_port", &self.source_port.get())
            .field("destination_port", &self.destination_port.get())
            .field("length", &self.length.get())
            .field("checksum", &self.checksum.get())
            .finish()
    }
}
