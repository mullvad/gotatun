// Copyright (c) 2025 Mullvad VPN AB. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use bitfield_struct::bitfield;
use std::{fmt::Debug, net::Ipv4Addr};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned, big_endian};

mod protocol;
pub use protocol::*;

use super::util::size_must_be;

/// An Ipv4 packet.
///
/// This is a dynamically sized zerocopy type, which means you can compose packet types like
/// `Ipv4<Udp<WgData>>` and cast them to/from byte slices using [`FromBytes`] and [`IntoBytes`].
#[repr(C)]
#[derive(Debug, FromBytes, IntoBytes, KnownLayout, Unaligned, Immutable)]
pub struct Ipv4<Payload: ?Sized = [u8]> {
    /// IPv4 header.
    pub header: Ipv4Header,
    /// IPv4 payload.
    pub payload: Payload,
}

/// A bitfield struct containing the IPv4 fields `version` and `ihl`.
#[bitfield(u8)]
#[derive(FromBytes, IntoBytes, KnownLayout, Unaligned, Immutable, PartialEq, Eq)]
pub struct Ipv4VersionIhl {
    /// IPv4 `ihl` field (Internet Header Length).
    ///
    /// This determines the length in `u32`s of the IPv4 header, including optional fields.
    /// The minimum value is `5`, which implies no optional fields.
    #[bits(4)]
    pub ihl: u8,

    /// IPv4 `version` field. This must be `4`.
    #[bits(4)]
    pub version: u8,
}

/// A bitfield struct containing the IPv4 fields `dscp` and `ecn`.
#[bitfield(u8)]
#[derive(FromBytes, IntoBytes, KnownLayout, Unaligned, Immutable, PartialEq, Eq)]
pub struct Ipv4DscpEcn {
    #[bits(2)]
    pub ecn: u8,
    #[bits(6)]
    pub dscp: u8,
}

/// A bitfield struct containing the IPv4 bitflags and the `fragment_offset` field.
#[bitfield(u16, order = Msb, repr = big_endian::U16, from = big_endian::U16::new, into = big_endian::U16::get)]
#[derive(FromBytes, IntoBytes, KnownLayout, Unaligned, Immutable, PartialEq, Eq)]
pub struct Ipv4FlagsFragmentOffset {
    _reserved: bool,
    /// IPv4 `dont_fragment` flag.
    pub dont_fragment: bool,
    /// IPv4 `more_fragments` flag.
    pub more_fragments: bool,
    /// IPv4 `fragment_offset` field.
    #[bits(13)]
    pub fragment_offset: u16,
}

/// An IPv4 header.
#[repr(C, packed)]
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Unaligned, Immutable, PartialEq, Eq)]
pub struct Ipv4Header {
    /// IPv4 `version`, and `ihl` fields.
    pub version_and_ihl: Ipv4VersionIhl,
    /// IPv4 `dscp`, and `ecn` fields.
    pub dscp_and_ecn: Ipv4DscpEcn,
    /// Length of the IPv4 packet, including headers.
    pub total_len: big_endian::U16,
    /// IPv4 `identification`. This is used for fragmentation.
    pub identification: big_endian::U16,
    /// IPv4 bitflags, and `fragment_offset` fields.
    pub flags_and_fragment_offset: Ipv4FlagsFragmentOffset,
    /// Maximum number of hops for the IPv4 packet.
    pub time_to_live: u8,
    /// Protocol of the IPv4 payload.
    pub protocol: IpNextProtocol,
    /// Checksum of the IPv4 header.
    pub header_checksum: big_endian::U16,
    /// IPv4 source address. Use [`Ipv4Header::source`].
    pub source_address: big_endian::U32,
    /// IPv4 destination address. Use [`Ipv4Header::destination`].
    pub destination_address: big_endian::U32,
}

impl Ipv4Header {
    /// Construct an IPv4 header with the reasonable defaults.
    ///
    /// `payload` field is used to set the `total_len` field.
    #[allow(dead_code)]
    pub const fn new(
        source: Ipv4Addr,
        destination: Ipv4Addr,
        protocol: IpNextProtocol,
        payload: &[u8],
    ) -> Self {
        Self::new_for_length(source, destination, protocol, payload.len() as u16)
    }

    /// Construct an IPv4 header with the reasonable defaults.
    ///
    /// `payload_len` is used to set the `total_len` field.
    /// The checksum is initialized to `0`.
    pub const fn new_for_length(
        source: Ipv4Addr,
        destination: Ipv4Addr,
        protocol: IpNextProtocol,
        payload_len: u16,
    ) -> Self {
        let header_len = size_of::<Ipv4Header>() as u16;
        let total_len = header_len + payload_len;

        Self {
            protocol,

            version_and_ihl: Ipv4VersionIhl::new().with_version(4).with_ihl(5),
            dscp_and_ecn: Ipv4DscpEcn::new(),
            total_len: big_endian::U16::new(total_len),
            identification: big_endian::U16::ZERO,
            flags_and_fragment_offset: Ipv4FlagsFragmentOffset::new(),
            time_to_live: 64, // default TTL in linux
            source_address: big_endian::U32::from_bytes(source.octets()),
            destination_address: big_endian::U32::from_bytes(destination.octets()),

            // TODO:
            header_checksum: big_endian::U16::ZERO,
        }
    }
}

impl Ipv4Header {
    /// Length, in bytes, of an [`Ipv4Header`].
    pub const LEN: usize = size_must_be::<Ipv4Header>(20);

    /// Get IP version. Must be `4` for a valid IPv4 header.
    pub const fn version(&self) -> u8 {
        self.version_and_ihl.version()
    }

    /// Get [`ihl`](Ipv4VersionIhl::ihl)
    pub const fn ihl(&self) -> u8 {
        self.version_and_ihl.ihl()
    }

    /// Get [`source_address`](Ipv4Header::source_address).
    pub const fn source(&self) -> Ipv4Addr {
        let bits = self.source_address.get();
        Ipv4Addr::from_bits(bits)
    }

    /// Get [`destination_address`](Ipv4Header::destination_address).
    pub const fn destination(&self) -> Ipv4Addr {
        let bits = self.destination_address.get();
        Ipv4Addr::from_bits(bits)
    }

    /// Get [`protocol`](Ipv4Header::protocol).
    pub const fn next_protocol(&self) -> IpNextProtocol {
        self.protocol
    }

    /// Get [`dscp`](Ipv4DscpEcn::dscp).
    pub const fn dscp(&self) -> u8 {
        self.dscp_and_ecn.dscp()
    }

    /// Get [`ecn`](Ipv4DscpEcn::ecn).
    pub const fn ecn(&self) -> u8 {
        self.dscp_and_ecn.ecn()
    }

    /// Get [`dont_fragment`](Ipv4FlagsFragmentOffset::dont_fragment).
    pub const fn dont_fragment(&self) -> bool {
        self.flags_and_fragment_offset.dont_fragment()
    }

    /// Get [`more_fragments`](Ipv4FlagsFragmentOffset::more_fragments).
    pub const fn more_fragments(&self) -> bool {
        self.flags_and_fragment_offset.more_fragments()
    }

    /// Get [`fragment_offset`](Ipv4FlagsFragmentOffset::fragment_offset).
    ///
    /// This is the offset of IP fragment payload relative to the start of payload of the original
    /// packet. Note that the value returned is in units of 8 bytes.
    pub const fn fragment_offset(&self) -> u16 {
        self.flags_and_fragment_offset.fragment_offset()
    }
}

impl Ipv4 {
    /// Maximum possible length of an IPv4 packet.
    pub const MAX_LEN: usize = 65535;
}

impl Debug for Ipv4Header {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ipv4Header")
            .field("version", &self.version())
            .field("ihl", &self.ihl())
            .field("dscp", &self.dscp())
            .field("ecn", &self.ecn())
            .field("total_len", &self.total_len.get())
            .field("identification", &self.identification.get())
            .field("dont_fragment", &self.dont_fragment())
            .field("more_fragments", &self.more_fragments())
            .field("fragment_offset", &self.fragment_offset())
            .field("time_to_live", &self.time_to_live)
            .field("protocol", &self.protocol)
            .field("header_checksum", &self.header_checksum.get())
            .field("source_address", &self.source())
            .field("destination_address", &self.destination())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use zerocopy::FromBytes;

    use super::{Ipv4, Ipv4Header};
    use crate::packet::IpNextProtocol;
    use std::net::Ipv4Addr;

    const EXAMPLE_IPV4_ICMP: &[u8] = &[
        0x45, 0x83, 0x0, 0x54, 0xa3, 0x13, 0x40, 0x0, 0x40, 0x1, 0xc6, 0x26, 0xa, 0x8c, 0xc2, 0xdd,
        0x1, 0x2, 0x3, 0x4, 0x8, 0x0, 0x51, 0x13, 0x0, 0x2b, 0x0, 0x1, 0xb1, 0x5c, 0x87, 0x68, 0x0,
        0x0, 0x0, 0x0, 0xa8, 0x28, 0x7, 0x0, 0x0, 0x0, 0x0, 0x0, 0x10, 0x11, 0x12, 0x13, 0x14,
        0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23,
        0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32,
        0x33, 0x34, 0x35, 0x36, 0x37,
    ];

    #[test]
    fn ipv4_header_layout() {
        let packet = Ipv4::<[u8]>::ref_from_bytes(EXAMPLE_IPV4_ICMP).unwrap();
        let header = &packet.header;

        assert_eq!(header.version(), 4);
        assert_eq!(header.ihl(), 5);
        assert_eq!(header.dscp(), 32);
        assert_eq!(header.ecn(), 0x3);
        assert_eq!(header.total_len, 84);
        assert_eq!(header.identification, 41747);
        assert!(header.dont_fragment());
        assert!(!header.more_fragments());
        assert_eq!(header.fragment_offset(), 0);
        assert_eq!(header.time_to_live, 64);
        assert_eq!(header.protocol, IpNextProtocol::Icmp);
        assert_eq!(header.header_checksum, 0xc626);
        assert_eq!(header.source(), Ipv4Addr::new(10, 140, 194, 221));
        assert_eq!(header.destination(), Ipv4Addr::new(1, 2, 3, 4));

        assert_eq!(
            packet.payload.len() + Ipv4Header::LEN,
            usize::from(header.total_len)
        );
    }
}
