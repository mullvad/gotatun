// Copyright (c) 2025 Mullvad VPN AB. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use bitfield_struct::bitfield;
use std::{fmt::Debug, net::Ipv6Addr};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned, big_endian};

use super::{IpNextProtocol, util::size_must_be};

/// An IPv6 packet.
///
/// This is a dynamically sized zerocopy type, which means you can compose packet types like
/// `Ipv6<Udp<WgData>>` and cast them to/from byte slices using [`FromBytes`] and [`IntoBytes`].
/// [Read more](crate::packet)
#[repr(C)]
#[derive(Debug, FromBytes, IntoBytes, KnownLayout, Unaligned, Immutable)]
pub struct Ipv6<Payload: ?Sized = [u8]> {
    /// IPv6 header.
    pub header: Ipv6Header,
    /// IPv6 payload. The type of this is `[u8]` by default, but it may be any zerocopy type,
    /// e.g. a `Udp<WgData>`
    pub payload: Payload,
}

/// An IPv6 header.
#[repr(C, packed)]
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Unaligned, Immutable, PartialEq, Eq)]
pub struct Ipv6Header {
    /// IPv6 `flow_label`, `traffic_class` and `version` fields.
    pub version_traffic_flow: Ipv6VersionTrafficFlow,
    /// Length of the IPv6 payload.
    pub payload_length: big_endian::U16,
    /// Protocol of the IPv6 payload.
    pub next_header: IpNextProtocol,
    /// Maximum number of hops for the IPv6 packet.
    pub hop_limit: u8,
    /// IPv6 source address.
    pub source_address: big_endian::U128,
    /// IPv6 destination address.
    pub destination_address: big_endian::U128,
}

/// A bitfield struct containing the IPv6 fields `flow_label`, `traffic_class` and `version`.
#[bitfield(u32, repr = big_endian::U32, from = big_endian::U32::new, into = big_endian::U32::get)]
#[derive(FromBytes, IntoBytes, KnownLayout, Unaligned, Immutable, PartialEq, Eq)]
pub struct Ipv6VersionTrafficFlow {
    /// IPv6 flow label.
    #[bits(20)]
    pub flow_label: u32,
    /// IPv6 traffic class.
    #[bits(8)]
    pub traffic_class: u8,
    /// IPv6 version. This must be `6`.
    #[bits(4)]
    pub version: u8,
}

impl Ipv6Header {
    /// Length, in bytes, of an [`Ipv6Header`].
    #[allow(dead_code)]
    pub const LEN: usize = size_must_be::<Ipv6Header>(40);

    /// Get [`version`](Ipv6VersionTrafficFlow::version). This is expected to be `6`.
    pub const fn version(&self) -> u8 {
        self.version_traffic_flow.version()
    }

    /// Get [`traffic_class`](Ipv6VersionTrafficFlow::traffic_class).
    pub const fn traffic_class(&self) -> u8 {
        self.version_traffic_flow.traffic_class()
    }

    /// Get [`flow_label`](Ipv6VersionTrafficFlow::flow_label).
    pub const fn flow_label(&self) -> u32 {
        self.version_traffic_flow.flow_label()
    }

    /// Set [`version`](Ipv6VersionTrafficFlow::version).
    // If you're setting it to anything other than `6`, you're probably doing it wrong.
    pub const fn set_version(&mut self, version: u8) {
        self.version_traffic_flow.set_version(version);
    }

    /// Set [`traffic_class`](Ipv6VersionTrafficFlow::traffic_class).
    pub const fn set_traffic_class(&mut self, tc: u8) {
        self.version_traffic_flow.set_traffic_class(tc);
    }

    /// Set [`flow_label`](Ipv6VersionTrafficFlow::flow_label).
    pub const fn set_flow_label(&mut self, flow: u32) {
        self.version_traffic_flow.set_flow_label(flow);
    }

    /// Set [next header protocol](Ipv6Header::next_protocol).
    pub const fn next_protocol(&self) -> IpNextProtocol {
        self.next_header
    }

    /// Get source address.
    pub const fn source(&self) -> Ipv6Addr {
        let bits = self.source_address.get();
        Ipv6Addr::from_bits(bits)
    }

    /// Get destination address.
    pub const fn destination(&self) -> Ipv6Addr {
        let bits = self.destination_address.get();
        Ipv6Addr::from_bits(bits)
    }
}

impl Debug for Ipv6Header {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ipv6Header")
            .field("version", &self.version())
            .field("traffic_class", &self.traffic_class())
            .field("flow_label", &self.flow_label())
            .field("payload_length", &self.payload_length.get())
            .field("next_header", &self.next_header)
            .field("hop_limit", &self.hop_limit)
            .field("source_address", &self.source())
            .field("destination_address", &self.destination())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use zerocopy::FromBytes;

    use super::Ipv6;
    use crate::packet::{IpNextProtocol, Ipv6Header};
    use std::{net::Ipv6Addr, str::FromStr};

    const EXAMPLE_IPV6_ICMP: &[u8] = &[
        0x60, 0x8, 0xc7, 0xf3, 0x0, 0x40, 0x3a, 0x40, 0xfc, 0x0, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0x1,
        0x0, 0xd, 0x0, 0x0, 0x0, 0xc, 0xc2, 0xdd, 0x26, 0x6, 0x47, 0x0, 0x47, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x0, 0x11, 0x11, 0x80, 0x0, 0x2d, 0xc5, 0x0, 0x2f, 0x0, 0xb, 0x1c,
        0xa7, 0x87, 0x68, 0x0, 0x0, 0x0, 0x0, 0x35, 0x1b, 0x3, 0x0, 0x0, 0x0, 0x0, 0x0, 0x10, 0x11,
        0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
        0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
    ];

    #[test]
    fn ipv6_header_layout() {
        let packet = Ipv6::<[u8]>::ref_from_bytes(EXAMPLE_IPV6_ICMP).unwrap();
        let header = &packet.header;

        assert_eq!(header.version(), 6);
        assert_eq!(header.traffic_class(), 0);
        assert_eq!(header.flow_label(), 0x8c7f3);
        assert_eq!(header.payload_length, 64);
        assert_eq!(usize::from(header.payload_length), packet.payload.len());
        assert_eq!(header.next_protocol(), IpNextProtocol::Icmpv6);
        assert_eq!(header.hop_limit, 64);
        assert_eq!(
            header.source(),
            Ipv6Addr::from_str("fc00:bbbb:bbbb:bb01:d:0:c:c2dd").unwrap(),
        );
        assert_eq!(
            header.destination(),
            Ipv6Addr::from_str("2606:4700:4700::1111").unwrap(),
        );
        assert_eq!(
            Ipv6Header::LEN + packet.payload.len(),
            EXAMPLE_IPV6_ICMP.len(),
        );
    }
}
