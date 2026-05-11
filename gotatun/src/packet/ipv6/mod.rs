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

use bitfield_struct::bitfield;
use duplicate::duplicate_item;
use eyre::eyre;
use std::{fmt::Debug, net::Ipv6Addr};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, TryFromBytes, Unaligned, big_endian};

use crate::packet::{Tcp, TcpDecoder};

use super::{
    DecodeError, Decoder, IpNextProtocol, PseudoHeaderV6, Udp, UdpDecoder, util::size_must_be,
};

/// An IPv6 packet.
///
/// This is a dynamically sized [`zerocopy`] type which allows for cheap conversions.
/// The generic payload allows you to compose packet types like `Ipv6<Udp<WgData>>`.
///
/// Use [`Ipv6Decoder`] and [`Ipv6PayloadDecoder`] for parsing into these packet types from
/// byte slices and such. You can also use [`FromBytes`] and [`IntoBytes`] if you want minimal
/// validation. [Read more](crate::packet)
#[repr(C)]
#[derive(Debug, FromBytes, IntoBytes, KnownLayout, Unaligned, Immutable)]
pub struct Ipv6<Payload: ?Sized = [u8]> {
    /// IPv6 header.
    pub header: Ipv6Header,
    /// IPv6 payload. The type of this is `[u8]` by default, but it may be any zerocopy type,
    /// e.g. a `Udp<WgData>`.
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
    /// Length of an [`Ipv6Header`], in bytes.
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

    /// Get [`Ipv6Header::payload_length`] plus [`Ipv6Header::LEN`].
    /// This is a [`usize`] because the length might exceed [`u16::MAX`].
    pub const fn total_length(&self) -> usize {
        self.payload_length.get() as usize + Ipv6Header::LEN
    }
}

impl<P: ?Sized> Ipv6<P>
where
    P: IntoBytes + Immutable,
{
    /// Update [`Ipv6Header::payload_length`] to match real payload size.
    pub fn try_update_ip_len(&mut self) -> eyre::Result<()> {
        self.header.payload_length = self
            .payload
            .as_bytes()
            .len()
            .try_into()
            .map_err(|_| eyre!("IPv6 payload was larger than {}", u16::MAX))?;
        Ok(())
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

/// An [`Ipv6`] [`Decoder`].
pub struct Ipv6Decoder {
    /// Fail if version field is not `6`.
    pub version: bool,

    // TODO: length and truncate should be mutually exclusive
    /// Fail if IPv6 header length is too big.
    pub length: bool,
    /// Truncate the buffer if it's longer than header length.
    pub truncate: bool,
}

impl Ipv6Decoder {
    /// Validate as *much* as possible about the decoded packet.
    pub const CHECK_ALL: Self = Self {
        version: true,
        length: true,
        truncate: true,
    };

    /// Validate as *little* as possible about the decoded packet.
    pub const UNCHECKED: Self = Self {
        version: false,
        length: false,
        truncate: false,
    };
}

/// Decode a byte slice into an [`Ipv6`] packet.
impl Decoder<[u8], Ipv6<[u8]>> for Ipv6Decoder {
    fn validate(&self, bytes: &[u8]) -> Result<usize, DecodeError> {
        let ipv6: &Ipv6 = Ipv6::try_ref_from_bytes(bytes)?;

        if self.version && ipv6.header.version() != 6 {
            return Err(DecodeError::InvalidValue("version"));
        }

        let total_len = ipv6.header.total_length();
        if (self.length || self.truncate) && total_len > bytes.len() {
            return Err(DecodeError::InvalidValue("total length"));
        }

        let len = if self.truncate {
            total_len
        } else {
            bytes.len()
        };

        Ok(len)
    }
}

#[duplicate_item(
    Proto ProtoDecoder proto_str from_proto_fn checksum_fn;
    [Tcp] [TcpDecoder] ["TCP"] [from_tcp] [checksum_tcp_with_skip];
    [Udp] [UdpDecoder] ["UDP"] [from_udp] [checksum_udp_with_skip];
)]
/// Decode the [`Ipv6::payload`].
impl Decoder<Ipv6<[u8]>, Ipv6<Proto>> for Ipv6PayloadDecoder<ProtoDecoder> {
    fn validate(&self, ipv6: &Ipv6<[u8]>) -> Result<usize, DecodeError> {
        if self.ip_next_protocol && ipv6.header.next_protocol() != IpNextProtocol::Proto {
            return Err(DecodeError::InvalidValue("protocol"));
        }

        if self.inner.checksum {
            let proto = Proto::<[u8]>::try_ref_from_bytes(&ipv6.payload)?;

            let header = PseudoHeaderV6::from_proto_fn(
                ipv6.header.source_address,
                ipv6.header.destination_address,
                proto,
            );
            let expected_csum = crate::packet::util::checksum_fn(header, proto);
            if expected_csum != proto.header.checksum.get() {
                return Err(DecodeError::InvalidValue(concat!(proto_str, " checksum")));
            }
        }

        let len = self.inner.validate(&ipv6.payload)?;
        Ok(len + Ipv6Header::LEN)
    }
}

/// A [`Decoder`] for [`Ipv6::payload`] into a transport protocol like [`Udp`].
pub struct Ipv6PayloadDecoder<Inner> {
    /// Assert that [`IpNextProtocol`] matches the payload.
    pub ip_next_protocol: bool,
    /// Decoder for the inner transport protocol
    pub inner: Inner,
}

#[duplicate_item(
    Inner;
    [UdpDecoder];
    [TcpDecoder];
)]
impl Ipv6PayloadDecoder<Inner> {
    /// Validate as *much* as possible about the decoded payload.
    pub const CHECK_ALL: Self = Self {
        ip_next_protocol: true,
        inner: Inner::CHECK_ALL,
    };

    /// Validate as *little* as possible about the decoded payload.
    pub const UNCHECKED: Self = Self {
        ip_next_protocol: false,
        inner: Inner::UNCHECKED,
    };
}

#[cfg(test)]
mod tests {
    use zerocopy::{FromBytes, IntoBytes};

    use super::{Ipv6, Ipv6Decoder};
    use crate::packet::{Decoder, IpNextProtocol, Ipv6Header};
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
    fn ipv6_decode_and_validate() {
        let ipv6: &Ipv6 = Ipv6Decoder::CHECK_ALL
            .decode_ref(EXAMPLE_IPV6_ICMP)
            .expect("IPv6 packet is valid");
        assert_eq!(ipv6.as_bytes(), EXAMPLE_IPV6_ICMP);
    }

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

        Ipv6Decoder::CHECK_ALL
            .decode_ref(EXAMPLE_IPV6_ICMP)
            .expect("Packet is valid");
    }
}
