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
use eyre::eyre;
use std::{fmt::Debug, net::Ipv4Addr};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, TryFromBytes, Unaligned, big_endian};

mod protocol;
pub use protocol::*;

use crate::packet::{DecodeAs, DecodeError, PseudoHeaderV4, Udp, UdpDecoder};

use super::util::size_must_be;

/// An IPv4 packet.
///
/// This is a dynamically sized zerocopy type, which means you can compose packet types like
/// `Ipv4<Udp<WgData>>` and cast them to/from byte slices using [`FromBytes`] and [`IntoBytes`].
/// [Read more](crate::packet)
#[repr(C)]
#[derive(Debug, FromBytes, IntoBytes, KnownLayout, Unaligned, Immutable, PartialEq, Eq)]
pub struct Ipv4<Payload: ?Sized = [u8]> {
    /// IPv4 header.
    pub header: Ipv4Header,
    /// IPv4 payload.
    pub payload: Payload,
}

pub struct Ipv4Decoder {
    /// Fail if IP version field is not `4`.
    pub version: bool,
    /// Fail if IHL is invalid (<5 or too big).
    pub ihl: bool,
    /// Fail if IPv4 header checksum is incorrect.
    pub checksum: bool,
    /// Fail if IPv4 header length is invalid or too big.
    pub length: bool,
    /// Truncate the buffer if it's longer than header lengths.
    pub truncate: bool,
}

impl Ipv4Decoder {
    /// Validate as *much* as possible about the decoded packet.
    pub const CHECK_ALL: Self = Self {
        version: true,
        ihl: true,
        checksum: true,
        length: true,
        truncate: true,
    };

    /// Validate as *little* as possible about the decoded packet.
    pub const UNCHECKED: Self = Self {
        version: false,
        ihl: false,
        checksum: false,
        length: false,
        truncate: false,
    };
}

impl DecodeAs<Ipv4<Ipv4Options<[u8]>>> for [u8] {
    type Decoder = Ipv4Decoder;

    fn validate(&self, d: Self::Decoder) -> Result<usize, DecodeError> {
        let ipv4: &Ipv4 = Ipv4::try_ref_from_bytes(self)?;

        if d.version && ipv4.header.version() != 4 {
            return Err(DecodeError::InvalidValue("version"));
        }

        if d.checksum {
            let expected_csum = ipv4.header.compute_checksum();
            if ipv4.header.header_checksum.get() != expected_csum {
                return Err(DecodeError::InvalidValue("checksum"));
            }
        }

        let total_len = usize::from(ipv4.header.total_len.get());
        if d.length || d.truncate {
            if total_len > self.len() || total_len < Ipv4Header::LEN {
                return Err(DecodeError::InvalidValue("total_len"));
            }
        }

        if d.ihl {
            let ihl = usize::from(ipv4.header.ihl());
            if ihl < 5 || ihl * size_of::<u32>() > self.len() {
                return Err(DecodeError::InvalidValue("IHL"));
            }
        }

        let len = if d.truncate { total_len } else { self.len() };

        Ok(len)
    }
}

impl DecodeAs<Ipv4<[u8]>> for Ipv4<Ipv4Options<[u8]>> {
    type Decoder = ();
    fn validate(&self, _: Self::Decoder) -> Result<usize, DecodeError> {
        if self.header.ihl() == 5 {
            Ok(self.as_bytes().len())
        } else {
            Err(DecodeError::InvalidValue("IHL"))
        }
    }
}

impl DecodeAs<Ipv4<[u8]>> for [u8] {
    type Decoder = Ipv4Decoder;
    fn validate(&self, d: Self::Decoder) -> Result<usize, DecodeError> {
        let ipv4: &Ipv4 = Ipv4::try_ref_from_bytes(self)?;

        if d.version && ipv4.header.version() != 4 {
            return Err(DecodeError::InvalidValue("version"));
        }

        if d.checksum {
            let expected_csum = ipv4.header.compute_checksum();
            if ipv4.header.header_checksum.get() != expected_csum {
                return Err(DecodeError::InvalidValue("checksum"));
            }
        }

        let total_len = usize::from(ipv4.header.total_len.get());
        if d.length || d.truncate {
            if total_len > self.len() || total_len < Ipv4Header::LEN {
                return Err(DecodeError::InvalidValue("total_len"));
            }
        }

        if d.ihl {
            let ihl = usize::from(ipv4.header.ihl());
            if ihl != 5 {
                return Err(DecodeError::InvalidValue("IHL"));
            }
        }

        let len = if d.truncate { total_len } else { self.len() };

        Ok(len)
    }
}

fn validate_ipv4(d: &Ipv4Decoder, ipv4: &Ipv4) -> Result<usize, DecodeError> {
    let buf_len = ipv4.as_bytes().len();

    if d.version && ipv4.header.version() != 4 {
        return Err(DecodeError::InvalidValue("version"));
    }

    if d.checksum {
        let expected_csum = ipv4.header.compute_checksum();
        if ipv4.header.header_checksum.get() != expected_csum {
            return Err(DecodeError::InvalidValue("checksum"));
        }
    }

    let total_len = usize::from(ipv4.header.total_len.get());
    if (d.length || d.truncate) && (total_len > buf_len || total_len < Ipv4Header::LEN) {
        return Err(DecodeError::InvalidValue("total_len"));
    }

    Ok(if d.truncate { total_len } else { buf_len })
}

/// A [`Decoder`] for [`Ipv4::payload`] into a transport protocol like [`Udp`].
pub struct Ipv4PayloadDecoder<Inner> {
    /// Assert that [`IpNextProtocol`] matches the payload.
    pub ip_next_protocol: bool,
    /// Assert that the IP packet is not a fragment.
    pub dont_fragment: bool,
    /// Decoder for the inner transport protocol
    pub inner: Inner,
}

impl Ipv4PayloadDecoder<UdpDecoder> {
    /// Validate as *much* as possible about the decoded UDP payload.
    pub const CHECK_ALL: Self = Self {
        ip_next_protocol: true,
        dont_fragment: true,
        inner: UdpDecoder::CHECK_ALL,
    };

    /// Validate as *little* as possible about the decoded UDP payload.
    pub const UNCHECKED: Self = Self {
        ip_next_protocol: false,
        dont_fragment: false,
        inner: UdpDecoder::UNCHECKED,
    };
}

impl DecodeAs<Ipv4<Udp>> for Ipv4<[u8]> {
    type Decoder = Ipv4PayloadDecoder<UdpDecoder>;

    fn validate(&self, d: Self::Decoder) -> Result<usize, DecodeError> {
        if d.ip_next_protocol && self.header.next_protocol() != IpNextProtocol::Udp {
            return Err(DecodeError::InvalidValue("protocol"));
        }

        if d.dont_fragment && (self.header.fragment_offset() != 0 || self.header.more_fragments()) {
            return Err(DecodeError::InvalidValue(
                "fragment_offset / more_fragments",
            ));
        }

        if d.inner.checksum {
            let udp = Udp::<[u8]>::try_ref_from_bytes(&self.payload)?;
            if udp.header.checksum.get() != 0 {
                let header = PseudoHeaderV4::from_bytes(
                    self.header.source_address,
                    self.header.destination_address,
                    IpNextProtocol::Udp,
                    self.payload.as_bytes(),
                );
                let expected_csum =
                    crate::packet::util::checksum_udp_with_skip(header, self.payload.as_bytes());
                if expected_csum != udp.header.checksum.get() {
                    return Err(DecodeError::InvalidValue("UDP checksum"));
                }
            }
        }

        let len = DecodeAs::<Udp>::validate(&self.payload, d.inner)?;
        Ok(len + Ipv4Header::LEN)
    }
}

/// IPv4 options and payload.
#[repr(C)]
#[derive(Debug, FromBytes, IntoBytes, KnownLayout, Unaligned, Immutable)]
pub struct Ipv4Options<T: ?Sized = [u8]> {
    _pd: std::marker::PhantomData<T>,
    options: [u8],
}

/// A bitfield struct containing the IPv4 fields `version` and `ihl`.
#[bitfield(u8)]
#[derive(FromBytes, IntoBytes, KnownLayout, Unaligned, Immutable, PartialEq, Eq)]
pub struct Ipv4VersionIhl {
    /// IPv4 `ihl` field (Internet Header Length).
    ///
    /// This determines the length of the IPv4 header as the number of 32-bit (or 4-byte)
    /// blocks, including optional fields. The minimum value is `5`, which implies no
    /// optional fields.
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
    /// Length of an [`Ipv4Header`], in bytes.
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

    /// Compute expected header checksum.
    pub fn compute_checksum(&self) -> u16 {
        crate::packet::util::checksum_ipv4_with_skip(self.as_bytes())
    }
}

impl Ipv4 {
    /// Maximum possible length of an IPv4 packet.
    pub const MAX_LEN: usize = 65535;
}

impl<P: ?Sized> Ipv4<P>
where
    Self: IntoBytes + Immutable,
{
    /// Update [`Ipv4Header::total_len`] according to how big `self` is.
    ///
    /// # Errors
    /// Returns an error if `self` is larger than [`Ipv4::MAX_LEN`].
    pub fn try_update_ip_len(&mut self) -> eyre::Result<()> {
        self.header.total_len = self
            .as_bytes()
            .len()
            .try_into()
            .map_err(|_| eyre!("IPv4 packet was larger than {}", u16::MAX))?;
        Ok(())
    }
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
    use zerocopy::{FromBytes, IntoBytes, big_endian};

    use super::{Ipv4, Ipv4Decoder, Ipv4Header, Ipv4PayloadDecoder};
    use crate::packet::{DecodeError, IpNextProtocol, Udp, UdpDecoder, UdpHeader, decode_ref};
    use std::net::Ipv4Addr;

    const EXAMPLE_IPV4_ICMP: &[u8] = &[
        0x45, 0x83, 0x0, 0x54, 0xa3, 0x13, 0x40, 0x0, 0x40, 0x1, 0xc6, 0x26, 0xa, 0x8c, 0xc2, 0xdd,
        0x1, 0x2, 0x3, 0x4, 0x8, 0x0, 0x51, 0x13, 0x0, 0x2b, 0x0, 0x1, 0xb1, 0x5c, 0x87, 0x68, 0x0,
        0x0, 0x0, 0x0, 0xa8, 0x28, 0x7, 0x0, 0x0, 0x0, 0x0, 0x0, 0x10, 0x11, 0x12, 0x13, 0x14,
        0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23,
        0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32,
        0x33, 0x34, 0x35, 0x36, 0x37,
    ];

    const EXAMPLE_IPV4_UDP: Ipv4<Udp<[u8; 12]>> = Ipv4 {
        header: Ipv4Header {
            header_checksum: big_endian::U16::new(0x78c4),
            ..Ipv4Header::new_for_length(
                Ipv4Addr::new(1, 2, 3, 4),
                Ipv4Addr::new(255, 254, 253, 252),
                IpNextProtocol::Udp,
                (UdpHeader::LEN + 12) as u16,
            )
        },
        payload: Udp {
            header: UdpHeader::new(12345, 65421, (UdpHeader::LEN + 12) as u16, 0x6b0f),
            payload: *b"Hello there!",
        },
    };

    const EXAMPLE_IPV4_UDP_RAW: &[u8] = &[
        0x45, 0x0, 0x0, 0x28, 0x0, 0x0, 0x0, 0x0, 0x40, 0x11, 0x78, 0xc4, 0x1, 0x2, 0x3, 0x4, 0xff,
        0xfe, 0xfd, 0xfc, 0x30, 0x39, 0xff, 0x8d, 0x0, 0x14, 0x6b, 0x0f, 0x48, 0x65, 0x6c, 0x6c,
        0x6f, 0x20, 0x74, 0x68, 0x65, 0x72, 0x65, 0x21,
    ];

    /// Test that [`decode_ref`] can decode a valid IPv4/UDP packet.
    #[test]
    fn ipv4_decode_and_validate() {
        let ipv4: &Ipv4 =
            decode_ref(EXAMPLE_IPV4_UDP_RAW, Ipv4Decoder::CHECK_ALL).expect("IPv4 packet is valid");
        let ipv4_udp: &Ipv4<Udp> = decode_ref(
            ipv4,
            Ipv4PayloadDecoder {
                ip_next_protocol: true,
                dont_fragment: true,
                inner: UdpDecoder::CHECK_ALL,
            },
        )
        .expect("IPv4/UDP packet is valid");

        assert_eq!(ipv4_udp.as_bytes(), EXAMPLE_IPV4_UDP_RAW);
    }

    /// Test that [`decode_ref`] errors on a bad IPv4 checksum.
    #[test]
    fn ipv4_decode_invalid_checksum() {
        let mut ipv4 = EXAMPLE_IPV4_UDP;
        ipv4.header.header_checksum.set(1234);

        let _ipv4_with_bad_checksum: &Ipv4 =
            decode_ref(ipv4.as_bytes(), Ipv4Decoder::UNCHECKED).expect("Validation is disabled");

        let Err(DecodeError::InvalidValue("checksum")) =
            decode_ref::<_, Ipv4>(ipv4.as_bytes(), Ipv4Decoder::CHECK_ALL)
        else {
            panic!("Must fail with checksum error");
        };
    }

    /// Test that the [`Ipv4`] type has the expected bytewise layout.
    #[test]
    fn ipv4_layout() {
        assert_eq!(EXAMPLE_IPV4_UDP.as_bytes(), EXAMPLE_IPV4_UDP_RAW);
    }

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
