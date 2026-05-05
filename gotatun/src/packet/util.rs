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

use std::mem::offset_of;

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned, big_endian};

use crate::packet::{IpNextProtocol, TcpHeader, Udp, UdpHeader};

/// Check that the size of type `T` is `size`. If not, panic.
///
/// Returns `size` for convenience.
pub(crate) const fn size_must_be<T>(size: usize) -> usize {
    if size_of::<T>() == size {
        size
    } else {
        panic!("Size of T is wrong!")
    }
}

/// Pseudo-header used for computing UDP and TCP checksums.
#[repr(C)]
#[derive(Debug, FromBytes, IntoBytes, KnownLayout, Unaligned, Immutable)]
pub struct PseudoHeaderV4 {
    /// Source IP address
    pub source: big_endian::U32,
    /// Destination IP address
    pub destination: big_endian::U32,
    _zero: u8,
    /// Transport protocol
    pub protocol: IpNextProtocol,
    /// Transport header and payload size
    pub length: big_endian::U16,
}

impl PseudoHeaderV4 {
    /// Create a new [`PseudoHeaderV4`] from a [`Udp`] datagram.
    pub fn from_udp(source: big_endian::U32, destination: big_endian::U32, udp: &Udp) -> Self {
        Self {
            source,
            destination,
            _zero: 0,
            protocol: IpNextProtocol::Udp,
            length: udp.as_bytes().len().try_into().unwrap(),
        }
    }

    /// Create a new [`PseudoHeaderV4`] from payload.
    ///
    /// # Panics
    ///
    /// This panics if `payload` is bigger than `u16::MAX`.
    pub fn from_bytes(
        source: big_endian::U32,
        destination: big_endian::U32,
        protocol: IpNextProtocol,
        payload: &[u8],
    ) -> Self {
        Self {
            source,
            destination,
            _zero: 0,
            protocol,
            length: payload.len().try_into().unwrap(),
        }
    }
}

/// Pseudo-header used for computing UDP and TCP checksums.
#[repr(C)]
#[derive(Debug, FromBytes, IntoBytes, KnownLayout, Unaligned, Immutable)]
pub struct PseudoHeaderV6 {
    /// Source IP address
    pub source: big_endian::U128,
    /// Destination IP address
    pub destination: big_endian::U128,
    _zero: u8,
    /// Transport protocol
    pub protocol: IpNextProtocol,
    /// Transport header and payload size
    pub length: big_endian::U16,
}

impl PseudoHeaderV6 {
    /// Create a new [`PseudoHeaderV6`] from a [`Udp`] datagram.
    pub fn from_udp(source: big_endian::U128, destination: big_endian::U128, udp: &Udp) -> Self {
        Self {
            source,
            destination,
            _zero: 0,
            protocol: IpNextProtocol::Udp,
            length: udp.as_bytes().len().try_into().unwrap(),
        }
    }

    /// Create a new [`PseudoHeaderV6`] from payload.
    ///
    /// # Panics
    ///
    /// This panics if `payload` is bigger than `u16::MAX`.
    pub fn from_bytes(
        source: big_endian::U128,
        destination: big_endian::U128,
        protocol: IpNextProtocol,
        payload: &[u8],
    ) -> Self {
        Self {
            source,
            destination,
            _zero: 0,
            protocol,
            length: payload.len().try_into().unwrap(),
        }
    }
}

/// Compute an "Internet checksum"
pub fn checksum(payload: &[&[u8]]) -> u16 {
    let mut sum = 0;
    for p in payload {
        sum += checksum_payload(p);
    }
    finalize_csum(sum)
}

/// Compute an "Internet checksum" for IPv4.
/// This skips the checksum field, so it works for even if non-zero.
pub fn checksum_ipv4_with_skip(payload: &[u8]) -> u16 {
    const SKIP_WORD: usize =
        offset_of!(crate::packet::Ipv4Header, header_checksum) / size_of::<u16>();
    let sum = checksum_payload_with_skip(payload, SKIP_WORD);
    finalize_csum(sum)
}

/// Compute an "Internet checksum" with an additional header and a final
/// inversion of all bits if the checksum is all zeros. This is used for UDP checksums
/// because 0 means "no checksum" in UDP + IPv4.
pub fn checksum_udp<H: IntoBytes + Immutable>(header: H, payload: &[u8]) -> u16 {
    let csum = checksum(&[header.as_bytes(), payload]);
    if csum == 0 {
        return !0;
    }
    csum
}

/// Compute an "Internet checksum" with an additional header and a final
/// inversion of all bits if the checksum is all zeros. This is used for UDP checksums
/// because 0 means "no checksum" in UDP + IPv4.
///
/// This also skips any existing checksum field.
pub fn checksum_udp_with_skip<H: IntoBytes + Immutable>(header: H, payload: &[u8]) -> u16 {
    const SKIP_INDEX: usize = offset_of!(UdpHeader, checksum) / size_of::<u16>();
    let mut sum = checksum_payload(header.as_bytes());
    sum += checksum_payload_with_skip(payload, SKIP_INDEX);
    let csum = finalize_csum(sum);
    if csum == 0 {
        return !0;
    }
    csum
}

/// Compute an "Internet checksum" with an additional header and a final
/// inversion of all bits if the checksum is all zeros. This is used for UDP checksums
/// because 0 means "no checksum" in UDP + IPv4.
///
/// This also skips any existing checksum field.
pub fn checksum_tcp_with_skip<H: IntoBytes + Immutable>(header: H, payload: &[u8]) -> u16 {
    const SKIP_INDEX: usize = offset_of!(TcpHeader, checksum) / size_of::<u16>();
    let mut sum = checksum_payload(header.as_bytes());
    sum += checksum_payload_with_skip(payload, SKIP_INDEX);
    finalize_csum(sum)
}

fn checksum_payload(bytes: &[u8]) -> u32 {
    let (words, rest) = <[big_endian::U16]>::ref_from_prefix(bytes).unwrap();

    let mut sum: u32 = words.iter().map(|w| u32::from(w.get())).sum();
    if let [b] = rest {
        // Zero-pad if odd number of bytes
        sum += u32::from(u16::from_be_bytes([*b, 0]));
    }

    sum
}

fn checksum_payload_with_skip(bytes: &[u8], skip_word_index: usize) -> u32 {
    let (words, rest) = <[big_endian::U16]>::ref_from_prefix(bytes).unwrap();

    let mut sum: u32 = words
        .iter()
        .enumerate()
        .filter(|(i, _)| *i != skip_word_index)
        .map(|(_, w)| u32::from(w.get()))
        .sum();
    if let [b] = rest {
        // Zero-pad if odd number of bytes
        sum += u32::from(u16::from_be_bytes([*b, 0]));
    }

    sum
}

fn finalize_csum(mut sum: u32) -> u16 {
    // Wrap overflowing bits and add back
    while sum >> 16 != 0 {
        sum = (sum >> 16) + (sum & 0xffff);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::Ipv4Header;
    use std::net::Ipv4Addr;

    #[test]
    fn test_ipv4_header_checksum() {
        let src_ip = Ipv4Addr::new(10, 0, 0, 1);
        let dst_ip = Ipv4Addr::new(192, 168, 1, 1);
        let mut header = Ipv4Header::new_for_length(src_ip, dst_ip, IpNextProtocol::Udp, 23);
        header.header_checksum = checksum(&[header.as_bytes()]).into();
        assert_eq!(header.header_checksum.get(), 0xAF18);
        assert_eq!(checksum(&[header.as_bytes()]), 0);
    }
}
