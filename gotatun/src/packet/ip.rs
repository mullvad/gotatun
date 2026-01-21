// Copyright (c) 2025 Mullvad VPN AB. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

use bitfield_struct::bitfield;
use either::Either;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned, big_endian};

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
/// [Read more](crate::packet)
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

/// IP socket address encoding used in the handshake response.
///
/// Layout:
///
/// ```text
///  remote_addr = {
///      u8  ip_version      // either 0x04 or 0x06
///      u8  reserved_zero   // must be 0
///      u16 port            // big-endian
///      u8  receiver_index[16] // either IPv4 address with leading 0 or IPv6 addr
///  }
/// ```
///
/// - For an IPv4 address, the first 12 bytes of `receiver_index` are zero and the last 4 bytes hold
///   the IPv4 address (embedded IPv4-in-IPv6 style).
/// - For an IPv6 address, all 16 bytes are the IPv6 address.
#[repr(C, packed)]
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Unaligned, Immutable, PartialEq, Eq)]
pub struct IpSocketAddr {
    pub ip_version: u8,
    pub reserved_zero: u8,
    pub port: big_endian::U16,
    pub ip_addr: [u8; 16],
}

impl From<SocketAddr> for IpSocketAddr {
    fn from(addr: SocketAddr) -> Self {
        match addr {
            SocketAddr::V4(v4) => IpSocketAddr::from(v4),
            SocketAddr::V6(v6) => IpSocketAddr::from(v6),
        }
    }
}

impl From<SocketAddrV4> for IpSocketAddr {
    fn from(addr: SocketAddrV4) -> Self {
        let ip = addr.ip().octets();
        let port = addr.port();

        let mut ip_addr = [0u8; 16];
        // IPv4 mapped into the last 4 bytes; first 12 zeroed
        ip_addr[12..16].copy_from_slice(&ip);

        IpSocketAddr {
            ip_version: 0x04,
            reserved_zero: 0,
            port: big_endian::U16::new(port),
            ip_addr,
        }
    }
}

impl From<SocketAddrV6> for IpSocketAddr {
    fn from(addr: SocketAddrV6) -> Self {
        let ip = addr.ip().octets();
        let port = addr.port();

        IpSocketAddr {
            ip_version: 0x06,
            reserved_zero: 0,
            port: big_endian::U16::new(port),
            ip_addr: ip,
        }
    }
}

/// Error type for converting `IpSocketAddr` back to `SocketAddr`.
#[derive(Debug, thiserror::Error)]
pub enum IpSocketAddrError {
    #[error("Invalid Version: {0}")]
    InvalidVersion(u8),
    #[error("Reserved Non Zero invalid: {0}")]
    ReservedNonZero(u8),
}

impl TryFrom<IpSocketAddr> for SocketAddr {
    type Error = IpSocketAddrError;

    fn try_from(value: IpSocketAddr) -> Result<Self, Self::Error> {
        if value.reserved_zero != 0 {
            return Err(IpSocketAddrError::ReservedNonZero(value.reserved_zero));
        }

        let port = value.port.get();

        match value.ip_version {
            0x04 => {
                // Expect IPv4 in the last 4 bytes; ignore leading 12 bytes.
                let mut ip_bytes = [0u8; 4];
                ip_bytes.copy_from_slice(&value.ip_addr[12..16]);

                let v4 = SocketAddrV4::new(Ipv4Addr::from(ip_bytes), port);
                Ok(SocketAddr::V4(v4))
            }
            0x06 => {
                let ip_bytes = value.ip_addr;
                let v6 = SocketAddrV6::new(Ipv6Addr::from(ip_bytes), port, 0, 0);
                Ok(SocketAddr::V6(v6))
            }
            other => Err(IpSocketAddrError::InvalidVersion(other)),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

    use rand::{RngCore, SeedableRng};
    use rand_xorshift::XorShiftRng;

    use super::*;
    use crate::packet::IpSocketAddr;

    // In principle, there is no point in testing the format of the message
    // explicitly. The encoding is declaratively defined in the struct.
    #[test]
    fn encode_and_then_decode_v4_sock_addr_success() -> Result<(), Box<dyn std::error::Error>> {
        let mut rng = XorShiftRng::seed_from_u64(47);
        let mut ipv4_bytes = [0u8; 4];
        let mut input = [0u8; 20];
        input[0] = 0x04;
        for _ in 0..256 {
            rng.fill_bytes(&mut ipv4_bytes);
            let expected_ip_addr = Ipv4Addr::from_octets(ipv4_bytes);
            let expected_port = rng.next_u32() as u16;
            let expected_sock_addr =
                SocketAddr::V4(SocketAddrV4::new(expected_ip_addr, expected_port));
            let ip_sock_addr: IpSocketAddr = expected_sock_addr.into();
            let actual_socket_addr: SocketAddr = ip_sock_addr.try_into()?;

            assert_eq!(expected_sock_addr, actual_socket_addr);
        }
        Ok(())
    }

    #[test]
    fn encode_and_then_decode_v6_sock_addr_success() -> Result<(), Box<dyn std::error::Error>> {
        let mut rng = XorShiftRng::seed_from_u64(47);
        let mut ipv6_bytes = [0u8; 16];
        let mut input = [0u8; 20];
        input[0] = 0x04;
        for _ in 0..256 {
            rng.fill_bytes(&mut ipv6_bytes);
            let expected_ip_addr = Ipv6Addr::from_octets(ipv6_bytes);
            let expected_port = rng.next_u32() as u16;
            let expected_sock_addr =
                SocketAddr::V6(SocketAddrV6::new(expected_ip_addr, expected_port, 0, 0));
            let ip_sock_addr: IpSocketAddr = expected_sock_addr.into();
            let actual_socket_addr: SocketAddr = ip_sock_addr.try_into()?;

            assert_eq!(expected_sock_addr, actual_socket_addr);
        }
        Ok(())
    }
}
