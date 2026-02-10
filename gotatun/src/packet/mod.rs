// Copyright (c) 2025 Mullvad VPN AB. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Types to create, parse, and move network packets around in a zero-copy manner.
//!
//! See [`Packet`](crate::packet::Packet) for an implementation of a [`bytes`]-backed owned packet buffer.
//!
//! Any of the <https://docs.rs/zerocopy>-enabled definitions such as [`Ipv4`](crate::packet::Ipv4) or [`Udp`](crate::packet::Udp) can be used to cheaply
//! construct or parse packets:
//! ```
//! let example_ipv4_icmp: &mut [u8] = &mut [
//!     0x45, 0x83, 0x0, 0x54, 0xa3, 0x13, 0x40, 0x0, 0x40, 0x1, 0xc6, 0x26, 0xa, 0x8c, 0xc2, 0xdd,
//!     0x1, 0x2, 0x3, 0x4, 0x8, 0x0, 0x51, 0x13, 0x0, 0x2b, 0x0, 0x1, 0xb1, 0x5c, 0x87, 0x68, 0x0,
//!     0x0, 0x0, 0x0, 0xa8, 0x28, 0x7, 0x0, 0x0, 0x0, 0x0, 0x0, 0x10, 0x11, 0x12, 0x13, 0x14,
//!     0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23,
//!     0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32,
//!     0x33, 0x34, 0x35, 0x36, 0x37,
//! ];
//!
//! use gotatun::packet::{Ipv4, Ipv4Header, IpNextProtocol};
//! use zerocopy::FromBytes;
//! use std::net::Ipv4Addr;
//!
//! // Cast the `&[u8]` to an &Ipv4.
//! // Note that this doesn't validate anything about the packet,
//! // except that it's at least Ipv4Header::LEN bytes long.
//! let packet = Ipv4::<[u8]>::mut_from_bytes(example_ipv4_icmp)
//!     .expect("Packet must be large enough to be IPv4");
//! let header: &mut Ipv4Header = &mut packet.header;
//! let payload: &mut [u8] = &mut packet.payload;
//!
//! // Read stuff from the IPv4 header
//! assert_eq!(header.version(), 4);
//! assert_eq!(header.source(), Ipv4Addr::new(10, 140, 194, 221));
//! assert_eq!(header.destination(), Ipv4Addr::new(1, 2, 3, 4));
//! assert_eq!(header.header_checksum, 0xc626);
//! assert_eq!(header.protocol, IpNextProtocol::Icmp);
//!
//! // Write stuff to the header. Note that this invalidates the checksum.
//! header.time_to_live = 123;
//!
//! // Write stuff to the payload. Note that this clobbers the ICMP packet stored here.
//! payload[..12].copy_from_slice(b"Hello there!");
//! assert_eq!(&example_ipv4_icmp[20..][..12], b"Hello there!");
//! ```

use std::{
    fmt::{self, Debug},
    marker::PhantomData,
    ops::{Deref, DerefMut},
};

use bytes::{Buf, BytesMut};
use duplicate::duplicate_item;
use either::Either;
use eyre::{Context, bail, eyre};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

mod ip;
mod ipv4;
mod ipv6;
mod pool;
mod udp;
mod util;
mod wg;

pub use ip::*;
pub use ipv4::*;
pub use ipv6::*;
pub use pool::*;
pub use udp::*;
pub use wg::*;

/// An owned packet of some type.
///
/// The generic type `Kind` represents the type of packet.
/// For example, a `Packet<[u8]>` is an untyped packet containing arbitrary bytes.
/// It can be safely decoded into a `Packet<Ipv4>` using [`Packet::try_into_ip`],
/// and further decoded into a `Packet<Ipv4<Udp>>` using [`Packet::try_into_udp`].
///
/// [`Packet`] uses [`BytesMut`] as the backing buffer.
///
/// ```
/// use gotatun::packet::*;
/// use std::net::Ipv4Addr;
/// use zerocopy::IntoBytes;
///
/// let ip_header = Ipv4Header::new(
///     Ipv4Addr::new(10, 0, 0, 1),
///     Ipv4Addr::new(1, 2, 3, 4),
///     IpNextProtocol::Icmp,
///     &[],
/// );
///
/// let ip_header_bytes = ip_header.as_bytes();
///
/// let raw_packet: Packet<[u8]> = Packet::copy_from(ip_header_bytes);
/// let ipv4_packet: Packet<Ipv4> = raw_packet.try_into_ipvx().unwrap().unwrap_left();
/// assert_eq!(&ip_header, &ipv4_packet.header);
/// ```
pub struct Packet<Kind: ?Sized = [u8]> {
    inner: PacketInner,

    /// Marker type defining what type `Bytes` is.
    ///
    /// INVARIANT:
    /// `buf` must have been ensured to actually contain a packet of this type.
    _kind: PhantomData<Kind>,
}

struct PacketInner {
    buf: BytesMut,

    // If the [BytesMut] was allocated by a [PacketBufPool], this will return the buffer to be re-used later.
    _return_to_pool: Option<ReturnToPool>,
}

/// A marker trait that indicates that a [Packet] contains a valid payload of a specific type.
///
/// For example, [`CheckedPayload`] is implemented for [`Ipv4<[u8]>`], and a [`Packet<Ipv4<[u8]>>>`]
/// can only be constructed through [`Packet::<[u8]>::try_into_ipvx`], which checks that the IPv4
/// header is valid.
pub trait CheckedPayload: FromBytes + IntoBytes + KnownLayout + Immutable + Unaligned {}

impl CheckedPayload for [u8] {}
impl CheckedPayload for Ip {}
impl<P: CheckedPayload + ?Sized> CheckedPayload for Ipv6<P> {}
impl<P: CheckedPayload + ?Sized> CheckedPayload for Ipv4<P> {}
impl<P: CheckedPayload + ?Sized> CheckedPayload for Udp<P> {}
impl CheckedPayload for WgHandshakeInit {}
impl CheckedPayload for WgHandshakeResp {}
impl CheckedPayload for WgCookieReply {}
impl CheckedPayload for WgData {}

impl<T: CheckedPayload + ?Sized> Packet<T> {
    /// Cast `T` to `Y` without checking anything.
    ///
    /// Only invoke this after checking that the backing buffer contain a bitwise valid `Y` type.
    /// Incorrect usage of this function will cause [`Packet::deref`] to panic.
    fn cast<Y: CheckedPayload + ?Sized>(self) -> Packet<Y> {
        Packet {
            inner: self.inner,
            _kind: PhantomData::<Y>,
        }
    }

    /// Discard the type of this packet and treat it as a pile of bytes.
    pub fn into_bytes(self) -> Packet<[u8]> {
        self.cast()
    }

    fn buf(&self) -> &[u8] {
        &self.inner.buf
    }

    /// Create a `Packet<T>` from a `&T`.
    pub fn copy_from(payload: &T) -> Self {
        Self {
            inner: PacketInner {
                buf: BytesMut::from(payload.as_bytes()),
                _return_to_pool: None,
            },
            _kind: PhantomData::<T>,
        }
    }

    /// Create a `Packet<Y>` from a `&Y` by copying its bytes into the backing buffer of this
    /// `Packet<T>`.
    ///
    /// If the `Y` won't fit into the backing buffer, this call will allocate, and effectively
    /// devolves into [`Packet::copy_from`].
    pub fn overwrite_with<Y: CheckedPayload>(mut self, payload: &Y) -> Packet<Y> {
        self.inner.buf.clear();
        self.inner.buf.extend_from_slice(payload.as_bytes());
        self.cast()
    }
}

// Trivial `From`-conversions between packet types
#[duplicate_item(
    FromType ToType;
    [Ipv4<Udp>]             [Ipv4];
    [Ipv6<Udp>]             [Ipv6];

    [Ipv4<Udp>]             [Ip];
    [Ipv6<Udp>]             [Ip];
    [Ipv4]                  [Ip];
    [Ipv6]                  [Ip];

    [Ipv4<Udp>]             [[u8]];
    [Ipv6<Udp>]             [[u8]];
    [Ipv4]                  [[u8]];
    [Ipv6]                  [[u8]];
    [Ip]                    [[u8]];
    [WgData]                [[u8]];
    [WgHandshakeInit]       [[u8]];
    [WgHandshakeResp]       [[u8]];
    [WgCookieReply]         [[u8]];
)]
impl From<Packet<FromType>> for Packet<ToType> {
    fn from(value: Packet<FromType>) -> Packet<ToType> {
        value.cast()
    }
}

impl Default for Packet<[u8]> {
    fn default() -> Self {
        Self {
            inner: PacketInner {
                buf: BytesMut::default(),
                _return_to_pool: None,
            },
            _kind: PhantomData,
        }
    }
}

impl Packet<[u8]> {
    /// Create a new packet from a pool, with automatic return-to-pool on drop.
    ///
    /// This is used internally by [`PacketBufPool`] to create packets that are
    /// automatically returned to the pool when dropped.
    pub fn new_from_pool(return_to_pool: ReturnToPool, bytes: BytesMut) -> Self {
        Self {
            inner: PacketInner {
                buf: bytes,
                _return_to_pool: Some(return_to_pool),
            },
            _kind: PhantomData::<[u8]>,
        }
    }

    /// Create a `Packet::<u8>` from a [`BytesMut`].
    pub fn from_bytes(bytes: BytesMut) -> Self {
        Self {
            inner: PacketInner {
                buf: bytes,
                _return_to_pool: None,
            },
            _kind: PhantomData::<[u8]>,
        }
    }

    /// See [`BytesMut::truncate`].
    pub fn truncate(&mut self, new_len: usize) {
        self.inner.buf.truncate(new_len);
    }

    /// Get direct mutable access to the backing buffer.
    pub fn buf_mut(&mut self) -> &mut BytesMut {
        &mut self.inner.buf
    }

    /// Try to cast this untyped packet into an [`Ip`].
    ///
    /// This is a stepping stone to casting the packet into an [`Ipv4`] or an [`Ipv6`].
    /// See also [`Packet::try_into_ipvx`].
    ///
    /// # Errors
    ///
    /// Returns [`Err`] if this packet is smaller than [`Ipv4Header::LEN`] bytes.
    pub fn try_into_ip(self) -> eyre::Result<Packet<Ip>> {
        let buf_len = self.buf().len();

        // IPv6 packets are larger, but their length after we know the packet IP version.
        // This is the smallest any packet can be.
        if buf_len < Ipv4Header::LEN {
            bail!("Packet too small ({buf_len} < {})", Ipv4Header::LEN);
        }

        // we have asserted that the packet is long enough to _maybe_ be an IP packet.
        Ok(self.cast::<Ip>())
    }

    /// Try to cast this untyped packet into either an [`Ipv4`] or [`Ipv6`] packet.
    ///
    /// The buffer will be truncated to [`Ipv4Header::total_len`] or [`Ipv6Header::total_length`].
    ///
    /// # Errors
    ///
    /// Returns [`Err`] if any of the following checks fail:
    /// - The IP version field is `4` or `6`
    /// - The packet is smaller than the minimum header length.
    /// - The IPv4 packet is smaller than [`Ipv4Header::total_len`].
    /// - The IPv6 payload is smaller than [`Ipv6Header::payload_length`].
    pub fn try_into_ipvx(self) -> eyre::Result<Either<Packet<Ipv4>, Packet<Ipv6>>> {
        self.try_into_ip()?.try_into_ipvx()
    }
}

impl Packet<Ip> {
    /// Try to cast this [`Ip`] packet into either an [`Ipv4`] or [`Ipv6`] packet.
    ///
    /// The buffer will be truncated to [`Ipv4Header::total_len`] or [`Ipv6Header::total_length`].
    ///
    /// # Errors
    ///
    /// Returns [`Err`] if any of the following checks fail:
    /// - The IP version field is `4` or `6`
    /// - The IPv4 packet is smaller than [`Ipv4Header::total_len`].
    /// - The IPv6 payload is smaller than [`Ipv6Header::payload_length`].
    pub fn try_into_ipvx(mut self) -> eyre::Result<Either<Packet<Ipv4>, Packet<Ipv6>>> {
        match self.header.version() {
            4 => {
                let buf_len = self.buf().len();

                let ipv4 = Ipv4::<[u8]>::ref_from_bytes(self.buf())
                    .map_err(|e| eyre!("Bad IPv4 packet: {e:?}"))?;

                let ip_len = usize::from(ipv4.header.total_len.get());
                if ip_len > buf_len {
                    bail!("IPv4 `total_len` exceeded actual packet length: {ip_len} > {buf_len}");
                }
                if ip_len < Ipv4Header::LEN {
                    bail!(
                        "IPv4 `total_len` less than packet header len: {ip_len} < {}",
                        Ipv4Header::LEN
                    );
                }

                self.inner.buf.truncate(ip_len);

                // TODO: validate checksum

                // we have asserted that the packet is a valid IPv4 packet.
                // update `_kind` to reflect this.
                Ok(Either::Left(self.cast::<Ipv4>()))
            }
            6 => {
                let ipv6 = Ipv6::<[u8]>::ref_from_bytes(self.buf())
                    .map_err(|e| eyre!("Bad IPv6 packet: {e:?}"))?;

                let payload_len = usize::from(ipv6.header.payload_length.get());
                if payload_len > ipv6.payload.len() {
                    bail!(
                        "IPv6 `payload_len` exceeded actual payload length: {payload_len} > {}",
                        ipv6.payload.len()
                    );
                }

                self.inner.buf.truncate(payload_len + Ipv6Header::LEN);

                // TODO: validate checksum

                // we have asserted that the packet is a valid IPv6 packet.
                // update `_kind` to reflect this.
                Ok(Either::Right(self.cast::<Ipv6>()))
            }
            v => bail!("Bad IP version: {v}"),
        }
    }
}

impl Packet<Ipv4> {
    /// Try to cast this [`Ipv4`] packet into an [`Udp`] packet.
    ///
    /// Returns `Packet<Ipv4<Udp>>` if the packet is a valid,
    /// non-fragmented IPv4 UDP packet with no options (IHL == `5`).
    ///
    /// # Errors
    /// Returns an error if
    /// - the packet is a fragment
    /// - the IHL is not `5`
    /// - UDP validation fails
    pub fn try_into_udp(self) -> eyre::Result<Packet<Ipv4<Udp>>> {
        let ip = self.deref();

        // We validate the IHL here, instead of in the `try_into_ipvx` method,
        // because there we can still parse the part of the Ipv4 header that is always present
        // and ignore the options. To parse the UDP packet, we must know that the IHL is 5,
        // otherwise it will not start at the right offset.
        match ip.header.ihl() {
            5 => {}
            6.. => {
                return Err(eyre!("IP header: {:?}", ip.header))
                    .wrap_err(eyre!("IPv4 packets with options are not supported"));
            }
            ihl @ ..5 => {
                return Err(eyre!("IP header: {:?}", ip.header))
                    .wrap_err(eyre!("Bad IHL value: {ihl}"));
            }
        }

        if ip.header.fragment_offset() != 0 || ip.header.more_fragments() {
            eyre::bail!("IPv4 packet is a fragment: {:?}", ip.header);
        }

        validate_udp(ip.header.next_protocol(), &ip.payload)
            .wrap_err_with(|| eyre!("IP header: {:?}", ip.header))?;

        // we have asserted that the packet is a valid IPv4 UDP packet.
        // update `_kind` to reflect this.
        Ok(self.cast::<Ipv4<Udp>>())
    }
}

impl Packet<Ipv6> {
    /// Try to cast this [`Ipv6`] packet into an [`Udp`] packet.
    ///
    /// Returns `Packet<Ipv6<Udp>>` if the packet is a valid IPv6 UDP packet.
    ///
    /// # Errors
    /// Returns an error if UDP validation fails
    pub fn try_into_udp(self) -> eyre::Result<Packet<Ipv6<Udp>>> {
        let ip = self.deref();

        validate_udp(ip.header.next_protocol(), &ip.payload)
            .wrap_err_with(|| eyre!("IP header: {:?}", ip.header))?;

        // we have asserted that the packet is a valid IPv6 UDP packet.
        // update `_kind` to reflect this.
        Ok(self.cast::<Ipv6<Udp>>())
    }
}

impl<T: CheckedPayload + ?Sized> Packet<Ipv4<T>> {
    /// Strip the IPv4 header and return the payload.
    pub fn into_payload(mut self) -> Packet<T> {
        debug_assert_eq!(
            self.header.ihl() as usize * 4,
            Ipv4Header::LEN,
            "IPv4 header length must be 20 bytes (IHL = 5)"
        );
        self.inner.buf.advance(Ipv4Header::LEN);
        self.cast::<T>()
    }
}
impl<T: CheckedPayload + ?Sized> Packet<Ipv6<T>> {
    /// Strip the IPv6 header and return the payload.
    pub fn into_payload(mut self) -> Packet<T> {
        self.inner.buf.advance(Ipv6Header::LEN);
        self.cast::<T>()
    }
}
impl<T: CheckedPayload + ?Sized> Packet<Udp<T>> {
    /// Strip the UDP header and return the payload.
    pub fn into_payload(mut self) -> Packet<T> {
        self.inner.buf.advance(UdpHeader::LEN);
        self.cast::<T>()
    }
}

fn validate_udp(next_protocol: IpNextProtocol, payload: &[u8]) -> eyre::Result<()> {
    let IpNextProtocol::Udp = next_protocol else {
        bail!("Expected UDP, but packet was {next_protocol:?}");
    };

    let ip_payload_len = payload.len();
    let udp = Udp::<[u8]>::ref_from_bytes(payload).map_err(|e| eyre!("Bad UDP packet: {e:?}"))?;

    let udp_len = usize::from(udp.header.length.get());
    if udp_len != ip_payload_len {
        return Err(eyre!("UDP header: {:?}", udp.header)).wrap_err_with(|| {
            eyre!(
                "UDP header length did not match IP payload length: {} != {}",
                udp_len,
                ip_payload_len,
            )
        });
    }

    // TODO: validate checksum?

    Ok(())
}

impl<Kind> Deref for Packet<Kind>
where
    Kind: CheckedPayload + ?Sized,
{
    type Target = Kind;

    fn deref(&self) -> &Self::Target {
        Self::Target::ref_from_bytes(&self.inner.buf)
            .expect("We have previously checked that the payload is valid")
    }
}

impl<Kind> DerefMut for Packet<Kind>
where
    Kind: CheckedPayload + ?Sized,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        Self::Target::mut_from_bytes(&mut self.inner.buf)
            .expect("We have previously checked that the payload is valid")
    }
}

// This clone implementation is only for tests, as the clone will cause an allocation and will not return the buffer to the pool.
#[cfg(test)]
impl<Kind: ?Sized> Clone for Packet<Kind> {
    fn clone(&self) -> Self {
        Self {
            inner: PacketInner {
                buf: self.inner.buf.clone(),
                _return_to_pool: None, // Clone does not return to pool
            },
            _kind: PhantomData,
        }
    }
}

impl<Kind: Debug> Debug for Packet<Kind>
where
    Kind: CheckedPayload + ?Sized,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Packet").field(&self.deref()).finish()
    }
}
