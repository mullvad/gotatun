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

pub use ip::*;
pub use ipv4::*;
pub use ipv6::*;
pub use pool::*;
pub use udp::*;

/// An owned packet of some type.
///
/// The generic type `Kind` represents the type of packet.
/// For example, a `Packet<[u8]>` is an untyped packet containing arbitrary bytes.
/// It can be safely decoded into a `Packet<Ipv4>` using [`Packet::try_into_ip`],
/// and further decoded into a `Packet<Ipv4<Udp>>` using [`Packet::try_into_udp`].
///
/// [Packet] uses [BytesMut] as the backing buffer.
///
/// ```
/// use boringtun::packet::*;
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

pub struct PacketInner {
    buf: BytesMut,

    // If the [BytesMut] was allocated by a [PacketBufPool], this will return the buffer to be re-used later.
    _return_to_pool: Option<ReturnToPool>,
}

/// A marker trait that indicates that a [Packet] contains a valid payload of a specific type.
///
/// For example, [CheckedPayload] is implemented for [`Ipv4<[u8]>`], and a [`Packet<Ipv4<[u8]>>>`]
/// can only be constructed through [`Packet::<[u8]>::try_into_ip`], which checks that the IPv4
/// header is valid.
pub trait CheckedPayload: FromBytes + IntoBytes + KnownLayout + Immutable + Unaligned {}

impl CheckedPayload for [u8] {}
impl CheckedPayload for Ip {}
impl<P: CheckedPayload + ?Sized> CheckedPayload for Ipv6<P> {}
impl<P: CheckedPayload + ?Sized> CheckedPayload for Ipv4<P> {}
impl<P: CheckedPayload + ?Sized> CheckedPayload for Udp<P> {}

impl<T: CheckedPayload + ?Sized> Packet<T> {
    fn cast<Y: CheckedPayload + ?Sized>(self) -> Packet<Y> {
        Packet {
            inner: self.inner,
            _kind: PhantomData::<Y>,
        }
    }

    pub fn into_bytes(self) -> Packet<[u8]> {
        self.cast()
    }

    fn buf(&self) -> &[u8] {
        &self.inner.buf
    }

    pub fn copy_from(payload: &T) -> Self {
        Self {
            inner: PacketInner {
                buf: BytesMut::from(payload.as_bytes()),
                _return_to_pool: None,
            },
            _kind: PhantomData::<T>,
        }
    }
}

// Trivial From conversions between packet types
#[duplicate_item(
    FromType ToType;
    [Ipv4<Udp>] [Ipv4];
    [Ipv6<Udp>] [Ipv6];

    [Ipv4<Udp>] [Ip];
    [Ipv6<Udp>] [Ip];
    [Ipv4]      [Ip];
    [Ipv6]      [Ip];

    [Ipv4<Udp>] [[u8]];
    [Ipv6<Udp>] [[u8]];
    [Ipv4]      [[u8]];
    [Ipv6]      [[u8]];
    [Ip]        [[u8]];
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
    pub fn new_from_pool(return_to_pool: ReturnToPool, bytes: BytesMut) -> Self {
        Self {
            inner: PacketInner {
                buf: bytes,
                _return_to_pool: Some(return_to_pool),
            },
            _kind: PhantomData::<[u8]>,
        }
    }

    pub fn from_bytes(bytes: BytesMut) -> Self {
        Self {
            inner: PacketInner {
                buf: bytes,
                _return_to_pool: None,
            },
            _kind: PhantomData::<[u8]>,
        }
    }

    pub fn truncate(&mut self, new_len: usize) {
        self.inner.buf.truncate(new_len);
    }

    pub fn buf_mut(&mut self) -> &mut BytesMut {
        &mut self.inner.buf
    }

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

    pub fn try_into_ipvx(self) -> eyre::Result<Either<Packet<Ipv4>, Packet<Ipv6>>> {
        self.try_into_ip()?.try_into_ipvx()
    }
}

impl Packet<Ip> {
    pub fn try_into_ipvx(self) -> eyre::Result<Either<Packet<Ipv4>, Packet<Ipv6>>> {
        match self.header.version() {
            4 => {
                let buf_len = self.buf().len();

                let ipv4 = Ipv4::<[u8]>::ref_from_bytes(self.buf())
                    .map_err(|e| eyre!("Bad IPv4 packet: {e:?}"))?;

                let ip_len = usize::from(ipv4.header.total_len.get());
                if ip_len != buf_len {
                    bail!("IPv4 `total_len` did not match packet length: {ip_len} != {buf_len}");
                }

                // TODO: validate checksum

                // we have asserted that the packet is a valid IPv4 packet.
                // update `_kind` to reflect this.
                Ok(Either::Left(self.cast::<Ipv4>()))
            }
            6 => {
                let ipv6 = Ipv6::<[u8]>::ref_from_bytes(self.buf())
                    .map_err(|e| eyre!("Bad IPv6 packet: {e:?}"))?;

                let payload_len = usize::from(ipv6.header.payload_length.get());
                if payload_len != ipv6.payload.len() {
                    bail!(
                        "IPv6 `payload_len` did not match packet length: {payload_len} != {}",
                        ipv6.payload.len()
                    );
                }

                // TODO: validate checksum

                // we have asserted that the packet is a valid IPv6 packet.
                // update `_kind` to reflect this.
                Ok(Either::Right(self.cast::<Ipv6>()))
            }
            v => bail!("Bad IP version: {v}"),
        }
    }
}

/// Result of attempting to convert an IPv4 packet into a UDP packet.
#[derive(Debug)]
pub enum TryIntoUdpResult {
    /// The packet is a valid IPv4 UDP packet.
    Udp(Packet<Ipv4<Udp>>),
    /// The packet is an IPv4 fragment.
    UdpFragment(Packet<Ipv4>),
}

impl Packet<Ipv4> {
    /// Attempts to convert this IPv4 packet into a UDP packet.
    ///
    /// Returns [`TryIntoUdpResult::Udp`] if the packet is a valid, non-fragmented IPv4 UDP packet
    /// with no options (IHL == 5). Returns [`TryIntoUdpResult::NotUdp`] if the packet is a fragment
    /// of a UDP packet.
    ///
    /// # Errors
    ///
    /// Returns an error if the IHL is invalid or if UDP validation fails.
    pub fn try_into_udp(self) -> eyre::Result<TryIntoUdpResult> {
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
            return Ok(TryIntoUdpResult::UdpFragment(self));
        }

        validate_udp(ip.header.next_protocol(), &ip.payload)
            .wrap_err_with(|| eyre!("IP header: {:?}", ip.header))?;

        // we have asserted that the packet is a valid IPv4 UDP packet.
        // update `_kind` to reflect this.
        Ok(TryIntoUdpResult::Udp(self.cast::<Ipv4<Udp>>()))
    }
}

impl Packet<Ipv6> {
    /// Check if the IP payload is valid UDP.
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
    pub fn into_payload(mut self) -> Packet<T> {
        self.inner.buf.advance(Ipv6Header::LEN);
        self.cast::<T>()
    }
}
impl<T: CheckedPayload + ?Sized> Packet<Udp<T>> {
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

impl<Kind: Debug> Debug for Packet<Kind>
where
    Kind: CheckedPayload + ?Sized,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Packet").field(&self.deref()).finish()
    }
}

// This clone implementation is only for tests, as the clone will cause an allocation and will not return the buffer to the pool.
#[cfg(test)]
impl<Kind: ?Sized> Clone for Packet<Kind> {
    fn clone(&self) -> Self {
        Self {
            inner: PacketInner {
                buf: self.inner.buf.clone(),
                _return_to_pool: None, // Cloning does not return to pool
            },
            _kind: PhantomData,
        }
    }
}
