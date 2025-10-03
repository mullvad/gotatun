//! Trait abstractions for UDP sockets.
//!
//! [socket] contains implementation for actual UDP sockets.
//! [channel] contains implementation for tokio-based channels.

use std::{
    future::Future,
    io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
};

use crate::packet::{Packet, PacketBufPool};

pub mod buffer;
pub mod channel;
pub mod socket;

/// An abstraction of `UdpSocket::bind`.
///
/// See [UdpTransport].
pub trait UdpTransportFactory: Send + Sync + 'static {
    type Send: UdpSend + 'static;
    type RecvV4: UdpRecv + 'static;
    type RecvV6: UdpRecv + 'static;

    /// Bind sockets for sending and receiving UDP.
    ///
    /// Returns two pairs of UdpSend/Recvs, one for IPv4 and one for IPv6.
    #[allow(clippy::type_complexity)]
    fn bind(
        &mut self,
        params: &UdpTransportFactoryParams,
    ) -> impl Future<Output = io::Result<((Self::Send, Self::RecvV4), (Self::Send, Self::RecvV6))>> + Send;
}

/// Arguments to [UdpTransportFactory::bind].
#[derive(Clone)]
pub struct UdpTransportFactoryParams {
    pub addr_v4: Ipv4Addr,
    pub addr_v6: Ipv6Addr,
    pub port: u16,

    #[cfg(target_os = "linux")]
    pub fwmark: Option<u32>,
}

/// An abstraction of `recv_from` for a UDP socket.
///
/// This allows us to, for example, swap out UDP sockets with a channel.
pub trait UdpRecv: Send + Sync {
    /// Receive a single UDP packet.
    fn recv_from(
        &mut self,
        pool: &mut PacketBufPool,
    ) -> impl Future<Output = io::Result<(Packet, SocketAddr)>> + Send;

    /// The maximum number of packets that can be passed to [UdpRecv::recv_many_from].
    fn max_number_of_packets_to_recv(&self) -> usize {
        1
    }

    /// The buffer type that is passed to [UdpRecv::recv_many_from].
    type RecvManyBuf: Default + Send;

    /// Receive up to `x` packets at once,
    /// where `x` is [UdpRecv::max_number_of_packets_to_recv].
    ///
    /// # Arguments
    /// - `recv_buf` - Internal buffer. Should be reused between calls. Create with [Default].
    /// - `pool` - A pool that allocates packet buffers.
    /// - `packets` - Output. UDP datagrams and source addresses will be appended to this vector.
    ///
    /// The default implementation always reads 1 packet.
    fn recv_many_from(
        &mut self,
        recv_buf: &mut Self::RecvManyBuf,
        pool: &mut PacketBufPool,
        packets: &mut Vec<(Packet, SocketAddr)>,
    ) -> impl Future<Output = io::Result<()>> + Send {
        let _ = recv_buf;
        async move {
            let (packet, source_addr) = self.recv_from(pool).await?;
            packets.push((packet, source_addr));
            Ok(())
        }
    }

    /// Enable UDP GRO, if available
    fn enable_udp_gro(&self) -> io::Result<()> {
        Ok(())
    }
}

/// An abstraction of `send_to` for a UDP socket.
///
/// This allows us to, for example, swap out UDP sockets with a channel.
pub trait UdpSend: Send + Sync + Clone {
    type SendManyBuf: Default + Send + Sync;

    /// Send a single UDP packet to `destination`.
    fn send_to(
        &self,
        packet: Packet,
        destination: SocketAddr,
    ) -> impl Future<Output = io::Result<()>> + Send;

    /// The maximum number of packets that can be passed to [UdpSend::send_many_to].
    fn max_number_of_packets_to_send(&self) -> usize {
        1
    }

    /// Send up to `x` UDP packets to the destination,
    /// where `x` is [UdpSend::max_number_of_packets_to_send];
    ///
    /// # Arguments
    /// - `send_buf` - Internal buffer. Should be reused between calls. Create with [Default].
    /// - `packets` - Input. Packets to send. Packets are removed from this vector when sent.
    //
    // TODO: define how many packets are sent in case of an error.
    fn send_many_to(
        &self,
        send_buf: &mut Self::SendManyBuf,
        packets: &mut Vec<(Packet, SocketAddr)>,
    ) -> impl Future<Output = io::Result<()>> + Send {
        let _ = send_buf;
        generic_send_many_to(self, packets)
    }

    // --- Optional Methods ---

    /// Get the port in use, if any.
    ///
    /// This is applicable to UDP sockets, i.e. [tokio::net::UdpSocket].
    fn local_addr(&self) -> io::Result<Option<SocketAddr>> {
        Ok(None)
    }

    /// Set `fwmark`.
    ///
    /// This is applicable to UDP sockets, i.e. [tokio::net::UdpSocket].
    #[cfg(target_os = "linux")]
    fn set_fwmark(&self, _mark: u32) -> io::Result<()> {
        Ok(())
    }
}

async fn generic_send_many_to<U: UdpSend>(
    transport: &U,
    packets: &mut Vec<(Packet, SocketAddr)>,
) -> io::Result<()> {
    for (packet, target) in packets.drain(..) {
        transport.send_to(packet, target).await?;
    }
    Ok(())
}
