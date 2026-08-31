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

//! Implementations of [`super::UdpSend`] and [`super::UdpRecv`] traits for [`UdpSocket`].

use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
};

use super::{UdpRecv, UdpTransportFactory, UdpTransportFactoryParams};

/// Implementations of [`super::UdpSend`]/[`super::UdpRecv`] for all targets
#[cfg(not(any(target_os = "linux", target_os = "android", target_os = "windows")))]
mod generic;

/// Implementations of [`super::UdpSend`]/[`super::UdpRecv`] for linux
#[cfg(any(target_os = "linux", target_os = "android"))]
mod linux;

/// Implementations of [`super::UdpSend`]/[`super::UdpRecv`] for windows
#[cfg(target_os = "windows")]
mod windows;

/// An implementation of [`UdpTransportFactory`] for regular UDP sockets. This provides `bind`.
#[derive(Debug, Default)]
pub struct UdpSocketFactory {
    /// If `Some`, set `SO_RCVBUF` on the socket.
    pub recv_buffer_size: Option<usize>,
    /// If `Some`, set `SO_SNDBUF` on the socket.
    pub send_buffer_size: Option<usize>,
}

impl UdpTransportFactory for UdpSocketFactory {
    type Send = UdpSocket;
    type Recv = UdpSocket;

    async fn bind(
        &mut self,
        params: &UdpTransportFactoryParams,
    ) -> io::Result<(Self::Send, Self::Recv)> {
        let dual_stack = params.addr.is_none();
        let only_v6 = match params.addr {
            Some(IpAddr::V6(..)) => Some(true),
            Some(IpAddr::V4(..)) => None,
            None => Some(false),
        };

        let opts = SockOpt {
            #[cfg(target_os = "linux")]
            fwmark: params.fwmark,
            recv_buffer_size: self.recv_buffer_size,
            send_buffer_size: self.send_buffer_size,
            only_v6,
        };

        let addr = params.addr.unwrap_or(Ipv6Addr::UNSPECIFIED.into());
        let udp = match UdpSocket::bind((addr, params.port).into(), opts) {
            Ok(udp) => udp,
            Err(e) if dual_stack && is_ipv6_unavailable(&e) => {
                tracing::warn!("IPv6 UDP sockets are unavailable; continuing with IPv4-only");
                UdpSocket::bind((Ipv4Addr::UNSPECIFIED, params.port).into(), opts)?
            }
            Err(e) => return Err(e),
        };

        if let Err(err) = udp.enable_udp_gro() {
            tracing::warn!("Failed to enable UDP GRO: {err}");
        }

        Ok((udp.clone(), udp))
    }
}

/// Default UDP socket implementation
#[derive(Clone)]
pub struct UdpSocket {
    inner: Arc<tokio::net::UdpSocket>,
    map_ipv4_to_ipv6: bool,
}

/// Options set on the socket created by [`UdpSocket::bind`].
#[derive(Copy, Clone, Debug, Default)]
pub struct SockOpt {
    /// If `Some`, set `fwmark` on the socket.
    #[cfg(target_os = "linux")]
    pub fwmark: Option<u32>,
    /// If `Some`, set `SO_RCVBUF` on the socket.
    pub recv_buffer_size: Option<usize>,
    /// If `Some`, set `SO_SNDBUF` on the socket.
    pub send_buffer_size: Option<usize>,
    /// If `Some`, set `IPV6_V6ONLY` on the socket.
    pub only_v6: Option<bool>,
}

impl UdpSocket {
    /// Create a UDP socket and bind it to `addr`.
    ///
    /// This also configures the following socket options:
    /// - `nonblocking`, to work with [`tokio`].
    /// - `only_v6`, to bind dual-stack sockets.
    /// - `mark`, only on linux.
    /// - `{recv,send}_buffer_size`, for better performance. See [`SockOpt`].
    pub fn bind(addr: SocketAddr, opts: SockOpt) -> io::Result<Self> {
        let domain = match addr {
            SocketAddr::V4(..) => socket2::Domain::IPV4,
            SocketAddr::V6(..) => socket2::Domain::IPV6,
        };

        // Construct the socket using `socket2` because we need to set the only_v6 flag.
        let udp_sock =
            socket2::Socket::new(domain, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))?;
        udp_sock.set_nonblocking(true)?;
        if let Some(only_v6) = opts.only_v6
            && addr.is_ipv6()
        {
            udp_sock.set_only_v6(only_v6)?;
        }
        #[cfg(target_os = "linux")]
        if let Some(mark) = opts.fwmark {
            udp_sock.set_mark(mark)?;
        }
        // Failing to set buffer sizes is not a fatal error - the tunnel will most likely work just
        // fine, even if not as performant as possible. In that case it is still a good idea to
        // tweak the buffer sizes.
        if let Some(recv_buffer_size) = opts.recv_buffer_size
            && let Err(err) = udp_sock.set_recv_buffer_size(recv_buffer_size)
        {
            if cfg!(debug_assertions) {
                return Err(err);
            } else {
                tracing::error!("Failed to change UDP socket receive buffer size: {err}");
            }
        }
        if let Some(send_buffer_size) = opts.send_buffer_size
            && let Err(err) = udp_sock.set_send_buffer_size(send_buffer_size)
        {
            if cfg!(debug_assertions) {
                return Err(err);
            } else {
                tracing::error!("Failed to change UDP socket send buffer size: {err}");
            }
        }

        udp_sock.bind(&addr.into())?;

        let inner = tokio::net::UdpSocket::from_std(udp_sock.into())?;

        Ok(Self {
            inner: Arc::new(inner),
            map_ipv4_to_ipv6: addr.is_ipv6() && opts.only_v6 == Some(false),
        })
    }

    /// Get the inner [`tokio::net::UdpSocket`].
    #[inline(always)]
    pub fn socket(&self) -> &tokio::net::UdpSocket {
        &self.inner
    }

    /// Returns the local address that this socket is bound to.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    /// Map an IPv4 address to IPv6 if necessary.
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    #[inline(always)]
    fn map_dst(&self, mut addr: SocketAddr) -> SocketAddr {
        if self.map_ipv4_to_ipv6
            && let std::net::IpAddr::V4(ip) = addr.ip()
        {
            addr.set_ip(ip.to_ipv6_mapped().into());
        }
        addr
    }
    /// Map an IPv6 address back to IPv4 if necessary.
    #[inline(always)]
    fn map_src(&self, addr: SocketAddr) -> SocketAddr {
        map_src_addr(self.map_ipv4_to_ipv6, addr)
    }
}

#[cfg(not(windows))]
impl std::os::fd::AsFd for UdpSocket {
    fn as_fd(&self) -> std::os::unix::prelude::BorrowedFd<'_> {
        self.inner.as_fd()
    }
}

#[cfg(windows)]
impl std::os::windows::io::AsSocket for UdpSocket {
    fn as_socket(&self) -> std::os::windows::io::BorrowedSocket<'_> {
        self.inner.as_socket()
    }
}

#[inline(always)]
fn map_src_addr(ipv4_over_ipv6: bool, mut addr: SocketAddr) -> SocketAddr {
    if ipv4_over_ipv6
        && let std::net::IpAddr::V6(ip) = addr.ip()
        && let Some(ipv4) = ip.to_ipv4_mapped()
    {
        addr.set_ip(ipv4.into());
    }
    addr
}

fn is_ipv6_unavailable(err: &io::Error) -> bool {
    cfg_select! {
        any(target_os = "linux", target_os = "android") => {
            matches!(
                err.raw_os_error(),
                Some(libc::EAFNOSUPPORT | libc::EADDRNOTAVAIL)
            )
        }
        _ => {
            let _ = err;
            false
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "android", target_os = "windows"))]
fn check_send_max_number_of_packets(
    max_number_of_packets: usize,
    packets: &[(crate::packet::Packet, SocketAddr)],
) -> io::Result<()> {
    debug_assert!(packets.len() <= max_number_of_packets);
    if packets.len() > max_number_of_packets {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("send_many_to: Number of packets may not exceed {max_number_of_packets}"),
        ));
    }
    Ok(())
}

#[cfg(test)]
#[cfg_attr(target_vendor = "apple", expect(clippy::let_unit_value))]
mod tests {
    use bytes::BytesMut;
    use tokio::time::timeout;
    use zerocopy::IntoBytes;

    use super::*;
    use crate::packet::{Packet, PacketBufPool};
    #[cfg(target_os = "linux")]
    use crate::udp::UdpRecv;
    use crate::udp::UdpSend;
    use std::iter;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::time::Duration;

    async fn set_up_dual_stack_test() -> (
        (UdpSocket, u16),
        tokio::net::UdpSocket,
        tokio::net::UdpSocket,
    ) {
        // Bind dual-stack socket
        let mut factory = UdpSocketFactory::default();
        let params = UdpTransportFactoryParams {
            addr: None,
            port: 0,
            #[cfg(target_os = "linux")]
            fwmark: None,
        };
        let (dual_sock, _) = factory.bind(&params).await.expect("bind");
        let addr = dual_sock.local_addr().expect("local_addr");
        assert_eq!(addr.ip(), Ipv6Addr::UNSPECIFIED);

        // Assert that IPV6_V6ONLY is false.
        #[cfg(not(windows))]
        {
            use std::os::fd::{AsRawFd, FromRawFd};
            let raw_fd = dual_sock.socket().as_raw_fd();
            let socket2 = unsafe { socket2::Socket::from_raw_fd(raw_fd) };
            assert!(!socket2.only_v6().unwrap());
            std::mem::forget(socket2); // Don't close the socket
        }
        #[cfg(windows)]
        {
            use std::os::windows::io::{AsRawSocket, FromRawSocket};
            let raw_socket = dual_sock.socket().as_raw_socket();
            let socket2 = unsafe { socket2::Socket::from_raw_socket(raw_socket) };
            assert!(!socket2.only_v6().unwrap());
            std::mem::forget(socket2); // Don't close the socket
        }

        // Bind two new sockets for receving packets from `dual_sock`
        let bind = async |addr: IpAddr| tokio::net::UdpSocket::bind((addr, 0)).await.unwrap();
        let v4 = bind(Ipv4Addr::LOCALHOST.into()).await;
        let v6 = bind(Ipv6Addr::LOCALHOST.into()).await;

        ((dual_sock, addr.port()), v4, v6)
    }

    /// Test that we can bind and send from a dual-stack ipv4+ipv6 socket.
    #[tokio::test]
    async fn dual_stack_socket_send() {
        let ((dual_sock, ..), v4_sock, v6_sock) = set_up_dual_stack_test().await;

        let v4_addr = v4_sock.local_addr().unwrap();
        let v6_addr = v6_sock.local_addr().unwrap();

        let mut recv_v4 = BytesMut::new();
        let mut recv_v6 = BytesMut::new();

        // Test helpers
        let t = Duration::from_millis(100);
        let recv_some = async |s: &tokio::net::UdpSocket, buf: &mut BytesMut| {
            timeout(t, s.recv_buf(buf)).await.unwrap().unwrap();
        };
        let recv_none = async |s: &tokio::net::UdpSocket, buf: &mut BytesMut| {
            timeout(t, s.recv_buf(buf)).await.expect_err("no packets");
        };
        let packet = |s: &str| Packet::from_bytes(s.as_bytes().into());

        // Send & receive a packet over IPv4
        dual_sock.send_to(packet("v4"), v4_addr).await.unwrap();
        recv_some(&v4_sock, &mut recv_v4).await;
        recv_none(&v6_sock, &mut recv_v6).await;
        assert_eq!(recv_v4, packet("v4").as_bytes());

        // Send & receive a packet over IPv6
        dual_sock.send_to(packet("v6"), v6_addr).await.unwrap();
        recv_some(&v6_sock, &mut recv_v6).await;
        recv_none(&v4_sock, &mut recv_v4).await;
        assert_eq!(recv_v6, packet("v6").as_bytes());

        // Send & receive many packet over IPv4
        let n = dual_sock.max_number_of_packets_to_send();
        let packets = iter::repeat(packet("v4")).map(|p| (p, v4_addr)).take(n);
        let mut buf = Default::default();
        dual_sock
            .send_many_to(&mut buf, &mut packets.collect())
            .await
            .unwrap();
        recv_none(&v6_sock, &mut recv_v4).await;
        for _ in 0..n {
            recv_some(&v4_sock, &mut recv_v6).await;
        }
        recv_none(&v4_sock, &mut recv_v6).await;

        // Send & receive many packet over IPv6
        let packets = iter::repeat(packet("v6")).map(|p| (p, v6_addr)).take(n);
        let mut buf = Default::default();
        dual_sock
            .send_many_to(&mut buf, &mut packets.collect())
            .await
            .unwrap();
        recv_none(&v4_sock, &mut recv_v4).await;
        for _ in 0..n {
            recv_some(&v6_sock, &mut recv_v6).await;
        }
        recv_none(&v6_sock, &mut recv_v6).await;
    }

    /// Test that we can bind and recv from a dual-stack ipv4+ipv6 socket.
    #[tokio::test]
    async fn dual_stack_socket_recv() {
        let mut pool1 = PacketBufPool::new(10);
        let mut pool2 = PacketBufPool::new(10);

        let ((mut dual_sock, port), v4_sock, v6_sock) = set_up_dual_stack_test().await;

        let v4_addr = v4_sock.local_addr().unwrap();
        let v6_addr = v6_sock.local_addr().unwrap();

        let dual_sock_v4_addr = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), port);
        let dual_sock_v6_addr = SocketAddr::new(Ipv6Addr::LOCALHOST.into(), port);

        // Test helpers
        let t = Duration::from_millis(100);
        let mut recv_some =
            async |s: &mut UdpSocket| timeout(t, s.recv_from(&mut pool1)).await.unwrap().unwrap();
        let mut recv_none = async |s: &mut UdpSocket| {
            timeout(t, s.recv_from(&mut pool2))
                .await
                .expect_err("no packets");
        };
        let packet = |s: &str| Packet::from_bytes(s.as_bytes().into());

        v4_sock
            .send_to(&packet("v4"), dual_sock_v4_addr)
            .await
            .unwrap();
        let (p, src) = recv_some(&mut dual_sock).await;
        assert_eq!(src, v4_addr);
        assert_eq!(&p[..], &packet("v4")[..]);
        recv_none(&mut dual_sock).await;

        v6_sock
            .send_to(&packet("v6"), dual_sock_v6_addr)
            .await
            .unwrap();
        let (p, src) = recv_some(&mut dual_sock).await;
        assert_eq!(src, v6_addr);
        assert_eq!(&p[..], &packet("v6")[..]);
        recv_none(&mut dual_sock).await;

        let mut n = 32;
        for _ in 0..n {
            v6_sock
                .send_to(&packet("v6"), dual_sock_v6_addr)
                .await
                .unwrap();
        }
        let mut buf = Default::default();
        while n > 0 {
            let mut out = vec![];
            dual_sock
                .recv_many_from(&mut buf, &mut pool1, &mut out)
                .await
                .unwrap();
            assert!(!out.is_empty() && out.len() <= n);
            n -= out.len();
            for (p, src) in out {
                assert_eq!(src, v6_addr);
                assert_eq!(&p[..], &packet("v6")[..]);
            }
        }
        recv_none(&mut dual_sock).await;

        let mut n = 32;
        for _ in 0..n {
            v4_sock
                .send_to(&packet("v4"), dual_sock_v4_addr)
                .await
                .unwrap();
        }
        let mut buf = Default::default();
        while n > 0 {
            let mut out = vec![];
            dual_sock
                .recv_many_from(&mut buf, &mut pool1, &mut out)
                .await
                .unwrap();
            assert!((1..=n).contains(&out.len()));
            n -= out.len();
            for (p, src) in out {
                assert_eq!(src, v4_addr);
                assert_eq!(&p[..], &packet("v4")[..]);
            }
        }
        recv_none(&mut dual_sock).await;
    }
}
