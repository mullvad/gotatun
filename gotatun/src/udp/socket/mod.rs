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
    type SendV4 = UdpSocket;
    type SendV6 = UdpSocket;
    type RecvV4 = UdpSocket;
    type RecvV6 = UdpSocket;

    async fn bind(
        &mut self,
        params: &UdpTransportFactoryParams,
    ) -> io::Result<((Self::SendV4, Self::RecvV4), (Self::SendV6, Self::RecvV6))> {
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
        let (udp, udp_v6) = match UdpSocket::bind((addr, params.port).into(), opts) {
            Ok(udp) => (udp.clone(), udp),
            Err(e) if dual_stack && is_ipv6_unavailable(&e) => {
                tracing::warn!("IPv6 UDP sockets are unavailable; continuing with IPv4-only");
                let udp_v4 = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, params.port).into(), opts)?;
                (udp_v4, UdpSocket::disabled_ipv6())
            }
            Err(e) => return Err(e),
        };

        if let Err(err) = udp.enable_udp_gro() {
            tracing::warn!("Failed to enable UDP GRO: {err}");
        }

        Ok(((udp.clone(), udp), (udp_v6.clone(), udp_v6)))
    }
}

/// Default UDP socket implementation
#[derive(Clone)]
pub struct UdpSocket {
    inner: UdpSocketInner,
}

#[derive(Clone)]
enum UdpSocketInner {
    Socket(Arc<tokio::net::UdpSocket>),
    DisabledIpv6,
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
    /// - `reuse_address`, to allow IPv6 and IPv4 sockets to be bound to the same port.
    /// - `{recv,send}_buffer_size`, for better performance. See [`SockOpt`].
    pub fn bind(addr: SocketAddr, opts: SockOpt) -> io::Result<Self> {
        let domain = match addr {
            SocketAddr::V4(..) => socket2::Domain::IPV4,
            SocketAddr::V6(..) => socket2::Domain::IPV6,
        };

        // Construct the socket using `socket2` because we need to set the reuse_address flag.
        let udp_sock =
            socket2::Socket::new(domain, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))?;
        udp_sock.set_nonblocking(true)?;
        if let Some(only_v6) = opts.only_v6 {
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
            inner: UdpSocketInner::Socket(Arc::new(inner)),
        })
    }

    fn disabled_ipv6() -> Self {
        Self {
            inner: UdpSocketInner::DisabledIpv6,
        }
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn is_disabled_ipv6(&self) -> bool {
        matches!(&self.inner, UdpSocketInner::DisabledIpv6)
    }

    /// Get the inner [`tokio::net::UdpSocket`].
    ///
    /// # Linux
    /// Returns an error if the socket type is of IPv6 and that is disabled on the system.
    #[inline(always)]
    pub fn socket(&self) -> io::Result<&tokio::net::UdpSocket> {
        match &self.inner {
            UdpSocketInner::Socket(socket) => Ok(socket),
            UdpSocketInner::DisabledIpv6 => Err(disabled_ipv6_error()),
        }
    }

    /// Returns the local address that this socket is bound to.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket()?.local_addr()
    }
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

fn disabled_ipv6_error() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "IPv6 UDP sockets are unavailable",
    )
}

#[cfg(not(target_os = "macos"))]
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
mod tests {
    use bytes::BytesMut;
    use tokio::time::timeout;
    use zerocopy::IntoBytes;

    use super::*;
    use crate::packet::Packet;
    #[cfg(target_os = "linux")]
    use crate::packet::PacketBufPool;
    #[cfg(target_os = "linux")]
    use crate::udp::UdpRecv;
    use crate::udp::UdpSend;
    use std::net::{Ipv4Addr, Ipv6Addr};
    #[cfg(not(windows))]
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::time::Duration;

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn disabled_ipv6_send_returns_unsupported() {
        let socket = UdpSocket::disabled_ipv6();
        let error = socket
            .send_to(Packet::default(), (Ipv6Addr::LOCALHOST, 1).into())
            .await
            .unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn disabled_ipv6_recv_returns_unsupported() {
        let mut socket = UdpSocket::disabled_ipv6();
        let mut pool = PacketBufPool::new(1);
        let mut recv_many_buf = <UdpSocket as UdpRecv>::RecvManyBuf::default();
        let mut packets = Vec::new();

        let error = socket.recv_from(&mut pool).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);

        let error = socket
            .recv_many_from(&mut recv_many_buf, &mut pool, &mut packets)
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn disabled_ipv6_socket_options_are_noops() {
        let socket = UdpSocket::disabled_ipv6();

        assert!(socket.set_fwmark(1).is_ok());
        assert!(socket.enable_udp_gro().is_ok());
        assert_eq!(UdpSend::local_addr(&socket).unwrap(), None);
    }

    #[tokio::test]
    async fn bind_ipv4_socket_uses_ipv4() {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0).into(), SockOpt::default())
            .expect("bind IPv4");

        assert!(socket.local_addr().unwrap().is_ipv4());
    }

    /// Test that we can bind and use a dual-stack ipv4+ipv6 socket.
    #[tokio::test]
    async fn dual_stack_socket() {
        // Bind dual-stacks socket
        let mut factory = UdpSocketFactory::default();
        let params = UdpTransportFactoryParams {
            addr: None,
            port: 0,
            #[cfg(target_os = "linux")]
            fwmark: None,
        };
        let ((dual_sock, ..), ..) = factory.bind(&params).await.expect("bind");
        let addr = dual_sock.local_addr().expect("local_addr");
        assert_eq!(addr.ip(), Ipv6Addr::UNSPECIFIED);

        // Assert that IPV6_V6ONLY is explicitly false.
        #[cfg(not(windows))]
        {
            let socket2 =
                unsafe { socket2::Socket::from_raw_fd(dual_sock.socket().unwrap().as_raw_fd()) };
            assert!(!socket2.only_v6().unwrap());
            std::mem::forget(socket2);
        }

        // Bind two new sockets for receving packets from `socket`
        let bind = async |addr: IpAddr| tokio::net::UdpSocket::bind((addr, 0)).await.unwrap();
        let v4 = bind(Ipv4Addr::LOCALHOST.into()).await;
        let v6 = bind(Ipv6Addr::LOCALHOST.into()).await;

        let v4_addr = v4.local_addr().unwrap();
        let v6_addr = v6.local_addr().unwrap();

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
        recv_some(&v4, &mut recv_v4).await;
        recv_none(&v6, &mut recv_v6).await;
        assert_eq!(recv_v4, packet("v4").as_bytes());

        // Send & receive a packet over IPv6
        dual_sock.send_to(packet("v6"), v6_addr).await.unwrap();
        recv_some(&v6, &mut recv_v6).await;
        recv_none(&v4, &mut recv_v4).await;
        assert_eq!(recv_v6, packet("v6").as_bytes());
    }
}
