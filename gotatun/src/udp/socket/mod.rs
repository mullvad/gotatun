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

#[cfg(unix)]
use std::os::fd::AsFd;
use std::{
    io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
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
        let opts = SockOpt {
            #[cfg(target_os = "linux")]
            fwmark: params.fwmark,
            recv_buffer_size: self.recv_buffer_size,
            send_buffer_size: self.send_buffer_size,
        };

        let (udp_v4, udp_v6) = bind_sockets(params.addr_v4, params.addr_v6, params.port, opts)?;

        if let Err(err) = udp_v4.enable_udp_gro() {
            log::warn!("Failed to enable UDP GRO for IPv4 socket: {err}");
        }
        if let Err(err) = udp_v6.enable_udp_gro() {
            log::warn!("Failed to enable UDP GRO for IPv6 socket: {err}");
        }

        Ok(((udp_v4.clone(), udp_v4), (udp_v6.clone(), udp_v6)))
    }
}

/// Default UDP socket implementation
#[derive(Clone)]
pub struct UdpSocket {
    inner: Arc<tokio::net::UdpSocket>,
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
        udp_sock.set_reuse_address(true)?;
        #[cfg(target_os = "linux")]
        if let Some(mark) = opts.fwmark {
            udp_sock.set_mark(mark)?;
        }
        // Failing to set buffer sizes is not a fatal error - the tunnel will most likely work just
        // fine, even if not as performant as possible. In that case it is still a good idea to
        // tweak the buffer sizes.
        if let Some(recv_buffer_size) = opts.recv_buffer_size {
            if let Err(err) = udp_sock.set_recv_buffer_size(recv_buffer_size) {
                if cfg!(debug_assertions) {
                    return Err(err);
                } else {
                    log::error!("Failed to change UDP socket receive buffer size: {err}");
                }
            }
        }
        if let Some(send_buffer_size) = opts.send_buffer_size {
            if let Err(err) = udp_sock.set_send_buffer_size(send_buffer_size) {
                if cfg!(debug_assertions) {
                    return Err(err);
                } else {
                    log::error!("Failed to change UDP socket send buffer size: {err}");
                }
            }
        }

        udp_sock.bind(&addr.into())?;

        let inner = tokio::net::UdpSocket::from_std(udp_sock.into())?;

        Ok(Self {
            inner: Arc::new(inner),
        })
    }

    /// Returns the local address that this socket is bound to.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }
}

const BIND_MAX_RETRIES: u32 = 10;

/// Bind both an IPv4 and IPv6 UDP socket to the given port.
///
/// When `port` is 0 (random port), the IPv4 socket is bound first to get a port, then the IPv6
/// socket is bound to the same port. If the IPv6 bind fails with `AddrInUse`, both sockets are
/// rebound to a new random port, up to [`BIND_MAX_RETRIES`] times.
fn bind_sockets(
    addr_v4: Ipv4Addr,
    addr_v6: Ipv6Addr,
    port: u16,
    opts: SockOpt,
) -> io::Result<(UdpSocket, UdpSocket)> {
    let udp_v4 = UdpSocket::bind((addr_v4, port).into(), opts)?;
    match port {
        0 => bind_v6_with_retry(addr_v4, addr_v6, udp_v4, opts),
        p => {
            let udp_v6 = UdpSocket::bind((addr_v6, p).into(), opts)?;
            Ok((udp_v4, udp_v6))
        }
    }
}

/// When using a random port, the port chosen for IPv4 might already be in use on IPv6.
/// Retry with a new random port for both sockets.
fn bind_v6_with_retry(
    addr_v4: Ipv4Addr,
    addr_v6: Ipv6Addr,
    mut udp_v4: UdpSocket,
    opts: SockOpt,
) -> io::Result<(UdpSocket, UdpSocket)> {
    let mut port = UdpSocket::local_addr(&udp_v4)?.port();
    let mut retries = 0u32;
    let udp_v6 = loop {
        match UdpSocket::bind((addr_v6, port).into(), opts) {
            Ok(sock) => break sock,
            Err(err) if is_bind_retry_error(&err) && retries < BIND_MAX_RETRIES => {
                retries += 1;
                log::debug!(
                    "IPv6 port {port} already in use, retrying ({retries}/{BIND_MAX_RETRIES})"
                );
                udp_v4 = UdpSocket::bind((addr_v4, 0).into(), opts)?;
                port = UdpSocket::local_addr(&udp_v4)?.port();
            }
            Err(err) => return Err(err),
        }
    };
    Ok((udp_v4, udp_v6))
}

fn is_bind_retry_error(err: &io::Error) -> bool {
    #[cfg(not(target_os = "windows"))]
    {
        err.kind() == io::ErrorKind::AddrInUse
    }
    // Windows returns PermissionDenied (WSAEACCES) when binding with SO_REUSEADDR to a port
    // held by a socket without SO_REUSEADDR.
    #[cfg(target_os = "windows")]
    {
        err.kind() == io::ErrorKind::AddrInUse || err.kind() == io::ErrorKind::PermissionDenied
    }
}

#[cfg(unix)]
impl AsFd for UdpSocket {
    fn as_fd(&self) -> std::os::unix::prelude::BorrowedFd<'_> {
        self.inner.as_fd()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    /// Test that `bind_sockets` retries when the IPv6 port is already in use.
    ///
    /// We create an IPv6-only blocker (`IPV6_V6ONLY`, no `SO_REUSEADDR`) to exclusively
    /// hold a port on IPv6 without claiming the IPv4 side. Then we pre-bind an IPv4
    /// socket to the same port (which succeeds).
    #[tokio::test]
    async fn bind_retries_on_ipv6_conflict() {
        let blocker = socket2::Socket::new(
            socket2::Domain::IPV6,
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )
        .expect("create blocker");
        blocker.set_only_v6(true).expect("set IPV6_V6ONLY");
        blocker
            .bind(&SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)).into())
            .expect("bind blocker");
        let blocked_port = blocker
            .local_addr()
            .expect("blocker local_addr")
            .as_socket()
            .expect("as_socket")
            .port();

        // Pre-bind IPv4 to the blocked port (succeeds because the blocker is IPv6-only).
        let udp_v4 = UdpSocket::bind(
            (Ipv4Addr::UNSPECIFIED, blocked_port).into(),
            SockOpt::default(),
        )
        .expect("bind v4");

        // This should fail to bind IPv6 to blocked_port,
        // then rebind both sockets to a new random port.
        let (udp_v4, udp_v6) = bind_v6_with_retry(
            Ipv4Addr::UNSPECIFIED,
            Ipv6Addr::UNSPECIFIED,
            udp_v4,
            SockOpt::default(),
        )
        .expect("bind_v6_with_retry");

        let v4_port = udp_v4.local_addr().unwrap().port();
        let v6_port = udp_v6.local_addr().unwrap().port();
        assert_ne!(v4_port, blocked_port);
        assert_eq!(v4_port, v6_port);

        drop(blocker);
    }
}
