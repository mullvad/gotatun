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

        let (udp_v4, udp_v6) = cfg_select! {
            target_os = "linux" => {
                match bind_sockets(params.addr_v4, params.addr_v6, params.port, opts) {
                    Err(err) if is_ipv6_unavailable(&err) => {
                        tracing::warn!(
                            "IPv6 UDP sockets are unavailable; continuing with IPv4-only UDP transport"
                        );
                        let udp_v4 = bind_ipv4_socket(params.addr_v4, params.port, opts)?;
                        (udp_v4, UdpSocket::disabled_ipv6())
                    }
                    sockets => sockets?
                }
            }
            _ => { bind_sockets(params.addr_v4, params.addr_v6, params.port, opts)? }
        };

        if let Err(err) = udp_v4.enable_udp_gro() {
            tracing::warn!("Failed to enable UDP GRO for IPv4 socket: {err}");
        }
        if let Err(err) = udp_v6.enable_udp_gro() {
            tracing::warn!("Failed to enable UDP GRO for IPv6 socket: {err}");
        }

        let udp_v6 = (udp_v6.clone(), udp_v6);

        Ok(((udp_v4.clone(), udp_v4), udp_v6))
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
    #[cfg(target_os = "linux")]
    DisabledIpv6,
}

#[derive(Copy, Clone)]
enum BindMode {
    ReuseAddress,
    Exclusive,
    ExclusiveIpv6,
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
        Self::bind_inner(addr, opts, BindMode::ReuseAddress)
    }

    fn bind_exclusive(addr: SocketAddr, opts: SockOpt) -> io::Result<Self> {
        Self::bind_inner(addr, opts, BindMode::Exclusive)
    }

    fn bind_ipv6_only(addr: Ipv6Addr, port: u16, opts: SockOpt) -> io::Result<Self> {
        Self::bind_inner((addr, port).into(), opts, BindMode::ExclusiveIpv6)
    }

    fn bind_inner(addr: SocketAddr, opts: SockOpt, mode: BindMode) -> io::Result<Self> {
        let domain = match addr {
            SocketAddr::V4(..) => socket2::Domain::IPV4,
            SocketAddr::V6(..) => socket2::Domain::IPV6,
        };

        let udp_sock =
            socket2::Socket::new(domain, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))?;
        udp_sock.set_nonblocking(true)?;
        if matches!(mode, BindMode::ReuseAddress) {
            udp_sock.set_reuse_address(true)?;
        }
        #[cfg(target_os = "windows")]
        if matches!(mode, BindMode::Exclusive | BindMode::ExclusiveIpv6) {
            windows::set_exclusive_address_use(&udp_sock)?;
        }
        if matches!(mode, BindMode::ExclusiveIpv6) {
            udp_sock.set_only_v6(true)?;
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

    #[cfg(target_os = "linux")]
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
            #[cfg(target_os = "linux")]
            UdpSocketInner::DisabledIpv6 => Err(disabled_ipv6_error()),
        }
    }

    /// Returns the local address that this socket is bound to.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket()?.local_addr()
    }
}

const BIND_MAX_RETRIES: u32 = 10;

/// Bind both an IPv4 and IPv6 UDP socket to the given port.
///
/// Both sockets use non-reuse bindings. The IPv6 socket is IPv6-only, allowing both address
/// families to bind the same numeric port without enabling `SO_REUSEADDR`.
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
    let udp_v4 = UdpSocket::bind_exclusive((addr_v4, port).into(), opts)?;
    match port {
        0 => bind_v6_with_retry(addr_v4, addr_v6, udp_v4, opts),
        p => {
            let udp_v6 = UdpSocket::bind_ipv6_only(addr_v6, p, opts)?;
            Ok((udp_v4, udp_v6))
        }
    }
}

#[cfg(target_os = "linux")]
fn bind_ipv4_socket(addr_v4: Ipv4Addr, port: u16, opts: SockOpt) -> io::Result<UdpSocket> {
    UdpSocket::bind_exclusive((addr_v4, port).into(), opts)
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
        match UdpSocket::bind_ipv6_only(addr_v6, port, opts) {
            Ok(sock) => break sock,
            Err(err) if is_bind_retry_error(&err) && retries < BIND_MAX_RETRIES => {
                retries += 1;
                tracing::debug!(
                    "IPv6 port {port} already in use, retrying ({retries}/{BIND_MAX_RETRIES})"
                );
                udp_v4 = UdpSocket::bind_exclusive((addr_v4, 0).into(), opts)?;
                port = UdpSocket::local_addr(&udp_v4)?.port();
            }
            Err(err) => return Err(err),
        }
    };
    Ok((udp_v4, udp_v6))
}

#[cfg(target_os = "linux")]
fn is_ipv6_unavailable(err: &io::Error) -> bool {
    matches!(
        err.raw_os_error(),
        Some(libc::EAFNOSUPPORT | libc::EADDRNOTAVAIL)
    )
}

#[cfg(target_os = "linux")]
fn disabled_ipv6_error() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "IPv6 UDP sockets are unavailable",
    )
}

fn is_bind_retry_error(err: &io::Error) -> bool {
    #[cfg(not(target_os = "windows"))]
    {
        err.kind() == io::ErrorKind::AddrInUse
    }
    // Windows can report port ownership conflicts as WSAEACCES (PermissionDenied).
    #[cfg(target_os = "windows")]
    {
        err.kind() == io::ErrorKind::AddrInUse || err.kind() == io::ErrorKind::PermissionDenied
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(target_os = "linux")]
    use crate::packet::{Packet, PacketBufPool};
    #[cfg(target_os = "linux")]
    use crate::udp::{UdpRecv, UdpSend};
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[cfg(target_os = "linux")]
    #[test]
    fn recognizes_unavailable_ipv6_errors() {
        let error = io::Error::from_raw_os_error(libc::EAFNOSUPPORT);
        assert!(is_ipv6_unavailable(&error));

        let error = io::Error::from_raw_os_error(libc::EADDRNOTAVAIL);
        assert!(is_ipv6_unavailable(&error));

        let error = io::Error::from(io::ErrorKind::AddrInUse);
        assert!(!is_ipv6_unavailable(&error));
    }

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

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn bind_ipv4_socket_uses_ipv4() {
        let socket =
            bind_ipv4_socket(Ipv4Addr::LOCALHOST, 0, SockOpt::default()).expect("bind IPv4");

        assert!(socket.local_addr().unwrap().is_ipv4());
    }

    #[tokio::test]
    async fn bind_sockets_rejects_duplicate_port_and_releases_it() {
        let sockets = bind_sockets(
            Ipv4Addr::UNSPECIFIED,
            Ipv6Addr::UNSPECIFIED,
            0,
            SockOpt::default(),
        )
        .expect("bind exclusive sockets");
        let port = sockets.0.local_addr().expect("local address").port();

        let error = match bind_sockets(
            Ipv4Addr::UNSPECIFIED,
            Ipv6Addr::UNSPECIFIED,
            port,
            SockOpt::default(),
        ) {
            Ok(_) => panic!("a second socket pair claimed an active UDP port"),
            Err(error) => error,
        };
        assert!(
            is_bind_retry_error(&error),
            "unexpected bind error: {error}"
        );

        drop(sockets);
        bind_sockets(
            Ipv4Addr::UNSPECIFIED,
            Ipv6Addr::UNSPECIFIED,
            port,
            SockOpt::default(),
        )
        .expect("released UDP port should be immediately reusable");
    }

    #[tokio::test]
    async fn later_reuse_address_socket_cannot_claim_a_live_factory_port() {
        let (udp_v4, udp_v6) = bind_sockets(
            Ipv4Addr::UNSPECIFIED,
            Ipv6Addr::UNSPECIFIED,
            0,
            SockOpt::default(),
        )
        .expect("bind exclusive sockets");
        for address in [udp_v4.local_addr(), udp_v6.local_addr()] {
            let address = address.expect("local address");
            let domain = if address.is_ipv4() {
                socket2::Domain::IPV4
            } else {
                socket2::Domain::IPV6
            };
            let contender =
                socket2::Socket::new(domain, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))
                    .expect("create contender");
            if address.is_ipv6() {
                contender.set_only_v6(true).expect("set IPV6_V6ONLY");
            }
            contender.set_reuse_address(true).expect("set SO_REUSEADDR");

            let error = contender
                .bind(&address.into())
                .expect_err("live WireGuard port must remain exclusive");
            assert!(
                is_bind_retry_error(&error),
                "unexpected bind error: {error}"
            );
        }
    }

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
        let udp_v4 = UdpSocket::bind_exclusive(
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
