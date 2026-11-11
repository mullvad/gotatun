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

//! Integration tests for receiving on a UDP socket that has sent a datagram to a closed
//! port.
//!
//! When a datagram reaches a port where nothing listens, the receiving host answers with
//! an ICMP "port unreachable" message. Linux and macOS drop that report for an
//! unconnected socket. Windows keeps it and fails the socket's next receive with
//! `WSAECONNRESET`, although the next datagram may come from a different peer entirely.
//! The report concerns one earlier datagram, so it must not fail or end reception.
//! See <https://github.com/mullvad/gotatun/issues/226>.
//!
//! The tests drive the real `UdpSocket` through the public `UdpSend` and `UdpRecv` APIs
//! over loopback, so they exercise whichever receive code path is compiled in: Linux
//! `recvmmsg`, Windows `recvfrom` (or `WSARecvMsg` with the `windows-gro` feature), and
//! the generic tokio fallback.

use gotatun::packet::{Packet, PacketBufPool};
use gotatun::udp::socket::{SockOpt, UdpSocket, UdpSocketFactory};
use gotatun::udp::{UdpRecv, UdpSend, UdpTransportFactory, UdpTransportFactoryParams};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;
use tokio::time::timeout;

/// Guards every step against hanging. Generous, since CI runners can be slow.
const TIMEOUT: Duration = Duration::from_secs(5);

/// How the socket under test receives.
#[derive(Clone, Copy, Debug)]
enum Receive {
    /// [`UdpRecv::recv_from`]: one datagram.
    One,
    /// [`UdpRecv::recv_many_from`]: a batch, as gotatun's device receives.
    Many,
}

/// A gotatun socket and a plain socket that talks to it.
struct Harness {
    socket: UdpSocket,
    /// Where `peer` reaches `socket`.
    socket_addr: SocketAddr,
    peer: tokio::net::UdpSocket,
    peer_addr: SocketAddr,
    /// A loopback address where nothing listens.
    closed: SocketAddr,
    recv_buf: <UdpSocket as UdpRecv>::RecvManyBuf,
    pool: PacketBufPool,
}

impl Harness {
    /// Bind a gotatun socket to `ip`, and a peer on the loopback address of the same family.
    async fn bind(ip: IpAddr) -> Self {
        let socket = UdpSocket::bind((ip, 0).into(), SockOpt::default()).unwrap();
        Self::new(socket, ip).await
    }

    /// Bind a dual-stack socket the way a device does by default, and talk to it over
    /// IPv4 loopback.
    async fn bind_dual_stack() -> Self {
        let params = UdpTransportFactoryParams {
            addr: None,
            port: 0,
            #[cfg(target_os = "linux")]
            fwmark: None,
        };
        let (_, socket) = UdpSocketFactory::default().bind(&params).await.unwrap();
        Self::new(socket, Ipv4Addr::LOCALHOST.into()).await
    }

    async fn new(socket: UdpSocket, loopback: IpAddr) -> Self {
        // Exercise the GRO path on platforms that support it; a no-op elsewhere.
        socket.enable_udp_gro().ok();
        let socket_addr = SocketAddr::new(loopback, socket.local_addr().unwrap().port());
        let peer = tokio::net::UdpSocket::bind((loopback, 0)).await.unwrap();
        let peer_addr = peer.local_addr().unwrap();
        Self {
            socket,
            socket_addr,
            peer,
            peer_addr,
            closed: closed_port(loopback),
            recv_buf: Default::default(),
            pool: PacketBufPool::new(16),
        }
    }

    /// Send a datagram to the closed port, and wait until it has been handled.
    async fn send_to_closed_port(&self) {
        self.socket
            .send_to(Packet::copy_from(&b"to a closed port"[..]), self.closed)
            .await
            .unwrap();

        // On loopback, a datagram sent after it arrives after it has been handled, so by the
        // time the peer has this one, the port unreachable report has been sent back.
        self.socket
            .send_to(Packet::copy_from(&b"sync"[..]), self.peer_addr)
            .await
            .unwrap();
        let mut buf = [0u8; 64];
        let (n, from) = timeout(TIMEOUT, self.peer.recv_from(&mut buf))
            .await
            .expect("the peer must receive the sync datagram")
            .unwrap();
        assert_eq!((&buf[..n], from), (&b"sync"[..], self.socket_addr));
    }

    /// Send `marker` from the peer and assert that the socket receives exactly it.
    async fn expect_marker(&mut self, marker: &[u8], via: Receive) {
        self.peer.send_to(marker, self.socket_addr).await.unwrap();

        let (data, from) = timeout(TIMEOUT, self.receive(via))
            .await
            .unwrap_or_else(|_| panic!("{via:?}: the marker never arrived"))
            .unwrap_or_else(|err| {
                panic!("{via:?}: a port unreachable report must not fail the receive: {err:?}")
            });
        assert_eq!(
            data, marker,
            "{via:?}: received something other than the marker"
        );
        assert_eq!(from, self.peer_addr);
    }

    /// Receive one datagram.
    async fn receive(&mut self, via: Receive) -> io::Result<(Vec<u8>, SocketAddr)> {
        match via {
            Receive::One => {
                let (packet, from) = self.socket.recv_from(&mut self.pool).await?;
                Ok((packet.to_vec(), from))
            }
            Receive::Many => {
                let mut packets = Vec::new();
                self.socket
                    .recv_many_from(&mut self.recv_buf, &mut self.pool, &mut packets)
                    .await?;
                assert_eq!(packets.len(), 1, "expected a batch of one datagram");
                let (packet, from) = packets.pop().unwrap();
                Ok((packet.to_vec(), from))
            }
        }
    }

    /// Assert that nothing else is waiting: no datagram, and no error.
    async fn expect_quiet(&mut self, via: Receive) {
        if let Ok(result) = timeout(Duration::from_millis(200), self.receive(via)).await {
            panic!("{via:?}: expected nothing more, got {result:?}");
        }
    }
}

/// A loopback address where nothing listens: bind a socket, note its address, close it.
fn closed_port(loopback: IpAddr) -> SocketAddr {
    let socket = std::net::UdpSocket::bind((loopback, 0)).unwrap();
    socket.local_addr().unwrap()
}

async fn one_report(mut harness: Harness, via: Receive) {
    harness.send_to_closed_port().await;
    harness.expect_marker(b"marker", via).await;
    harness.expect_quiet(via).await;
}

#[tokio::test]
async fn recv_from_continues_after_port_unreachable_ipv4() {
    one_report(
        Harness::bind(Ipv4Addr::LOCALHOST.into()).await,
        Receive::One,
    )
    .await;
}

#[tokio::test]
async fn recv_from_continues_after_port_unreachable_ipv6() {
    one_report(
        Harness::bind(Ipv6Addr::LOCALHOST.into()).await,
        Receive::One,
    )
    .await;
}

#[tokio::test]
async fn recv_many_from_continues_after_port_unreachable_ipv4() {
    one_report(
        Harness::bind(Ipv4Addr::LOCALHOST.into()).await,
        Receive::Many,
    )
    .await;
}

#[tokio::test]
async fn recv_many_from_continues_after_port_unreachable_ipv6() {
    one_report(
        Harness::bind(Ipv6Addr::LOCALHOST.into()).await,
        Receive::Many,
    )
    .await;
}

/// The device binds a dual-stack socket by default.
#[tokio::test]
async fn recv_many_from_continues_after_port_unreachable_dual_stack() {
    one_report(Harness::bind_dual_stack().await, Receive::Many).await;
}

/// Many reports, one after another, each followed by a datagram: none is lost, and nothing
/// is left over afterwards.
#[tokio::test]
async fn receive_continues_after_many_port_unreachable_reports() {
    for via in [Receive::One, Receive::Many] {
        let mut harness = Harness::bind(Ipv4Addr::LOCALHOST.into()).await;
        for round in 0..100 {
            harness.send_to_closed_port().await;
            harness
                .expect_marker(format!("marker {round}").as_bytes(), via)
                .await;
        }
        harness.expect_quiet(via).await;
    }
}

/// Several reports pending at once, then a single datagram.
#[tokio::test]
async fn receive_continues_after_port_unreachable_reports_in_a_row() {
    for via in [Receive::One, Receive::Many] {
        let mut harness = Harness::bind(Ipv4Addr::LOCALHOST.into()).await;
        for _ in 0..20 {
            harness.send_to_closed_port().await;
        }
        harness.expect_marker(b"marker", via).await;
        harness.expect_quiet(via).await;
    }
}
