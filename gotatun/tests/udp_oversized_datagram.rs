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

//! Integration test for the UDP receive layer's handling of oversized datagrams.
//!
//! A remote peer can send a UDP datagram far larger than gotatun's receive pool
//! buffer (default 4096 bytes). On loopback this is a single jumbo datagram; over a
//! real network the same size is reachable via IP fragment reassembly. Every
//! platform-specific `UdpSocket` receive implementation (Linux GRO `recvmmsg`,
//! Windows `recvmsg`, and the generic tokio fallback) must handle this without
//! crashing the receive task - otherwise a single unauthenticated packet is a remote
//! denial of service.
//!
//! It drives the real `UdpSocket` through the public `UdpRecv` API, so it exercises
//! whichever receive code path is compiled in. It deliberately does not assert *how*
//! the oversized datagram is handled (Linux drops it, the generic path truncates it);
//! it asserts only the universal safety property: the receiver survives and still
//! delivers a subsequent legitimate datagram.
//!
//! Windows is excluded: its receive path reads into a 64 KiB buffer (not the 4096
//! pool buffer), so the overflow this guards against cannot occur there, and
//! `WSARecvMsg` reports an oversized datagram as a hard `WSAEMSGSIZE` error rather
//! than truncating, which this portable harness cannot drive uniformly.
#![cfg(not(target_os = "windows"))]

use gotatun::packet::{Packet, PacketBufPool};
use gotatun::udp::UdpRecv;
use gotatun::udp::socket::{SockOpt, UdpSocket};
use std::net::{Ipv6Addr, SocketAddr, UdpSocket as StdUdpSocket};
use std::time::Duration;

#[tokio::test]
async fn oversized_datagram_does_not_crash_receiver() {
    // Use IPv6 loopback. On WSL2 in mirrored networking mode, IPv4 `127.0.0.1`
    // traffic is routed through the Windows host path (MTU 1500), where the
    // oversized datagram must fragment and WSL's broken IPv4 UDP fragment
    // reassembly drops it. `::1` is left on the native Linux `lo` interface
    // (MTU 65536), so the datagram arrives intact on both WSL and native Linux.
    let mut receiver =
        UdpSocket::bind((Ipv6Addr::LOCALHOST, 0).into(), SockOpt::default()).unwrap();
    // Exercise the GRO path on platforms that support it; a no-op elsewhere.
    receiver.enable_udp_gro().ok();
    let recv_addr = receiver.local_addr().unwrap();

    // The attacker sends a datagram larger than the 4096-byte pool buffer, followed
    // by a legitimate small one. 8 KiB exceeds the receive buffer while staying within
    // the most restrictive platform's single-datagram UDP limit (macOS defaults to
    // net.inet.udp.maxdgram = 9216). On a real link such a datagram reaches the socket
    // via IP fragment reassembly.
    let attacker = StdUdpSocket::bind((Ipv6Addr::LOCALHOST, 0)).unwrap();
    attacker.send_to(&vec![0xABu8; 8000], recv_addr).unwrap();
    attacker.send_to(b"hello", recv_addr).unwrap();

    let mut pool = PacketBufPool::<4096>::new(16);
    // On platforms without a custom recv_many_from (the generic path) this type is
    // `()`, so the binding has unit value; it is a reusable buffer elsewhere.
    #[allow(clippy::let_unit_value)]
    let mut recv_buf = <UdpSocket as UdpRecv>::RecvManyBuf::default();
    let mut packets: Vec<(Packet, SocketAddr)> = Vec::new();

    // The receiver must survive the oversized datagram (no panic) and keep working,
    // proven by the legitimate "hello" still being delivered. A panic or a hang both
    // fail the test - the latter via the timeout.
    tokio::time::timeout(Duration::from_secs(5), async {
        while !packets.iter().any(|(buf, _)| &buf[..] == b"hello") {
            receiver
                .recv_many_from(&mut recv_buf, &mut pool, &mut packets)
                .await
                .unwrap();
        }
    })
    .await
    .expect("receiver must survive an oversized datagram and still deliver a valid one");
}
