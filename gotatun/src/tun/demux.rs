// Copyright (c) 2025 Mullvad VPN AB. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Routes decrypted packets to either an inner device's UDP bridge or the real TUN.
//!
//! See [`DemuxIpSend`].

// Note: For decrypted packets, the source IP is the inner tunnel endpoint.

use std::io;
use std::net::SocketAddr;

use crate::packet::{Ip, Packet};
use crate::tun::IpSend;

/// Routes decrypted packets to either an inner device's UDP bridge or the real TUN.
///
/// If a packet is UDP and its destination `(IP, port)` matches one of the `inner_addrs`,
/// it is forwarded to `inner_tx` (e.g. the [`TunChannelTx`](crate::tun::channel::TunChannelTx)
/// from [`new_udp_tun_channel`](crate::udp::channel::new_udp_tun_channel)).
/// Otherwise, it is sent to `outer_tx` (typically the real TUN device).
pub struct DemuxIpSend<Inner: IpSend, Outer: IpSend> {
    inner_tx: Inner,
    outer_tx: Outer,
    inner_tun_endpoint: SocketAddr,
}

impl<Inner: IpSend, Outer: IpSend> DemuxIpSend<Inner, Outer> {
    /// Create a new `DemuxIpSend`.
    ///
    /// # Arguments
    /// * `inner_tx` - Destination for packets matching inner tunnel addresse
    /// * `outer_tx` - Destination for all other packets
    /// * `inner_tun_addr` - IP address of the inner WireGuard
    // TODO: Also a router? Is this too specific?
    pub fn new(inner_tx: Inner, outer_tx: Outer, inner_tun_endpoint: SocketAddr) -> Self {
        Self {
            inner_tx,
            outer_tx,
            inner_tun_endpoint,
        }
    }
}

/// Extract the UDP source socket address from an IP packet without full parsing.
///
/// Returns `None` if:
/// - The IP version is not 4 or 6
/// - The protocol is not UDP (17)
/// - The packet is too short to contain UDP headers
fn extract_udp_src(packet: &Ip) -> Option<SocketAddr> {
    let src_ip = packet.source()?;
    let version = packet.header.version();

    // Determine protocol byte and UDP source port offset within `Ip::rest`.
    // `rest` starts at byte 1 of the IP packet (after the version nibble byte).
    let (protocol_byte, udp_src_port_offset) = match version {
        // IPv4: protocol at byte 9 from start → rest[8]
        //        UDP src port at bytes 20-21 from start → rest[19..21]
        4 => (packet.rest.get(8)?, 19usize),
        // IPv6: next_header at byte 6 from start → rest[5]
        //        UDP src port at bytes 40-41 from start → rest[39..41]
        6 => (packet.rest.get(5)?, 39usize),
        _ => return None,
    };

    // UDP protocol number is 17
    if *protocol_byte != 17 {
        return None;
    }

    let port_bytes = packet
        .rest
        .get(udp_src_port_offset..udp_src_port_offset + 2)?;
    let src_port = u16::from_be_bytes([port_bytes[0], port_bytes[1]]);
    Some(SocketAddr::new(src_ip, src_port))
}

impl<Inner: IpSend, Outer: IpSend> IpSend for DemuxIpSend<Inner, Outer> {
    async fn send(&mut self, packet: Packet<Ip>) -> io::Result<()> {
        if let Some(src) = extract_udp_src(&packet) {
            if self.inner_tun_endpoint == src {
                return self.inner_tx.send(packet).await;
            }
        }
        self.outer_tx.send(packet).await
    }
}
