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

//! Split one [`IpRecv`] source into multiple receivers based on IP destination,
//! or combine multiple [`IpSend`]s into one sender based on IP source.
//!
//! See [`TunRxRouter`] and [`TunTxRouter`].

use std::io;
use std::iter;
use std::net::SocketAddr;

use ip_network_table::IpNetworkTable;
use ipnetwork::IpNetwork;
use tokio::sync::mpsc;
use zerocopy::FromBytes;

use crate::packet::{Ip, IpNextProtocol, Packet, PacketBufPool, Udp};
use crate::tun::{IpRecv, IpSend, MtuWatcher};

/// An [`IpRecv`] that receives some subset of traffic from an unsplit [`IpRecv`].
pub struct SplitIpRecv {
    rx: mpsc::Receiver<Packet<Ip>>,
    mtu: MtuWatcher,
}

impl IpRecv for SplitIpRecv {
    async fn recv<'a>(
        &'a mut self,
        _pool: &mut PacketBufPool,
    ) -> io::Result<impl Iterator<Item = Packet<Ip>> + Send + 'a> {
        match self.rx.recv().await {
            Some(packet) => Ok(iter::once(packet)),
            None => Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "channel closed",
            )),
        }
    }

    fn mtu(&self) -> MtuWatcher {
        self.mtu.clone()
    }
}

fn new_split_channel(capacity: usize, mtu: MtuWatcher) -> (mpsc::Sender<Packet<Ip>>, SplitIpRecv) {
    let (tx, rx) = mpsc::channel(capacity);
    (tx, SplitIpRecv { rx, mtu })
}

/// A TUN router that splits a single [`IpRecv`] into multiple streams based on
/// destination IP.
pub struct TunRxRouter<SourceTunRx> {
    source: SourceTunRx,
    table: IpNetworkTable<mpsc::Sender<Packet<Ip>>>,
}

impl<SourceTunRx: IpRecv> TunRxRouter<SourceTunRx> {
    /// Create a new TUN router that reads from `source` and splits it into multiple streams.
    pub fn new(source: SourceTunRx) -> Self {
        Self {
            source,
            table: IpNetworkTable::new(),
        }
    }

    /// Insert a default route. This will replace any previous default route.
    pub fn add_default_route(&mut self, channel_capacity: usize) -> SplitIpRecv {
        self.add_route("0.0.0.0/0".parse().unwrap(), channel_capacity)
    }

    /// Insert a new route. This will replace any previously conflicting route.
    pub fn add_route(&mut self, route: IpNetwork, channel_capacity: usize) -> SplitIpRecv {
        let (tx, rx) = new_split_channel(channel_capacity, self.source.mtu());
        let net = ip_network::IpNetwork::new_truncate(route.ip(), route.prefix())
            .expect("cidr is valid length");
        self.table.insert(net, tx);
        rx
    }

    /// Insert multiple new routes with shared receiver. This will replace any previously conflicting route.
    pub fn add_routes(&mut self, routes: &[IpNetwork], channel_capacity: usize) -> SplitIpRecv {
        let (tx, rx) = new_split_channel(channel_capacity, self.source.mtu());
        for route in routes {
            let net = ip_network::IpNetwork::new_truncate(route.ip(), route.prefix())
                .expect("cidr is valid length");
            self.table.insert(net, tx.clone());
        }
        rx
    }

    /// Begin forwarding `self.source` to split streams.
    pub async fn run(mut self, mut pool: PacketBufPool) {
        loop {
            let packets = match self.source.recv(&mut pool).await {
                Ok(packets) => packets,
                Err(e) => {
                    log::error!("TUN router recv error: {e}");
                    // TODO: Must stop if TUN goes down, but is this always unrecoverable?
                    break;
                }
            };

            for packet in packets {
                let Some(dest) = packet.destination() else {
                    continue;
                };

                // Find matching route, or drop packet
                let Some((_net, tx)) = self.table.longest_match(dest) else {
                    continue;
                };

                if tx.send(packet).await.is_err() {
                    // TODO: Should we only stop if all channels have been dropped?
                    log::trace!("TUN router channel closed. Stopping");
                    return;
                }
            }
        }
    }
}

/// An [`IpSend`] combined from two [`IpSend`]s. If the source equals `inner_tun_endpoint`,
/// then `send` will forward the packet to `inner_tx` (e.g., a [`TunChannelTx`](crate::tun::channel::TunChannelTx)).
/// Otherwise, it is forwarded to `outer_tx` (e.g., a real TUN device).
///
/// Packets whose source IP falls inside any of the configured `inner_allowed_ips`
/// are silently dropped. This prevents the outer tunnel's peer from forging packets
/// that *appear* to originate inside the inner tunnel: such packets must only ever
/// reach the local stack via the inner WireGuard device, never via the outer one.
// TODO: Can we generalize this to map any number of endpoints to other channels?
pub struct TunTxRouter<Inner: IpSend, Outer: IpSend> {
    inner_tx: Inner,
    outer_tx: Outer,
    inner_tun_endpoint: SocketAddr,
    inner_allowed_ips: IpNetworkTable<()>,
}

impl<Inner: IpSend, Outer: IpSend> TunTxRouter<Inner, Outer> {
    /// Create a new `TunTxRouter`.
    ///
    /// # Arguments
    /// * `inner_tx` - Destination for packets matching inner tunnel addresses
    /// * `outer_tx` - Destination for all other packets
    /// * `inner_tun_endpoint` - UDP socket address of the inner WireGuard endpoint
    /// * `inner_allowed_ips` - Source IPs the inner tunnel is authoritative for.
    ///   Decapsulated packets with a source IP in this set are dropped, since the
    ///   outer peer would otherwise be able to spoof them. Pass an empty slice only
    ///   if no inner tunnel is wired up to this router (no spoofing surface).
    pub fn new(
        inner_tx: Inner,
        outer_tx: Outer,
        inner_tun_endpoint: SocketAddr,
        inner_allowed_ips: &[IpNetwork],
    ) -> Self {
        let mut table = IpNetworkTable::new();
        for net in inner_allowed_ips {
            let net = ip_network::IpNetwork::new_truncate(net.ip(), net.prefix())
                .expect("cidr is valid length");
            table.insert(net, ());
        }
        Self {
            inner_tx,
            outer_tx,
            inner_tun_endpoint,
            inner_allowed_ips: table,
        }
    }
}

impl<Inner: IpSend, Outer: IpSend> IpSend for TunTxRouter<Inner, Outer> {
    async fn send(&mut self, packet: Packet<Ip>) -> io::Result<()> {
        if let Some(src_ip) = packet.source()
            && self.inner_allowed_ips.longest_match(src_ip).is_some()
        {
            log::trace!(
                "Dropping decapsulated outer-tunnel packet with src {src_ip} \
                 inside inner_allowed_ips (forgery / hijack attempt)"
            );
            return Ok(());
        }
        if let Some(src) = extract_udp_src(&packet) {
            if self.inner_tun_endpoint == src {
                return self.inner_tx.send(packet).await;
            }
        }
        self.outer_tx.send(packet).await
    }
}

/// Extract the UDP source socket address from an IP packet without full parsing.
///
/// Returns `None` if:
/// - The IP version is not 4 or 6
/// - The protocol is not UDP
/// - The packet is too short to contain UDP headers
fn extract_udp_src(packet: &Ip) -> Option<SocketAddr> {
    let src_ip = packet.source()?;
    let transport_protocol = packet.next_protocol()?;
    if transport_protocol != IpNextProtocol::Udp {
        return None;
    }

    let udp = Udp::<[u8]>::ref_from_bytes(packet.payload()?).ok()?;

    // NOTE: Not validating UDP header/payload

    Some(SocketAddr::new(src_ip, udp.header.source_port.into()))
}
