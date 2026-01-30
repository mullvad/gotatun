// Copyright (c) 2025 Mullvad VPN AB. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Routes packets from one [`IpRecv`] source to multiple channel outputs based on destination IP.
//!
//! See [`tun_router`].

use std::io;
use std::iter;

use ip_network_table::IpNetworkTable;
use ipnetwork::IpNetwork;
use tokio::sync::mpsc;

use crate::packet::{Ip, Packet, PacketBufPool};
use crate::task::Task;
use crate::tun::{IpRecv, MtuWatcher};

/// Channel-based [`IpRecv`]. Receives packets routed by a [`tun_router`].
pub struct ChannelIpRecv {
    rx: mpsc::Receiver<Packet<Ip>>,
    mtu: MtuWatcher,
}

impl IpRecv for ChannelIpRecv {
    async fn recv<'a>(
        &'a mut self,
        _pool: &mut PacketBufPool,
    ) -> io::Result<impl Iterator<Item = Packet<Ip>> + Send + 'a> {
        match self.rx.recv().await {
            Some(packet) => Ok(iter::once(packet)),
            None => std::future::pending().await,
        }
    }

    fn mtu(&self) -> MtuWatcher {
        self.mtu.clone()
    }
}

async fn route_packets(
    mut source: impl IpRecv,
    table: IpNetworkTable<usize>,
    alt_sender: mpsc::Sender<Packet<Ip>>,
    default_sender: mpsc::Sender<Packet<Ip>>,
) {
    // TODO: do not use fixed-size pool
    let mut pool = PacketBufPool::new(100);

    loop {
        let packets = match source.recv(&mut pool).await {
            Ok(packets) => packets,
            Err(e) => {
                log::error!("TUN router recv error: {e}");
                // TODO: Handle error?
                continue;
            }
        };

        for packet in packets {
            let idx = packet
                .destination()
                .and_then(|dst| table.longest_match(dst).map(|(_, &idx)| idx))
                .unwrap_or(0);

            // TODO: Handle error?
            if idx == 1 {
                if alt_sender.send(packet).await.is_err() {
                    log::trace!("TUN router alt output channel closed");
                }
            } else {
                if default_sender.send(packet).await.is_err() {
                    log::trace!("TUN router default output channel closed");
                }
            }
        }
    }
}

/// Create a TUN router that reads from `source` and routes packets by destination IP.
///
/// Returns a handle (keeps the router task alive) and one [`ChannelIpRecv`] for
/// the alt route, and one for the default (unmatched) route.
///
/// # Arguments
/// * `source` - The [`IpRecv`] to read from (e.g. a TUN device)
/// * `alt_route` - Route to use for the alternative receiver
/// * `capacity` - Channel buffer size
pub fn tun_router(
    source: impl IpRecv,
    // TODO: multiple routes?
    alt_route: IpNetwork,
    capacity: usize,
) -> (Task, ChannelIpRecv, ChannelIpRecv) {
    let mtu = source.mtu();

    let (default_sender_tx, default_receiver_rx) = mpsc::channel(capacity);
    let (alt_sender_tx, alt_receiver_rx) = mpsc::channel(capacity);

    let default_receiver = ChannelIpRecv {
        rx: default_receiver_rx,
        mtu: mtu.clone(),
    };
    let alt_receiver = ChannelIpRecv {
        rx: alt_receiver_rx,
        mtu: mtu.clone(),
    };

    let mut table = IpNetworkTable::new();
    let net = ip_network::IpNetwork::new_truncate(alt_route.ip(), alt_route.prefix())
        .expect("cidr is valid length");
    table.insert(net, 1);

    let task = Task::spawn("tun-router", async move {
        route_packets(source, table, alt_sender_tx, default_sender_tx).await;
    });

    (task, alt_receiver, default_receiver)
}
