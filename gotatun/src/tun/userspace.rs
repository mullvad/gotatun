use std::{collections::HashMap, future::pending, io, iter::once, net::SocketAddrV4};

use either::Either;
use futures::FutureExt;
use tokio::{
    select,
    sync::{mpsc, watch},
};

use crate::{
    packet::{
        Decoder, Ip, Ipv4, Ipv4Decoder, Ipv4PayloadDecoder, Packet, PacketBufPool, Udp, UdpDecoder,
    },
    udp::channel::create_ipv4_payload,
};

use super::{IpRecv, IpSend};

pub fn new_userspace_net<Tx, Rx>(
    inner_tx: Tx,
    inner_rx: Rx,
) -> (
    UserspaceNet,
    UserspaceNetMuxerTx<Tx>,
    UserspaceNetMuxerRx<Rx>,
) {
    let (route_updates_tx, route_updates_rx) = watch::channel(Default::default());
    let (outgoing_tx, outgoing_rx) = mpsc::channel(100); // TODO: capacity?
    let net = UserspaceNet {
        routing_table: Default::default(),
        route_updates: route_updates_tx,
        outgoing_tx,
    };

    let tx = UserspaceNetMuxerTx {
        inner: inner_tx,
        routing_table: Default::default(),
        route_updates: route_updates_rx,
    };

    let rx = UserspaceNetMuxerRx {
        inner: inner_rx,
        userspace_rx: outgoing_rx,
    };

    (net, tx, rx)
}

pub struct UserspaceNet {
    routing_table: RoutingTable,
    route_updates: watch::Sender<RoutingTable>,
    outgoing_tx: mpsc::Sender<Packet<Ip>>,
}

pub struct UserspaceNetMuxerTx<Tx> {
    inner: Tx,
    routing_table: RoutingTable,
    route_updates: watch::Receiver<RoutingTable>,
}

pub struct UserspaceNetMuxerRx<Rx> {
    inner: Rx,
    userspace_rx: mpsc::Receiver<Packet<Ip>>,
}

pub struct UserspaceUdpV4 {
    route_updates: watch::Sender<RoutingTable>,
    local: SocketAddrV4,
    remote: SocketAddrV4,
    tx: mpsc::Sender<Packet<Ip>>,
    rx: mpsc::Receiver<Packet<Ip>>,
}

#[derive(Clone, PartialEq, Eq, Hash)]
enum Route {
    UdpV4 {
        local: SocketAddrV4,
        remote: SocketAddrV4,
    },
}

#[derive(Default, Clone)]
struct RoutingTable {
    table: HashMap<Route, mpsc::Sender<Packet<Ip>>>,
}

const IPV4_DECODER: Ipv4Decoder = Ipv4Decoder {
    version: true,
    ihl: true,
    checksum: false,
    length: true,
    truncate: false,
};

const UDP_DECODER: Ipv4PayloadDecoder<UdpDecoder> = Ipv4PayloadDecoder {
    ip_next_protocol: true,
    dont_fragment: true,
    inner: UdpDecoder::UNCHECKED,
};

impl RoutingTable {
    pub fn get_route(&self, packet: &Ip) -> Option<&mpsc::Sender<Packet<Ip>>> {
        if self.table.is_empty() {
            return None;
        }

        let packet: &Ipv4 = IPV4_DECODER.decode_ref(packet).ok()?;
        let packet: &Ipv4<Udp> = UDP_DECODER.decode_ref(packet).ok()?;

        let remote = SocketAddrV4::new(
            packet.header.source(),
            packet.payload.header.source_port.get(),
        );

        let local = SocketAddrV4::new(
            packet.header.destination(),
            packet.payload.header.destination_port.get(),
        );

        let route = Route::UdpV4 { remote, local };

        self.table.get(&route).inspect(|_| {
            tracing::info!("using userspace route: remote={remote} -> local={local}");
        })
    }
}

impl UserspaceNet {
    pub fn connect_udp_v4(
        &mut self,
        local: SocketAddrV4,
        remote: SocketAddrV4,
    ) -> Option<UserspaceUdpV4> {
        let outgoing_tx = self.outgoing_tx.clone();
        let (incoming_tx, incoming_rx) = mpsc::channel(100);

        let route = Route::UdpV4 { local, remote };

        if self.routing_table.table.contains_key(&route) {
            return None;
        }

        self.routing_table.table.insert(route, incoming_tx);
        self.route_updates.send_replace(self.routing_table.clone());

        Some(UserspaceUdpV4 {
            route_updates: self.route_updates.clone(),
            local,
            remote,
            tx: outgoing_tx,
            rx: incoming_rx,
        })
    }
}

impl<Tx> UserspaceNetMuxerTx<Tx> {
    fn update_routing_table(&mut self) {
        match self.route_updates.has_changed() {
            Ok(false) => {}
            Ok(true) => self.routing_table = self.route_updates.borrow_and_update().clone(),
            Err(_) => {
                // UserspaceNet has been dropped, no point routing packets there.
                self.routing_table = Default::default();
            }
        }
    }
}

impl<Tx: IpSend> IpSend for UserspaceNetMuxerTx<Tx> {
    async fn send(&mut self, packet: Packet<Ip>) -> io::Result<()> {
        self.update_routing_table();
        if let Some(userspace_socket) = self.routing_table.get_route(&packet) {
            // Use try_send to avoid letting userspace sockets slow down real ones.
            // TODO: handle "receiver dropped" error?
            let _ = userspace_socket.try_send(packet);
        } else {
            self.inner.send(packet).await?;
        }
        Ok(())
    }
}

impl<Rx: IpRecv> IpRecv for UserspaceNetMuxerRx<Rx> {
    async fn recv<'a>(
        &'a mut self,
        pool: &mut PacketBufPool,
    ) -> io::Result<impl Iterator<Item = Packet<Ip>> + Send + 'a> {
        let userspace_rx = self.userspace_rx.recv().then(async |packet| match packet {
            Some(packet) => packet,
            None => pending().await,
        });

        select! {
            result = self.inner.recv(pool) => result.map(Either::Left),
            packet = userspace_rx => Ok(Either::Right(once(packet))),
        }
    }

    fn mtu(&self) -> super::MtuWatcher {
        self.inner.mtu()
    }
}

impl UserspaceUdpV4 {
    pub async fn send(&self, bytes: &[u8]) {
        let packet = create_ipv4_payload(
            *self.local.ip(),
            self.local.port(),
            *self.remote.ip(),
            self.remote.port(),
            bytes,
        );

        tracing::info!(
            "send packet from userspace local={} -> remote={}",
            self.local,
            self.remote
        );

        self.tx.send(packet.into()).await.unwrap();
    }

    pub async fn recv(&mut self) -> Packet<Ipv4<Udp>> {
        let packet = self.rx.recv().await.unwrap();
        packet
            .try_into_ipvx()
            .unwrap()
            .unwrap_left()
            .try_into_udp()
            .unwrap()
    }
}

/// Remove the route from the routing table
impl Drop for UserspaceUdpV4 {
    fn drop(&mut self) {
        let route = Route::UdpV4 {
            local: self.local,
            remote: self.remote,
        };
        self.route_updates.send_modify(|routing_table| {
            routing_table.table.remove(&route);
        });
    }
}
