use std::net::SocketAddr;

use crate::{
    device::peer::Peer,
    packet::{Ip, Packet, Wg},
};

pub trait Hooks: Send + Sync {
    /// Called before a data packet is encapsulated
    #[inline(always)]
    fn before_data_encapsulate(&self, peer: &Peer, packet: Packet<Ip>) -> Packet {
        let _ = peer;
        packet.into() // noop
    }

    #[inline(always)]
    fn before_wg_send(
        &self,
        packet: Packet<Wg>,
        destination: SocketAddr,
    ) -> (Packet<Wg>, SocketAddr) {
        (packet, destination) // noop
    }

    #[inline(always)]
    fn after_wg_recv(
        &self,
        packet: Packet<Wg>,
        destination: SocketAddr,
    ) -> (Packet<Wg>, SocketAddr) {
        (packet, destination) // noop
    }

    #[inline(always)]
    fn after_data_decapsulate(&self, peer: &Peer, packet: Packet) -> Option<Packet> {
        let _ = peer;
        Some(packet) // noop
    }
}

impl Hooks for () {}
