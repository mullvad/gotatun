use std::net::SocketAddr;

use crate::{
    device::peer::Peer,
    packet::{Ip, Packet, Wg},
};

pub trait Hooks {
    /// Called before a data packet is encapsulated
    #[inline(always)]
    fn before_data_encapsulate(peer: &Peer, packet: Packet<Ip>) -> Packet {
        let _ = peer;
        packet.into() // noop
    }

    #[inline(always)]
    fn before_wg_send(packet: Packet<Wg>, destination: SocketAddr) -> (Packet<Wg>, SocketAddr) {
        (packet, destination) // noop
    }

    #[inline(always)]
    fn after_wg_recv(packet: Packet<Wg>, destination: SocketAddr) -> (Packet<Wg>, SocketAddr) {
        (packet, destination) // noop
    }

    #[inline(always)]
    fn after_data_decapsulate(
        peer: &Peer,
        packet: Packet,
        source: SocketAddr,
    ) -> (Packet, SocketAddr) {
        let _ = peer;
        (packet, source) // noop
    }
}
