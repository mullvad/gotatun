use crate::packet::{Packet, Wg};

pub trait Hooks: Send + Sync + 'static {
    /// Called before a data packet is encapsulated
    #[inline(always)]
    fn before_data_encapsulate(&self, packet: Packet) -> Packet {
        packet
    }

    /// Called after a data packet is encapsulated
    ///
    /// Return `None` to drop/ignore the packet
    #[inline(always)]
    fn after_data_encapsulate(&self, packet: Packet<Wg>) -> Option<Packet<Wg>> {
        Some(packet) // noop
    }

    /// Called before a data packet is decapsulated
    /// But after validating the packet
    #[inline(always)]
    fn before_data_decapsulate(&self) {}

    /// Called after a data packet is decapsulated
    ///
    /// Return `None` to drop/ignore the packet
    #[inline(always)]
    fn after_data_decapsulate(&self, packet: Packet) -> Option<Packet> {
        Some(packet) // noop
    }
}

// TODO: `NoopHooks`
impl Hooks for () {}
