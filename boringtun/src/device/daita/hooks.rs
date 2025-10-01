use super::MIN_BLOCKING_CAPACITY;
use super::types::{BlockingState, DAITA_MARKER, PacketCount, PaddingPacket};
use crate::{
    packet::{self, Packet, Wg, WgPacketType},
    tun::LinkMtuWatcher,
};
use maybenot::TriggerEvent;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use tokio::sync::{
    Notify, RwLock,
    mpsc::{self, error::TrySendError},
};
use zerocopy::{FromBytes, IntoBytes};

pub struct DaitaHooks {
    pub(super) event_tx: mpsc::UnboundedSender<TriggerEvent>,
    pub(super) packet_count: Arc<PacketCount>,
    pub(super) blocking_queue_tx: mpsc::Sender<Packet<Wg>>,
    pub(super) blocking_state: Arc<RwLock<BlockingState>>, // TODO: Replace with `tokio::sync::watch`?
    pub(super) blocking_abort: Arc<Notify>,
    pub(super) mtu: LinkMtuWatcher,
    // TODO: Export to metrics sink
    /// Total extra bytes added due to constant-size padding of data packets.
    pub(super) tx_padding_bytes: usize,
    /// Bytes of standalone padding packets transmitted.
    pub(super) tx_padding_packet_bytes: Arc<AtomicUsize>,
    /// Total extra bytes removed due to constant-size padding of data packets.
    pub(super) rx_padding_bytes: usize,
    /// Bytes of standalone padding packets received.
    pub(super) rx_padding_packet_bytes: usize,
}

impl DaitaHooks {
    /// Map an outgoing data packets before encapsulation, padding it to constant size.
    pub fn before_data_encapsulate(&mut self, mut packet: Packet) -> Packet {
        let _ = self.event_tx.send(TriggerEvent::NormalSent);
        self.packet_count.inc_outbound(1);

        let mtu = usize::from(self.mtu.get());

        if packet.len() > mtu {
            if cfg!(debug_assertions) {
                log::warn!(
                    "Packet size exceeded MTU. Either the TUN MTU changed, or there's a bug."
                );
            }
            return packet;
        }

        // Pad to constant size
        self.tx_padding_bytes += mtu - packet.len();
        packet.buf_mut().resize(mtu, 0);
        packet
    }

    /// Map an encapsulated packet, before they it is sent to the network.
    ///
    /// Returns `None` to drop/ignore the packet, e.g. when it was queued for blocking.
    /// Returns `Some(packet)` to send the packet.
    pub fn after_data_encapsulate(&self, packet: Packet<Wg>) -> Option<Packet<Wg>> {
        let packet_type = packet.packet_type;

        // DAITA only cares about data packets.
        if packet_type != WgPacketType::Data {
            return Some(packet);
        }

        if let Ok(blocking) = self.blocking_state.try_read()
            && blocking.is_active()
        {
            // Notify the blocking handler to abort blocking when the capacity is low
            if self.blocking_queue_tx.capacity() < MIN_BLOCKING_CAPACITY {
                self.blocking_abort.notify_one();
            }
            if let Err(TrySendError::Full(returned_packet)) =
                self.blocking_queue_tx.try_send(packet)
            {
                // If the queue is full, we can't block anymore, so we
                // send the packet anyway.
                // TODO: this would be an out of order packet, not ideal.
                // Should we drop the packet instead?
                let _ = self.event_tx.send(TriggerEvent::TunnelSent);
                self.packet_count.dec(1);
                return Some(returned_packet);
            }
            None
        } else {
            let _ = self.event_tx.send(TriggerEvent::TunnelSent);
            self.packet_count.dec(1);
            Some(packet)
        }
    }

    /// Should be called on incoming validated encapsulated packets.
    pub fn before_data_decapsulate(&self) {
        let _ = self.event_tx.send(TriggerEvent::TunnelRecv);
    }

    /// Should be called on incoming decapsulated *data* packets.
    pub fn after_data_decapsulate(&mut self, packet: Packet) -> Option<Packet> {
        if let Ok(padding) = PaddingPacket::ref_from_bytes(packet.as_bytes())
            && padding.header._daita_marker == DAITA_MARKER
        {
            let _ = self.event_tx.send(TriggerEvent::PaddingRecv);

            // Count received padding
            self.rx_padding_packet_bytes += size_of_val(padding);
            return None;
        }

        // TODO: Inspect Ipv4/Ipv6 header to determine actual payload size
        // self.rx_padding_bytes += packet.len() - packet.payload_len();
        let _ = self.event_tx.send(TriggerEvent::NormalRecv);

        Some(packet)
    }
}
