use super::types::{DAITA_MARKER, PacketCount, PaddingPacket};
use crate::device::daita::types::BlockingWatcher;
use crate::packet::WgKind;
use crate::{
    packet::{Packet, Wg},
    tun::LinkMtuWatcher,
};
use maybenot::TriggerEvent;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use tokio::sync::mpsc::{self};
use zerocopy::{FromBytes, IntoBytes};

pub struct DaitaHooks {
    pub(super) event_tx: mpsc::UnboundedSender<TriggerEvent>,
    pub(super) packet_count: Arc<PacketCount>,
    pub(super) blocking_watcher: BlockingWatcher,
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
        // DAITA only cares about data packets.
        let data_packet = match packet.into_kind() {
            Ok(WgKind::Data(packet)) => packet,
            Ok(other) => return Some(other.into()),
            Err(_) => todo!(),
        };

        self.blocking_watcher
            .send_if_blocking(data_packet)
            .map(|packet| {
                let _ = self.event_tx.send(TriggerEvent::TunnelSent);
                self.packet_count.dec(1);
                packet.into()
            })
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
