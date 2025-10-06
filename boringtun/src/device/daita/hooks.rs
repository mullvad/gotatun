use super::types::{DAITA_MARKER, PacketCount, PaddingPacket};
use crate::device::daita::types::BlockingWatcher;
use crate::packet::{self, WgKind};
use crate::{
    packet::{Packet, Wg},
    tun::LinkMtuWatcher,
};
use maybenot::TriggerEvent;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use tokio::sync::mpsc::{self};
use zerocopy::{FromBytes, IntoBytes};

// TODO: Although this is included in `GetPeer`, it is not read anywhere yet.
// Add it to `Tunnel::get_tunnel_stats`?
/// Padding overhead statistics, exposed via [`crate::device::api::command::GetPeer`].
#[derive(Default)]
pub struct PaddingOverhead {
    /// Total extra bytes added due to constant-size padding of data packets.
    pub tx_padding_bytes: usize,
    // This is an AtomicUsize because it is updated from `ActionHandler`
    /// Bytes of standalone padding packets transmitted.
    pub tx_padding_packet_bytes: Arc<AtomicUsize>,
    /// Total extra bytes removed due to constant-size padding of data packets.
    pub rx_padding_bytes: usize,
    /// Bytes of standalone padding packets received.
    pub rx_padding_packet_bytes: usize,
}

pub struct DaitaHooks {
    pub(super) event_tx: mpsc::UnboundedSender<TriggerEvent>,
    pub(super) packet_count: Arc<PacketCount>,
    pub(super) blocking_watcher: BlockingWatcher,
    pub(super) mtu: LinkMtuWatcher,
    pub(crate) padding_overhead: PaddingOverhead,
}

impl DaitaHooks {
    /// Map an outgoing data packets before encapsulation, padding it to constant size.
    pub fn before_data_encapsulate(&mut self, mut packet: Packet) -> Packet {
        let _ = self.event_tx.send(TriggerEvent::NormalSent);
        self.packet_count.inc_outbound(1);

        let mtu = usize::from(self.mtu.get());

        if let Ok(padded_bytes) = pad_to_constant_size(&mut packet, mtu) {
            self.padding_overhead.tx_padding_bytes += padded_bytes;
        };

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
            Err(e) => {
                log::error!("{e}");
                self.packet_count.dec(1);
                return None;
            }
        };

        self.blocking_watcher
            .maybe_block_packet(data_packet)
            .map(|packet| {
                let _ = self.event_tx.send(TriggerEvent::TunnelSent);
                self.packet_count.dec(1);
                packet.into()
            })
    }

    /// Inspect an incoming encapsulated data packet.
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
            self.padding_overhead.rx_padding_packet_bytes += size_of_val(padding);
            return None;
        }

        let _ = self.event_tx.send(TriggerEvent::NormalRecv);

        // Inspect Ipv4/Ipv6 header to determine actual payload size
        let ip = packet::Ip::ref_from_bytes(&packet).ok()?;
        let ip_len = match ip.header.version() {
            4 => {
                let ipv4 = packet::Ipv4::<[u8]>::ref_from_bytes(&packet).ok()?;
                usize::from(ipv4.header.total_len.get())
            }
            6 => {
                let ipv6 = packet::Ipv6::<[u8]>::ref_from_bytes(&packet).ok()?;
                let payload_len = usize::from(ipv6.header.payload_length.get());
                payload_len + packet::Ipv6Header::LEN
            }
            _ => return None,
        };

        // Add bytes padded due to constant-size
        // TODO: Should we truncate the packet buffer here? It will
        // be done before handing it to the TUN device anyway, with more
        // safety checks.
        self.padding_overhead.rx_padding_bytes += packet.len() - ip_len;

        Some(packet)
    }
}

/// Pad packet to MTU size and return the amount of added bytes.
///
/// If the packet is already larger than MTU, and error is returned and the packet
/// is not modified.
fn pad_to_constant_size(packet: &mut Packet, mtu: usize) -> Result<usize, ()> {
    let start_len = packet.len();
    if start_len > mtu {
        if cfg!(debug_assertions) {
            log::warn!(
                "Packet size {start_len} exceeded MTU {mtu}. Either the TUN MTU changed, or there's a bug.",
            );
        }
        return Err(());
    }
    packet.buf_mut().resize(mtu, 0);
    let padding_bytes = mtu - start_len;
    Ok(padding_bytes)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::packet::{IpNextProtocol, Ipv4, Ipv6VersionTrafficFlow};
    use crate::packet::{Ipv6, Ipv6Header};
    use bytes::BytesMut;
    use std::net::Ipv4Addr;
    use std::net::Ipv6Addr;
    use zerocopy::{U16, U128};

    #[test]
    fn test_constant_packet_size_ipv4() {
        let start_len = 100;
        let mtu = 500;
        let mut packet = Packet::from_bytes(BytesMut::zeroed(start_len));
        let ip_packet = Ipv4::mut_from_bytes(&mut packet).unwrap();

        let ipv4_header = packet::Ipv4Header::new(
            Ipv4Addr::new(1, 1, 1, 1),
            Ipv4Addr::new(2, 2, 2, 2),
            IpNextProtocol::Udp,
            &ip_packet.payload,
        );
        ip_packet.header = ipv4_header;

        let padding_bytes = pad_to_constant_size(&mut packet, mtu).unwrap();
        assert_eq!(padding_bytes, mtu - start_len);

        let ip_packet = packet
            .try_into_ip()
            .unwrap()
            .try_into_ipvx()
            .unwrap()
            .unwrap_left();
        assert_eq!(size_of_val(ip_packet.as_bytes()), start_len);
    }

    #[test]
    fn test_constant_packet_size_ipv6() {
        let start_len = 120;
        let mtu = 600;
        let mut packet = Packet::from_bytes(BytesMut::zeroed(start_len));
        let ip_packet: &mut Ipv6<[u8]> = Ipv6::mut_from_bytes(&mut packet).unwrap();

        let ipv6_header = Ipv6Header {
            version_traffic_flow: Ipv6VersionTrafficFlow::new().with_version(6),
            payload_length: U16::new((start_len - Ipv6Header::LEN).try_into().unwrap()),
            next_header: IpNextProtocol::Udp,
            hop_limit: 64,
            source_address: U128::new(u128::from(Ipv6Addr::LOCALHOST)),
            destination_address: U128::new(u128::from(Ipv6Addr::LOCALHOST)),
        };

        ip_packet.header = ipv6_header;

        let padding_bytes = pad_to_constant_size(&mut packet, mtu).unwrap();
        assert_eq!(padding_bytes, mtu - start_len);

        let ip_packet = packet
            .try_into_ip()
            .unwrap()
            .try_into_ipvx()
            .unwrap()
            .unwrap_right();
        assert_eq!(size_of_val(ip_packet.as_bytes()), start_len);
    }
}
