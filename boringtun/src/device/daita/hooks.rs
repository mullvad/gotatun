use super::types::{PacketCount, PaddingPacket};
use crate::device::daita::DaitaSettings;
use crate::device::daita::actions::ActionHandler;
use crate::device::daita::events::handle_events;
use crate::device::daita::types::{self, BlockingWatcher, PaddingMarker};
use crate::device::peer::Peer;
use crate::packet::{self, WgKind};
use crate::task::Task;
use crate::udp::UdpSend;
use crate::{
    packet::{Packet, Wg},
    tun::MtuWatcher,
};
use maybenot::TriggerEvent;
use rand::rngs::{OsRng, ReseedingRng};
use std::sync::atomic::AtomicUsize;
use std::sync::{Arc, Weak};
use tokio::sync::Mutex;
use tokio::sync::mpsc::{self};
use zerocopy::{FromBytes, IntoBytes, TryFromBytes};

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
    event_tx: mpsc::UnboundedSender<TriggerEvent>,
    packet_count: Arc<PacketCount>,
    blocking_watcher: BlockingWatcher,
    mtu: MtuWatcher,
    padding_overhead: PaddingOverhead,
    _actions_task: Task,
    _events_task: Task,
}

/// RNG used for DAITA. Same as maybenot-ffi.
///
/// This setup uses [OsRng] as the source of entropy, but extrapolates each call to [OsRng] into
/// at least [RNG_RESEED_THRESHOLD] bytes of randomness using [rand_chacha::ChaCha12Core].
///
/// This is the same Rng that [rand::thread_rng] uses internally,
/// but unlike thread_rng, this is Sync.
type Rng = ReseedingRng<rand_chacha::ChaCha12Core, OsRng>;
const RNG_RESEED_THRESHOLD: u64 = 1024 * 64; // 64 KiB

impl DaitaHooks {
    pub fn new<US>(
        daita_settings: DaitaSettings,
        peer: Weak<Mutex<Peer>>,
        mtu: MtuWatcher,
        udp_send_v4: US,
        udp_send_v6: US,
        packet_pool: packet::PacketBufPool,
    ) -> Result<Self, crate::device::Error>
    where
        US: UdpSend + Clone + 'static,
    {
        let DaitaSettings {
            maybenot_machines,
            max_padding_frac,
            max_blocking_frac,
            max_blocked_packets,
            min_blocking_capacity,
        } = daita_settings;
        log::info!("Initializing DAITA with machines: {maybenot_machines:?}");

        let (event_tx, event_rx) = mpsc::unbounded_channel();
        let (action_tx, action_rx) = mpsc::unbounded_channel();
        let packet_count = Arc::new(types::PacketCount::default());
        let padding_overhead = PaddingOverhead::default();

        let (blocking_queue_tx, blocking_queue_rx) = mpsc::channel(max_blocked_packets);
        let blocking_watcher = BlockingWatcher::new(blocking_queue_tx, min_blocking_capacity);

        let maybenot = maybenot::Framework::new(
            maybenot_machines,
            max_padding_frac,
            max_blocking_frac,
            std::time::Instant::now(),
            Rng::new(RNG_RESEED_THRESHOLD, OsRng).unwrap(),
        )?;

        let action_handler = ActionHandler::builder()
            .packet_count(packet_count.clone())
            .blocking_queue_rx(blocking_queue_rx)
            .blocking_watcher(blocking_watcher.clone())
            .peer(peer.clone())
            .packet_pool(packet_pool.clone())
            .udp_send_v4(udp_send_v4.clone())
            .udp_send_v6(udp_send_v6.clone())
            .mtu(mtu.clone())
            .tx_padding_packet_bytes(padding_overhead.tx_padding_packet_bytes.clone())
            .event_tx(event_tx.downgrade())
            .build();

        let actions_task = Task::spawn(
            "DaitaHooks::handle_actions",
            action_handler.handle_actions(action_rx),
        );
        let weak_event_tx = event_tx.downgrade();
        let events_task = Task::spawn("DaitaHooks::handle_events", async move {
            handle_events(maybenot, event_rx, weak_event_tx, action_tx).await;
        });

        Ok(DaitaHooks {
            event_tx,
            packet_count,
            blocking_watcher,
            mtu,
            padding_overhead,
            _actions_task: actions_task,
            _events_task: events_task,
        })
    }

    /// Map an outgoing data packets before encapsulation, padding it to constant size.
    ///
    /// Must not be called on keepalive packets.
    pub fn before_data_encapsulate(&mut self, mut packet: Packet) -> Packet {
        let is_keepalive = packet.is_empty();
        if is_keepalive {
            if cfg!(debug_assertions) {
                // Keepalive packets are 0-length data packets.
                // They do not contain an IP header, thus they would become malformed if padded.
                panic!("before_data_encapsulate must not be called on keepalives");
            }

            return packet;
        }

        let _ = self.event_tx.send(TriggerEvent::NormalSent);
        self.packet_count.inc(1);

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
        if packet.is_empty() {
            // this is a keepalive packet, ignore it.
            return Some(packet);
        }

        // Check whether this is a DAITA padding-packet.
        if let Ok(packet) = PaddingPacket::try_ref_from_bytes(packet.as_bytes()) {
            let PaddingMarker::Padding = packet.header.marker;

            debug_assert_eq!(usize::from(packet.header.length), size_of_val(packet));

            let _ = self.event_tx.send(TriggerEvent::PaddingRecv);

            // Count received padding
            self.padding_overhead.rx_padding_packet_bytes += size_of_val(packet);

            return None;
        }

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
            _ => {
                // bad packet, let the normal packet parser deal with the error
                if cfg!(debug_assertions) {
                    log::debug!("Malformed IP packet");
                }
                return Some(packet);
            }
        };

        // Add bytes padded due to constant-size
        // TODO: If we start padding all wg payloads to be multiples of 16 bytes in length
        // as described in section 5.4.6 of the wg whitepaper, then this would count that too.
        // When done, just round `ip_len` up to the next multiple of 16.
        // self.padding_overhead.rx_padding_bytes += packet.len() - ip_len.next_multiple_of(16);
        self.padding_overhead.rx_padding_bytes += packet.len() - ip_len;

        let _ = self.event_tx.send(TriggerEvent::NormalRecv);

        // Note: Not truncating the packet here, `try_into_ipvx` will do that later.

        Some(packet)
    }

    pub fn padding_overhead(&self) -> &PaddingOverhead {
        &self.padding_overhead
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

        let ip_packet = packet.try_into_ipvx().unwrap().unwrap_left();
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

        let ip_packet = packet.try_into_ipvx().unwrap().unwrap_right();
        assert_eq!(size_of_val(ip_packet.as_bytes()), start_len);
    }
}
