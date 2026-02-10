// Copyright (c) 2025 Mullvad VPN AB. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use super::types::{DecoyPacket, PacketCount};
use crate::device::daita::DaitaSettings;
use crate::device::daita::actions::ActionHandler;
use crate::device::daita::events::handle_events;
use crate::device::daita::types::{self, DecoyMarker, DelayWatcher};
use crate::device::peer_state::PeerState;
use crate::packet::{self, Ip, WgData, WgKind};
use crate::task::Task;
use crate::udp::UdpSend;
use crate::{packet::Packet, tun::MtuWatcher};
use maybenot::TriggerEvent;
use rand::rngs::{OsRng, ReseedingRng};
use std::sync::atomic::AtomicUsize;
use std::sync::{Arc, Weak};
use tokio::sync::Mutex;
use tokio::sync::mpsc::{self};
use zerocopy::{FromBytes, IntoBytes, TryFromBytes};

/// Overhead induced by DAITA from decoy packets and constant packet size.
/// Exposed via [`crate::device::uapi::command::GetPeer`].
#[derive(Default)]
pub struct DaitaOverhead {
    /// Total extra bytes added due to constant-size padding of data packets.
    pub tx_padding_bytes: usize,
    // This is an AtomicUsize because it is updated from `ActionHandler`
    /// Bytes of decoy packets transmitted.
    pub tx_decoy_packet_bytes: Arc<AtomicUsize>,
    /// Total extra bytes removed due to constant-size padding of data packets.
    pub rx_padding_bytes: usize,
    /// Bytes of decoy packets received.
    pub rx_decoy_packet_bytes: usize,
}

/// DAITA (Defense Against AI-guided Traffic Analysis) hooks for packet processing.
///
/// The struct exposes a number of hooks for the data pipeline which add constant packet
/// size-padding, decoy packet generation, and packet delays according to the maybenot framework.
pub struct DaitaHooks {
    event_tx: mpsc::UnboundedSender<TriggerEvent>,
    packet_count: Arc<PacketCount>,
    delay_watcher: DelayWatcher,
    mtu: MtuWatcher,
    daita_overhead: DaitaOverhead,
    _actions_task: Task,
    _events_task: Task,
}

/// RNG used for DAITA. Same as maybenot-ffi.
///
/// This setup uses [`OsRng`] as the source of entropy, but extrapolates each call to [`OsRng`] into
/// at least [`RNG_RESEED_THRESHOLD`] bytes of randomness using [`rand_chacha::ChaCha12Core`].
///
/// This is the same Rng that [`rand::thread_rng`] uses internally,
/// but unlike `thread_rng`, this is Sync.
type Rng = ReseedingRng<rand_chacha::ChaCha12Core, OsRng>;
const RNG_RESEED_THRESHOLD: u64 = 1024 * 64; // 64 KiB

impl DaitaHooks {
    /// Create a new DAITA hooks instance.
    ///
    /// This initializes the maybenot framework with the provided settings and spawns
    /// background tasks to handle DAITA events and actions.
    ///
    /// # Errors
    ///
    /// Returns an error if the maybenot framework initialization fails.
    pub fn new<US>(
        daita_settings: DaitaSettings,
        peer: Weak<Mutex<PeerState>>,
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
            max_decoy_frac,
            max_delay_frac,
            max_delayed_packets,
            min_delay_capacity,
        } = daita_settings;
        log::info!("Initializing DAITA");
        log::debug!("Using maybenot machines: {maybenot_machines:?}");

        let (event_tx, event_rx) = mpsc::unbounded_channel();
        let (action_tx, action_rx) = mpsc::unbounded_channel();
        let packet_count = Arc::new(types::PacketCount::default());
        let daita_overhead = DaitaOverhead::default();

        let (delay_queue_tx, delay_queue_rx) = mpsc::channel(max_delayed_packets.into());
        let delay_watcher = DelayWatcher::new(delay_queue_tx, min_delay_capacity);

        let maybenot = maybenot::Framework::new(
            maybenot_machines,
            max_decoy_frac,
            max_delay_frac,
            std::time::Instant::now(),
            Rng::new(RNG_RESEED_THRESHOLD, OsRng).unwrap(),
        )?;

        let action_handler = ActionHandler::builder()
            .packet_count(packet_count.clone())
            .delay_queue_rx(delay_queue_rx)
            .delay_watcher(delay_watcher.clone())
            .peer(peer)
            .packet_pool(packet_pool)
            .udp_send_v4(udp_send_v4)
            .udp_send_v6(udp_send_v6)
            .mtu(mtu.clone())
            .tx_decoy_packet_bytes(daita_overhead.tx_decoy_packet_bytes.clone())
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
            delay_watcher,
            mtu,
            daita_overhead,
            _actions_task: actions_task,
            _events_task: events_task,
        })
    }

    /// Map an outgoing data packet before encapsulation, padding it to constant size.
    ///
    /// Note:
    /// Should not be called on keepalive packets (0-length data packets).
    /// They do not contain an IP header, thus they would become malformed if padded.
    pub fn before_data_encapsulate(&mut self, packet: Packet<Ip>) -> Packet {
        let _ = self.event_tx.send(TriggerEvent::NormalSent);
        self.packet_count.inc(1);

        let mtu = usize::from(self.mtu.get());
        let mut packet: Packet = packet.into();
        if let Ok(padded_bytes) = pad_to_constant_size(&mut packet, mtu) {
            self.daita_overhead.tx_padding_bytes += padded_bytes;
        }

        packet
    }

    /// Map an encapsulated packet, before it is sent to the network.
    ///
    /// Returns `None` to drop/ignore the packet, e.g. when it was queued for delay.
    /// Returns `Some(packet)` to send the packet.
    pub fn after_data_encapsulate(&self, packet: WgKind) -> Option<WgKind> {
        // DAITA only cares about data packets.
        let data_packet = match packet {
            WgKind::Data(packet) if packet.is_keepalive() => {
                return Some(packet.into());
            }
            WgKind::Data(packet) => packet,
            other => return Some(other),
        };

        self.delay_watcher
            .maybe_delay_packet(data_packet)
            .map(|packet| {
                let _ = self.event_tx.send(TriggerEvent::TunnelSent);
                self.packet_count.dec(1);
                packet.into()
            })
    }

    /// Inspect an incoming encapsulated data packet.
    pub fn before_data_decapsulate(&self, packet: &Packet<WgData>) {
        if !packet.is_keepalive() {
            let _ = self.event_tx.send(TriggerEvent::TunnelRecv);
        }
    }

    /// Should be called on incoming decapsulated *data* packets.
    pub fn after_data_decapsulate(&mut self, packet: Packet) -> Option<Packet> {
        if packet.is_empty() {
            // this is a keepalive packet, ignore it.
            return Some(packet);
        }

        // Check whether this is a DAITA decoy-packet.
        if let Ok(packet) = DecoyPacket::try_ref_from_bytes(packet.as_bytes()) {
            let DecoyMarker::Decoy = packet.header.marker;

            debug_assert_eq!(usize::from(packet.header.length), size_of_val(packet));

            // NOTE: maybenot calls these "padding" packets
            let _ = self.event_tx.send(TriggerEvent::PaddingRecv);

            // Count received decoy bytes
            self.daita_overhead.rx_decoy_packet_bytes += size_of_val(packet);

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

        // Add bytes padded due to constant-size. Use `next_multiple_of(16)` to avoid counting
        // WireGuard's default behaviour of rounding packet lengths up to a multiple of 16.
        self.daita_overhead.rx_padding_bytes +=
            packet.len().saturating_sub(ip_len.next_multiple_of(16));

        let _ = self.event_tx.send(TriggerEvent::NormalRecv);

        // Note: Not truncating the packet here, `try_into_ipvx` will do that later.

        Some(packet)
    }

    /// Get a reference to the DAITA overhead statistics.
    ///
    /// This includes overhead in bytes induced by constant packet size-padding and decoy packets
    /// for both transmission and reception.
    pub fn daita_overhead(&self) -> &DaitaOverhead {
        &self.daita_overhead
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
