//! # NOTES
//!
//! This is a work-in-progress implementation of DAITA version 3.
//!
//! The intent of the design is that DAITA will exist in the app-repo (i.e. this module will not
//! be part of boringtun proper) and that it will be possible inject DAITA as a set of hooks/plugins
//! into boringtun.
//!
//! ## TODO
//!
//! - Make encapsulation/decapsulation concurrent with IO.
//!   The maybenot spec describes that outbound packet (i.e. those that have been received on the tunnel
//!   interface but not yet sent on the network) can replace padding packets. However, currently there
//!   are no `await`-points in `handle_outgoing` that would allow this to happen, I think.
//!   Lacking the ability to replace padding packets with in-flight packets would be a regression
//!   in comparison with the `wireguard-go` implementation. As far as I remember, this occurred quite
//!   often, so it could be important for performance.
//!     - Test whether we can replace egress packets.
//! - Tests and benches
//!     - LinkMtuWatcher
//! - The is from the spec of "SendPadding" action:
//!  > The replace flag determines if the padding packet MAY be replaced by a packet already queued to be sent
//!  > at the time the padding packet would be sent. This applies for data queued to be turned into normal
//!  > (non-padding) packets AND any packet (padding or normal) in the egress queue yet to be sent (i.e.,
//!  > before the TunnelSent event is triggered). Such a packet could be in the queue due to ongoing blocking
//!  > or just not being sent yet (e.g., due to CC). We assume that packets will be encrypted ASAP for the
//!  > egress queue and we do not want to keep state around to distinguish padding and non-padding, hence, any
//!  > packet. Similarly, this implies that a single blocked packet in the egress queue can replace multiple
//!  > padding packets with the replace flag set.
//!     - Ask Tobias about his stance on this
//! - Pick a good number for `MAX_BLOCKED_PACKETS` and `allowed_blocked_microsec` so that the blocking queue doesn'T
//!   fill to capacity.
//! - Test blocking with a real machine, ask Tobias for one
//! - Set `max_padding_frac` and `max_blocking_frac` from the daemon
//!
//!   We currently down't allow padding packets to replace other padding packets, or a single blocked packet
//!   to replace multiple padding packets
//!
//! ## Regarding <https://mullvad.atlassian.net/wiki/spaces/PPS/pages/4285923358/DAITA+version+3>
//! ### 1. Restore support for keep-alive packets
//! I would prefer to completely disregard any non-data packets for DAITA. This would be
//! less intrusive help decouple DAITA from WireGuard.
//! Keepalives should thus be left as-is and not padded to constant packet size.

mod actions;
mod events;
mod hooks;
mod types;

pub use hooks::DaitaHooks;

use std::{
    str::FromStr,
    sync::{Arc, Weak, atomic::AtomicU32},
};

use crate::{
    device::daita::{
        actions::ActionHandler, events::handle_events, hooks::PaddingOverhead,
        types::BlockingWatcher,
    },
    packet,
    tun::LinkMtuWatcher,
    udp::UdpSend,
};

use super::peer::Peer;
use maybenot::Machine;
use rand::{SeedableRng, rngs::StdRng};
use tokio::sync::{Mutex, mpsc};

pub struct DaitaSettings {
    /// The maybenot machines to use.
    pub maybenot_machines: Vec<String>,
    /// Maximum fraction of bandwidth that may be used for padding packets.
    pub max_padding_frac: f64,
    /// Maximum fraction of bandwidth that may be used for blocking packets.
    pub max_blocking_frac: f64,
    /// Maximum number of packets that may be blocked at any time.
    pub max_blocked_packets: usize,
    /// Minimum number of free slots in the blocking queue to continue blocking.
    pub min_blocking_capacity: usize,
}

impl DaitaHooks {
    pub fn new<US>(
        daita_settings: DaitaSettings,
        peer: Weak<Mutex<Peer>>,
        mtu: LinkMtuWatcher,
        udp_send_v4: US,
        udp_send_v6: US,
        packet_pool: packet::PacketBufPool,
    ) -> Self
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
        let packet_count = Arc::new(types::PacketCount {
            outbound_normal: AtomicU32::new(0),
            replaced_normal: AtomicU32::new(0),
        });
        let padding_overhead = PaddingOverhead::default();

        let (blocking_queue_tx, blocking_queue_rx) = mpsc::channel(max_blocked_packets);
        let blocking_watcher = BlockingWatcher::new(blocking_queue_tx, min_blocking_capacity);

        let machines = maybenot_machines
            .iter()
            .map(AsRef::as_ref)
            .map(Machine::from_str)
            .collect::<::core::result::Result<Vec<_>, _>>()
            .unwrap_or_else(|_| panic!("bad machines: {maybenot_machines:?}")); // TODO

        let rng = StdRng::from_os_rng(); // TODO

        let maybenot = maybenot::Framework::new(
            machines,
            max_padding_frac,
            max_blocking_frac,
            std::time::Instant::now(),
            rng,
        )
        .unwrap();

        let action_handler = ActionHandler {
            peer,
            packet_pool,
            packet_count: packet_count.clone(),
            blocking_queue_rx,
            blocking_watcher: blocking_watcher.clone(),
            udp_send_v4: udp_send_v4.clone(),
            udp_send_v6: udp_send_v6.clone(),
            mtu: mtu.clone(),
            tx_padding_packet_bytes: padding_overhead.tx_padding_packet_bytes.clone(),
            event_tx: event_tx.clone().downgrade(),
        };
        // TODO: Make sure that these tasks are properly closed
        // They should be, and seemingly are, from listening to closing of the channels they wrap
        // but consider also saving a handle to their tasks and awaiting their closing.
        tokio::spawn(action_handler.handle_actions(action_rx));
        tokio::spawn(handle_events(
            maybenot,
            event_rx,
            event_tx.clone().downgrade(),
            action_tx,
        ));

        DaitaHooks {
            event_tx: event_tx.clone(),
            packet_count,
            blocking_watcher,
            mtu,
            padding_overhead,
        }
    }
}
