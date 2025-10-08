//! # NOTES
//!
//! This is a work-in-progress implementation of DAITA version 3.
//!
//! ## TODO
//!
//! - Add (and log) error messages in the `ErrorAction::Ignore` variant (otherwise we might as well return `Ok(())` directly)
//! - Look over where `ErrorAction::Ignore` is used, and see if it makes sense to return `ErrorAction::Close` instead
//! - Remove debug logs, or lower their verbosity to TRACE
//! - Expose the `PaddingOverhead` stats to the daemon
//! - Support mocked time for tests (this is supported in other parts of GotaTun using `mock_instant` crate)
//! - Make sure that machines that include blocking actions are disabled, until we have tested blocking properly
//! - Test whether we can reliably replace padding packets with outgoing normal packets.
//! - Pick good numbers for `max_blocked_packets` and `min_blocking_capacity` so that the blocking queue doesn't
//!   fill to capacity.
//! - Test blocking with a real machine, ask Tobias for one
//! - Set `max_padding_frac` and `max_blocking_frac` from the daemon using the response of ephemeral peer API.

mod actions;
mod events;
mod hooks;
mod types;

pub use hooks::DaitaHooks;

use std::{
    str::FromStr,
    sync::{Arc, Weak},
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
use rand::rngs::{OsRng, ReseedingRng};
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
        mtu: LinkMtuWatcher,
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

        let machines = maybenot_machines
            .iter()
            .map(AsRef::as_ref)
            .map(Machine::from_str)
            .collect::<::core::result::Result<Vec<_>, _>>()?;

        let maybenot = maybenot::Framework::new(
            machines,
            max_padding_frac,
            max_blocking_frac,
            std::time::Instant::now(),
            Rng::new(RNG_RESEED_THRESHOLD, OsRng).unwrap(),
        )
        // FIXME: handle error (since machines are not guaranteed to be valid)
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
            event_tx: event_tx.downgrade(),
        };
        // TODO: Make sure that these tasks are properly closed
        // They should be, and seemingly are, from listening to closing of the channels they wrap
        // but consider also saving a handle to their tasks and awaiting their closing.
        tokio::spawn(action_handler.handle_actions(action_rx));
        tokio::spawn(handle_events(
            maybenot,
            event_rx,
            event_tx.downgrade(),
            action_tx,
        ));

        Ok(DaitaHooks {
            event_tx,
            packet_count,
            blocking_watcher,
            mtu,
            padding_overhead,
        })
    }
}
