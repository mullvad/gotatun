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
mod hooks;

pub use hooks::DaitaHooks;

use std::{
    str::FromStr,
    sync::{
        Arc, Weak,
        atomic::{AtomicU32, AtomicUsize},
    },
};

use crate::{
    device::daita::{
        actions::ActionHandler,
        types::{BlockingWatcher, MachineTimer},
    },
    packet,
    tun::LinkMtuWatcher,
    udp::UdpSend,
};

use super::peer::Peer;
use futures::FutureExt;
use maybenot::{Framework, Machine, MachineId, TriggerAction, TriggerEvent};
use rand::{RngCore, SeedableRng, rngs::StdRng};
use tokio::sync::{Mutex, mpsc};
use tokio::time::Instant;

// TODO: Pick a good number
/// Max number of blocked packets.
const MAX_BLOCKED_PACKETS: usize = 256;
// TODO: Pick a good number
/// When the capacity of the blocking queue get's lower that this value, the blocking is aborted.
const MIN_BLOCKING_CAPACITY: usize = 20;

mod types;

impl DaitaHooks {
    pub fn new<US>(
        maybenot_machines: Vec<String>,
        peer: Weak<Mutex<Peer>>,
        mtu: LinkMtuWatcher,
        udp_send_v4: US,
        udp_send_v6: US,
        packet_pool: packet::PacketBufPool,
    ) -> Self
    where
        US: UdpSend + Clone + 'static,
    {
        log::info!("Initializing DAITA with machines: {maybenot_machines:?}");

        let (event_tx, event_rx) = mpsc::unbounded_channel();
        let (action_tx, action_rx) = mpsc::unbounded_channel();
        let packet_count = Arc::new(types::PacketCount {
            outbound_normal: AtomicU32::new(0),
            replaced_normal: AtomicU32::new(0),
        });
        let tx_padding_packet_bytes = Arc::new(AtomicUsize::new(0));

        let (blocking_queue_tx, blocking_queue_rx) = mpsc::channel(MAX_BLOCKED_PACKETS);
        let blocking_watcher = BlockingWatcher::new(blocking_queue_tx);

        let machines = maybenot_machines
            .iter()
            .map(AsRef::as_ref)
            .map(Machine::from_str)
            .collect::<::core::result::Result<Vec<_>, _>>()
            .unwrap_or_else(|_| panic!("bad machines: {maybenot_machines:?}")); // TODO

        let rng = StdRng::from_os_rng(); // TODO

        let max_padding_frac = 0.5; // TODO
        let max_blocking_frac = 0.5; // TODO
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
            tx_padding_packet_bytes: tx_padding_packet_bytes.clone(),
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
            tx_padding_bytes: 0,
            tx_padding_packet_bytes,
            rx_padding_bytes: 0,
            rx_padding_packet_bytes: 0,
        }
    }
}

async fn handle_events<M, R>(
    mut maybenot: Framework<M, R>,
    mut event_rx: mpsc::UnboundedReceiver<TriggerEvent>,
    event_tx: mpsc::WeakUnboundedSender<TriggerEvent>,
    action_tx: mpsc::UnboundedSender<(types::Action, MachineId)>,
) -> Option<()>
// TODO: return type is meaningless and only there to allow `?` operator
where
    M: AsRef<[Machine]> + Send + 'static,
    R: RngCore,
{
    let mut machine_timers = types::MachineTimers::new(maybenot.num_machines() * 2);
    let mut event_buf = Vec::new();

    loop {
        futures::select! {
            _ = event_rx.recv_many(&mut event_buf, usize::MAX).fuse() => {
                log::debug!("DAITA: Received events {:?}", event_buf);
                if event_buf.is_empty() {
                    log::debug!("DAITA: event_rx channel closed, exiting handle_events");
                    return None; // channel closed
                }
            },
            _ = machine_timers.wait_next_timer().fuse() => {
                let (machine, timer) = machine_timers.pop_next_timer().unwrap();
                log::debug!("DAITA: Timer expired {:?} for machine {:?}", timer, machine);
                match timer {
                    MachineTimer::Action(action_type) => action_tx
                        .send((action_type, machine))
                        .ok(),
                    MachineTimer::Internal => event_tx
                        .upgrade()?
                        .send(TriggerEvent::TimerEnd { machine })
                        .ok(),
                }?;
                continue;
            }
        }
        let actions = maybenot.trigger_events(event_buf.as_slice(), Instant::now().into()); // TODO: support mocked time?
        event_buf.clear();
        for action in actions {
            log::debug!("DAITA: TriggerAction: {:?}", action);
            match action {
                TriggerAction::Cancel { machine, timer } => match timer {
                    maybenot::Timer::Action => machine_timers.remove_action(machine),
                    maybenot::Timer::Internal => machine_timers.remove_internal(machine),
                    maybenot::Timer::All => machine_timers.remove_all(machine),
                },
                TriggerAction::SendPadding {
                    timeout,
                    bypass,
                    replace,
                    machine,
                } => {
                    machine_timers.schedule_padding(*machine, *timeout, *replace, *bypass);
                }
                TriggerAction::BlockOutgoing {
                    timeout,
                    duration,
                    bypass,
                    replace,
                    machine,
                } => {
                    machine_timers.schedule_block(*machine, *timeout, *duration, *replace, *bypass);
                }
                TriggerAction::UpdateTimer {
                    duration,
                    replace,
                    machine,
                } => {
                    if machine_timers.schedule_internal_timer(*machine, *duration, *replace) {
                        event_tx
                            .upgrade()?
                            .send(TriggerEvent::TimerBegin { machine: *machine })
                            .ok()?;
                    }
                }
            }
        }
    }
}
