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
//! - Implement correct hooks in the packet pipeline. The methods on [DaitaHooks] describe where they
//!   should be injected. They need to operate on data packets for a particular peer, and need to have
//!   the ability to mutate the packet (constant packet size) or withhold it (blocking).
//! - Make encapsulation/decapsulation concurrent with IO.
//!   The maybenot spec describes that outbound packet (i.e. those that have been received on the tunnel
//!   interface but not yet sent on the network) can replace padding packets. However, currently there
//!   are no `await`-points in `handle_outgoing` that would allow this to happen, I think.
//!   Lacking the ability to replace padding packets with in-flight packets would be a regression
//!   in comparison with the `wireguard-go` implementation. As far as I remember, this occurred quite
//!   often, so it could be important for performance.
//! - The [crate::noise::Tunn] type already has a concept for a queue of blocked packets. Consider how this
//!   should interact/integrate with the blocking queue used by DAITA.
//! - Tests and benches
//! - Track MTU changes from somewhere. In wg-go, there is an atomic variable in `Tun` that updates in realized
//!   with MTU changes, that we use.
//! - The is from the spec of "SendPadding" action:
//!  > The replace flag determines if the padding packet MAY be replaced by a packet already queued to be sent
//!  > at the time the padding packet would be sent. This applies for data queued to be turned into normal
//!  > (non-padding) packets AND any packet (padding or normal) in the egress queue yet to be sent (i.e.,
//!  > before the TunnelSent event is triggered). Such a packet could be in the queue due to ongoing blocking
//!  > or just not being sent yet (e.g., due to CC). We assume that packets will be encrypted ASAP for the
//!  > egress queue and we do not want to keep state around to distinguish padding and non-padding, hence, any
//!  > packet. Similarly, this implies that a single blocked packet in the egress queue can replace multiple
//!  > padding packets with the replace flag set.
//!
//!   We currently down't allow padding packets to replace other padding packets, or a single blocked packet
//!   to replace multiple padding packets
//!
//! ## Regarding <https://mullvad.atlassian.net/wiki/spaces/PPS/pages/4285923358/DAITA+version+3>
//! ### 1. Restore support for keep-alive packets
//! I would prefer to completely disregard any non-data packets for DAITA. This would be
//! less intrusive help decouple DAITA from WireGuard.
//! Keepalives should thus be left as-is and not padded to constant packet size.

use std::{
    collections::VecDeque,
    pin::pin,
    str::FromStr,
    sync::{
        Arc, Weak,
        atomic::{self, AtomicU32, AtomicUsize},
    },
};

use crate::{
    device::hooks::Hooks,
    packet::{self, Packet, Wg, WgPacketType},
    tun::LinkMtuWatcher,
    udp::UdpSend,
};

use super::peer::Peer;
use futures::{FutureExt, future::Fuse};
use maybenot::{Framework, Machine, MachineId, TriggerAction, TriggerEvent};
use rand::{RngCore, SeedableRng, rngs::StdRng};
use tokio::sync::{
    Mutex, Notify, RwLock,
    mpsc::{self, error::TrySendError},
};
use tokio::time::Instant;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned, big_endian};

// TODO: Pick a good number
/// Max number of blocked packets.
const MAX_BLOCKED_PACKETS: usize = 256;
// TODO: Pick a good number
/// When the capacity of the blocking queue get's lower that this value, the blocking is aborted.
const MIN_BLOCKING_CAPACITY: usize = 20;

enum ErrorAction {
    Close,
    Ignore, // TODO: log error?
}

type Result<T> = std::result::Result<T, ErrorAction>;

pub struct DaitaHooks {
    event_tx: mpsc::UnboundedSender<TriggerEvent>,
    packet_count: Arc<PacketCount>,
    blocking_queue_tx: mpsc::Sender<Packet<Wg>>,
    blocking_state: Arc<RwLock<BlockingState>>, // TODO: Replace with `tokio::sync::watch`?
    blocking_abort: Arc<Notify>,
    mtu: LinkMtuWatcher,
    // TODO: Export to metrics sink
    /// Total extra bytes added due to constant-size padding of data packets.
    tx_padding_bytes: usize,
    /// Bytes of standalone padding packets transmitted.
    tx_padding_packet_bytes: Arc<AtomicUsize>,
    /// Total extra bytes removed due to constant-size padding of data packets.
    rx_padding_bytes: usize,
    /// Bytes of standalone padding packets received.
    rx_padding_packet_bytes: usize,
}

impl DaitaHooks {
    pub fn new<US>(
        maybenot_machines: Vec<String>,
        peer: Weak<Mutex<Peer>>,
        mtu: LinkMtuWatcher,
        udp_send: US,
        packet_pool: packet::PacketBufPool,
    ) -> Self
    where
        US: UdpSend + Clone + 'static,
    {
        log::info!("Initializing DAITA with machines: {maybenot_machines:?}");

        let (event_tx, event_rx) = mpsc::unbounded_channel();
        let (action_tx, action_rx) = mpsc::unbounded_channel();
        let packet_count = Arc::new(PacketCount {
            outbound_normal: AtomicU32::new(0),
            replaced_normal: AtomicU32::new(0),
        });
        let blocking = Arc::new(RwLock::new(BlockingState::Inactive));
        let (blocking_queue_tx, blocking_queue_rx) = mpsc::channel(MAX_BLOCKED_PACKETS);
        let tx_padding_packet_bytes = Arc::new(AtomicUsize::new(0));
        let blocking_abort = Arc::new(Notify::const_new());

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

        let daita = DAITA {
            peer,
            packet_pool,
            packet_count: packet_count.clone(),
            blocking_queue_rx,
            blocking_queue_tx: blocking_queue_tx.clone(),
            blocking_abort: blocking_abort.clone(),
            blocking: blocking.clone(),
            udp_send: udp_send.clone(),
            mtu: mtu.clone(),
            tx_padding_packet_bytes: tx_padding_packet_bytes.clone(),
            event_tx: event_tx.clone().downgrade(),
        };
        // TODO abort on drop?
        tokio::spawn(daita.handle_actions(action_rx));
        tokio::spawn(handle_events(
            maybenot,
            event_rx,
            event_tx.clone().downgrade(),
            action_tx,
        ));
        DaitaHooks {
            event_tx: event_tx.clone(),
            packet_count,
            blocking_queue_tx,
            blocking_state: blocking,
            blocking_abort,
            mtu,
            tx_padding_bytes: 0,
            tx_padding_packet_bytes,
            rx_padding_bytes: 0,
            rx_padding_packet_bytes: 0,
        }
    }

    /// Should be called on outgoing data packets, before encapsulation
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

    /// Should be called on packets, before they are sent to the network.
    pub fn after_data_encapsulate(&self, packet: Packet<Wg>) -> Option<Packet<Wg>> {
        let packet_type = packet.packet_type;

        // DAITA only cares about data packets.
        if packet_type != WgPacketType::Data {
            return Some(packet);
        }

        if let Ok(blocking) = self.blocking_state.try_read()
            && blocking.is_active()
        {
            if self.blocking_queue_tx.capacity() < MIN_BLOCKING_CAPACITY {
                self.blocking_abort.notify_one();
            }
            if let Err(TrySendError::Full(returned_packet)) =
                self.blocking_queue_tx.try_send(packet)
            {
                // Send the packet anyway if the blocking queue is full
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
            self.rx_padding_packet_bytes += u16::from(padding.header.length) as usize; // TODO
            return None;
        }

        let _ = self.event_tx.send(TriggerEvent::NormalRecv);

        Some(packet)
    }
}

impl Hooks for DaitaHooks {
    fn before_data_encapsulate(&mut self, packet: Packet) -> Packet {
        DaitaHooks::before_data_encapsulate(self, packet)
    }

    fn after_data_encapsulate(&self, packet: Packet<packet::Wg>) -> Option<Packet<Wg>> {
        DaitaHooks::after_data_encapsulate(self, packet)
    }

    fn before_data_decapsulate(&self) {
        DaitaHooks::before_data_decapsulate(self);
    }

    fn after_data_decapsulate(&mut self, packet: Packet) -> Option<Packet> {
        DaitaHooks::after_data_decapsulate(self, packet)
    }
}

#[derive(FromBytes, KnownLayout, Unaligned, Immutable, PartialEq, Eq)]
#[repr(C)]
struct PaddingPacket {
    header: PaddingHeader,
    payload: [u8],
}

#[derive(FromBytes, IntoBytes, KnownLayout, Unaligned, Immutable, PartialEq, Eq, Clone, Copy)]
#[repr(C, packed)]
struct PaddingHeader {
    pub _daita_marker: u8, // Must be `DAITA_MARKER`
    pub _reserved: u8,
    pub length: big_endian::U16,
}

const DAITA_MARKER: u8 = 0xFF;

#[derive(Clone, Copy, Debug)]
enum Action {
    Padding {
        replace: bool,
        bypass: bool,
    },
    Block {
        replace: bool,
        bypass: bool,
        duration: std::time::Duration,
    },
}

#[derive(Clone, Copy, Debug)]
enum MachineTimer {
    Internal,
    Action(Action),
}

/// Counter for the number of normal packets that have been received on the tunnel interface
/// but not yet sent to the network, and the number of those packets that have replaced
/// padding packets.
///
/// TODO: Is `Relaxed` atomic ordering fine?
struct PacketCount {
    outbound_normal: AtomicU32,
    replaced_normal: AtomicU32,
}

impl PacketCount {
    fn dec(&self, amount: u32) {
        self.replaced_normal
            .fetch_update(atomic::Ordering::Relaxed, atomic::Ordering::Relaxed, |x| {
                Some(x.saturating_sub(amount))
            })
            .ok();
        self.outbound_normal
            .fetch_sub(amount, atomic::Ordering::Relaxed);
    }

    fn inc_outbound(&self, amount: u32) {
        self.outbound_normal
            .fetch_add(amount, atomic::Ordering::Relaxed);
    }

    fn inc_replaced(&self, amount: u32) {
        self.replaced_normal
            .fetch_add(amount, atomic::Ordering::Relaxed);
    }

    fn outbound(&self) -> u32 {
        self.outbound_normal.load(atomic::Ordering::Relaxed)
    }

    fn replaced(&self) -> u32 {
        self.replaced_normal.load(atomic::Ordering::Relaxed)
    }
}

enum BlockingState {
    Inactive,
    Active { bypass: bool, expires_at: Instant },
}

impl BlockingState {
    /// Returns `true` if the blocking is [`Active`].
    ///
    /// [`Active`]: Blocking::Active
    #[must_use]
    fn is_active(&self) -> bool {
        matches!(self, Self::Active { .. })
    }
}

/// Queue of timers for each machine.
///
/// Use [`MachineTimers::wait_next_timer`] to wait for the next time expiration.
// INVARIANT: VecDeque is sorted by Instant, which represents the time of expiration.
// INVARIANT: Only one internal and one action timer per machine can exist at a time.
struct MachineTimers(VecDeque<(Instant, MachineId, MachineTimer)>);

impl MachineTimers {
    fn new(cap: usize) -> Self {
        Self(VecDeque::with_capacity(cap))
    }

    fn remove_action(&mut self, machine: &MachineId) {
        self.0
            .retain(|&(_, m, t)| !(m == *machine && matches!(t, MachineTimer::Action(_))));
    }

    fn remove_internal(&mut self, machine: &MachineId) {
        self.0
            .retain(|&(_, m, t)| !(m == *machine && matches!(t, MachineTimer::Internal)));
    }

    fn remove_all(&mut self, machine: &MachineId) {
        self.0.retain(|&(_, m, _)| m != *machine);
    }

    fn schedule_padding(
        &mut self,
        machine: MachineId,
        timeout: std::time::Duration,
        replace: bool,
        bypass: bool,
    ) {
        self.remove_action(&machine);
        let expiration_time = Instant::now() + timeout;
        let insert_at = self
            .0
            .binary_search_by_key(&expiration_time, |&(time, _, _)| time)
            .unwrap_or_else(|e| e);
        self.0.insert(
            insert_at,
            (
                expiration_time,
                machine,
                MachineTimer::Action(Action::Padding { replace, bypass }),
            ),
        );
        debug_assert!(self.0.iter().is_sorted_by_key(|(time, _, _)| *time));
    }

    fn schedule_block(
        &mut self,
        machine: MachineId,
        timeout: std::time::Duration,
        duration: std::time::Duration,
        replace: bool,
        bypass: bool,
    ) {
        self.remove_action(&machine);
        let expiration_time = Instant::now() + timeout;
        let insert_at = self
            .0
            .binary_search_by_key(&expiration_time, |&(time, _, _)| time)
            .unwrap_or_else(|e| e);
        self.0.insert(
            insert_at,
            (
                expiration_time,
                machine,
                MachineTimer::Action(Action::Block {
                    replace,
                    bypass,
                    duration,
                }),
            ),
        );
        debug_assert!(self.0.iter().is_sorted_by_key(|(time, _, _)| *time));
    }

    fn schedule_internal_timer(
        &mut self,
        machine: MachineId,
        duration: std::time::Duration,
        replace: bool,
    ) -> bool {
        let expiry = Instant::now() + duration;
        let idx = self
            .0
            .iter()
            .position(|&(_, m, t)| m == machine && matches!(t, MachineTimer::Internal));
        let should_update = match idx {
            Some(i) => {
                let (cur_expiry, _, _) = self.0[i];
                if replace || expiry > cur_expiry {
                    self.0.remove(i);
                    true
                } else {
                    false
                }
            }
            None => true,
        };
        if should_update {
            let insert_at = self
                .0
                .binary_search_by_key(&expiry, |&(time, _, _)| time)
                .unwrap_or_else(|e| e);
            self.0
                .insert(insert_at, (expiry, machine, MachineTimer::Internal));
            debug_assert!(self.0.iter().is_sorted_by_key(|(time, _, _)| *time));
        }
        should_update
    }

    /// Wait until the next timer expires. Afterwards, use
    /// [`MachineTimers::pop_next_timer`] to get the expired timer.
    async fn wait_next_timer(&mut self) {
        if let Some((time, _, _)) = self.0.front() {
            tokio::time::sleep_until(*time).await;
        } else {
            futures::future::pending().await
        }
    }

    fn pop_next_timer(&mut self) -> Option<(MachineId, MachineTimer)> {
        self.0.pop_front().map(|(_, m, t)| (m, t))
    }
}

async fn handle_events<M, R>(
    mut maybenot: Framework<M, R>,
    mut event_rx: mpsc::UnboundedReceiver<TriggerEvent>,
    event_tx: mpsc::WeakUnboundedSender<TriggerEvent>,
    action_tx: mpsc::UnboundedSender<(Action, MachineId)>,
) -> Option<()>
// TODO: return type is meaningless and only there to allow `?` operator
where
    M: AsRef<[Machine]> + Send + 'static,
    R: RngCore,
{
    let mut machine_timers = MachineTimers::new(maybenot.num_machines() * 2);
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

pub struct DAITA<US>
where
    US: UdpSend + Clone + 'static,
{
    packet_count: Arc<PacketCount>,
    blocking_queue_rx: mpsc::Receiver<Packet<Wg>>,
    blocking_queue_tx: mpsc::Sender<Packet<Wg>>,
    blocking_abort: Arc<Notify>,
    blocking: Arc<RwLock<BlockingState>>,
    peer: Weak<Mutex<Peer>>,
    packet_pool: packet::PacketBufPool,
    udp_send: US,
    mtu: LinkMtuWatcher,
    tx_padding_packet_bytes: Arc<AtomicUsize>,
    event_tx: mpsc::WeakUnboundedSender<TriggerEvent>,
}

impl<US> DAITA<US>
where
    US: UdpSend + Clone + 'static,
{
    async fn handle_actions(
        mut self,
        mut actions: mpsc::UnboundedReceiver<(Action, MachineId)>,
    ) -> Result<()> {
        let mut blocking_timer = pin!(Fuse::terminated());
        let mut blocked_packets_buf = Vec::new();

        loop {
            blocking_timer.set(
                // TODO: Try refactoring this into a function, I dare you
                if let BlockingState::Active { expires_at, .. } = &*self.blocking.read().await {
                    log::debug!("DAITA: Blocking active, expires at {:?}", expires_at);
                    tokio::time::sleep_until(*expires_at).fuse()
                } else {
                    Fuse::terminated()
                },
            );

            futures::select! {
                _ = blocking_timer => {
                    log::debug!("DAITA: Blocking ended, flushing blocked packets");
                    self.end_blocking(&mut blocked_packets_buf).await?;
                }
                _ = self.blocking_abort.notified().fuse() => {
                    log::debug!("DAITA: Blocking was aborted due to overfull buffer capacity, flushing blocked packets");
                    self.end_blocking(&mut blocked_packets_buf).await?;
                }
                res = actions.recv().fuse() => {
                    let Some((action, machine)) = res else {
                        log::debug!("DAITA: actions channel closed, exiting handle_actions");
                        break; // TODO: flush blocked packets?
                    };
                    match action {
                        Action::Padding { replace, bypass } => {
                            self.handle_padding(machine, replace, bypass).await?;
                        }
                        Action::Block { replace, bypass, duration } => {
                            self.send_event(TriggerEvent::BlockingBegin { machine })?;
                            let mut blocking = self.blocking.write().await;
                            let new_expiry = Instant::now() + duration;
                            match &mut *blocking {
                                BlockingState::Active { expires_at, .. } if !replace && new_expiry <= *expires_at => {
                                    log::debug!("Current blocking was not replaced");
                                }
                                _ => {
                                    *blocking = BlockingState::Active { bypass, expires_at: new_expiry };
                                    log::debug!("Blocking started");
                                }
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// Send a padding packet according to [`TriggerAction::SendPadding`].
    async fn handle_padding(
        &mut self,
        machine: MachineId,
        replace: bool,
        padding_bypass: bool,
    ) -> Result<()> {
        self.send_event(TriggerEvent::PaddingSent { machine })?;

        let blocking_with_bypass = match &*self.blocking.read().await {
            BlockingState::Inactive => None,
            BlockingState::Active {
                bypass: blocking_bypass,
                ..
            } => Some(*blocking_bypass && padding_bypass), // Both must be true to bypass
        };

        match (blocking_with_bypass, replace) {
            (Some(true), true) => {
                if let Ok(packet) = self.blocking_queue_rx.try_recv() {
                    // self.send_event(TriggerEvent::NormalSent)?; // TODO: Already sent when queued, unclear spec
                    log::debug!("Padding packet was replaced by blocked packet which was sent");
                    let peer = self.get_peer().await?;
                    self.send(packet, peer).await?;
                }
                log::debug!("Padding packet could not be replaced by blocked packet and was sent");
                self.send_padding().await
            }
            (Some(true), false) => {
                log::debug!("Padding packet was sent bypassing blocking");
                self.send_padding().await
            }
            (Some(false), true)
                if self.packet_count.replaced()
                    < self.packet_count.outbound() + self.blocking_queue_rx.len() as u32 =>
            {
                log::debug!("Padding packet was replaced by blocked data packet and dropped");
                self.packet_count.inc_replaced(1);
                Ok(())
            }
            // Padding packet should or cannot be replaced by a blocked packet, so we must added it to the blocking queue
            (Some(false), _) => {
                log::debug!("Padding packet was added to blocking queue");
                let mut peer = self.get_peer().await?;
                let mtu = self.mtu.get();
                let padding_packet = self.encapsulate_padding(&mut peer, mtu).await?;
                //  Drop the padding packet if blocking queue is full
                let _ = self.blocking_queue_tx.try_send(padding_packet);
                Ok(())
            }
            (None, true) if self.packet_count.replaced() < self.packet_count.outbound() => {
                log::debug!("Padding packet was replaced by in-flight data packet and dropped");
                self.packet_count.inc_replaced(1);
                Ok(())
            }
            (None, _) => {
                log::debug!("Padding packet was sent");
                self.send_padding().await
            }
        }
    }

    async fn end_blocking(&mut self, packets: &mut Vec<Packet<Wg>>) -> Result<()> {
        let Some(addr) = self.get_peer().await?.endpoint().addr else {
            log::error!("No endpoint");
            return Err(ErrorAction::Close);
        };

        let mut blocking = true;
        loop {
            let limit = self.udp_send.max_number_of_packets_to_send();
            futures::select! {
                count = self.blocking_queue_rx.recv_many(packets, limit - packets.len()).fuse() => {
                    if count == 0 {
                        break Err(ErrorAction::Close); // channel closed
                    }
                },
                // Packet queue is empty
                default => {
                    // When the packet queue is empty, we can end blocking.
                    // To prevent new packets from sneaking into the queue before we set the state to Inactive,
                    // we loop once more and flush any new packets that might have arrived.
                    if blocking {
                        *self.blocking.write().await = BlockingState::Inactive;
                        self.send_event(TriggerEvent::BlockingEnd)?;
                        blocking = false;
                    }  else {
                        return Ok(());
                    }

                },
            }

            let mut send_many_bufs = US::SendManyBuf::default();
            // TODO: don't allocate (update send_many_to to take iterator?)
            let mut packets: Vec<_> = packets.drain(..).map(|p| (p.into_bytes(), addr)).collect();
            let count = packets.len();
            if let Ok(()) = self
                .udp_send
                .send_many_to(&mut send_many_bufs, &mut packets)
                .await
            {
                // Trigger a TunnelSent for each packet sent
                let sent = count - packets.len();
                let event_tx = self.event_tx.upgrade().ok_or(ErrorAction::Close)?;
                for _ in 0..sent {
                    event_tx
                        .send(TriggerEvent::TunnelSent)
                        .map_err(|_| ErrorAction::Close)?;
                }
            }
        }
    }

    // TODO: handle the case where handle_outgoing_packet returns a handshake
    async fn encapsulate_padding(
        &self,
        peer: &mut tokio::sync::OwnedMutexGuard<Peer>,
        mtu: u16,
    ) -> Result<Packet<Wg>> {
        // TODO: Reuse the same padding packet each time (unless MTU changes)?
        match peer
            .tunnel
            .handle_outgoing_packet(self.create_padding_packet(mtu))
        {
            None => Err(ErrorAction::Ignore), // TODO: error?
            Some(packet) => Ok(packet),
        }
    }

    fn create_padding_packet(&self, mtu: u16) -> Packet {
        let padding_packet_header = PaddingHeader {
            _daita_marker: 0xFF,
            _reserved: 0,
            length: mtu.into(),
        };
        let mut padding_packet_buf = self.packet_pool.get();
        padding_packet_buf.buf_mut().clear();
        padding_packet_buf
            .buf_mut()
            .extend_from_slice(padding_packet_header.as_bytes());
        padding_packet_buf.buf_mut().resize(mtu.into(), 0);
        padding_packet_buf
    }

    async fn send_padding(&mut self) -> Result<()> {
        let mtu = self.mtu.get();
        let mut peer = self.get_peer().await?;

        let packet = self.encapsulate_padding(&mut peer, mtu).await?;
        self.send(packet, peer).await?;
        Ok(())
    }

    async fn send(
        &self,
        packet: Packet<Wg>,
        peer: tokio::sync::OwnedMutexGuard<Peer>,
    ) -> Result<()> {
        let endpoint_addr = peer.endpoint().addr;
        let Some(addr) = endpoint_addr else {
            log::trace!("No endpoint");
            return Err(ErrorAction::Ignore);
        };
        self.udp_send
            .send_to(packet.into_bytes(), addr)
            .await
            .map_err(|_| ErrorAction::Close)?;
        // self.tx_padding_packet_bytes
        //     .fetch_add(MTU as usize, atomic::Ordering::SeqCst);
        self.send_event(TriggerEvent::TunnelSent)?;
        Ok(())
    }

    async fn get_peer(&self) -> Result<tokio::sync::OwnedMutexGuard<Peer>> {
        let Some(peer) = self.peer.upgrade() else {
            return Err(ErrorAction::Close);
        };
        let peer = peer.lock_owned().await;
        Ok(peer)
    }

    fn send_event(&self, event: TriggerEvent) -> Result<()> {
        self.event_tx
            .upgrade()
            .ok_or(ErrorAction::Close)?
            .send(event)
            .map_err(|_| ErrorAction::Close)
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use crate::packet::PacketBufPool;

    use super::*;

    #[derive(Clone)]
    struct DummyUdpSend;

    impl UdpSend for DummyUdpSend {
        type SendManyBuf = ();
        fn max_number_of_packets_to_send(&self) -> usize {
            10
        }
        async fn send_many_to<'a>(
            &'a self,
            _send_buf: &mut Self::SendManyBuf,
            _packets: &mut Vec<(Packet, SocketAddr)>,
        ) -> std::io::Result<()> {
            Ok(())
        }

        async fn send_to(&self, _packet: Packet, _destination: SocketAddr) -> std::io::Result<()> {
            Ok(())
        }
    }

    // fn make_hooks() -> DaitaHooks {
    //     let peer = Arc::new(Mutex::new(Peer::dummy()));
    //     let udp_send = DummyUdpSend;
    //     let packet_pool = PacketBufPool::new(10);
    //     DaitaHooks::new(
    //         vec!["machine1".to_string()],
    //         Arc::downgrade(&peer),
    //         udp_send,
    //         packet_pool,
    //     )
    // }

    #[test]
    fn test_packet_count_concurrent() {
        let pc = PacketCount {
            outbound_normal: AtomicU32::new(0),
            replaced_normal: AtomicU32::new(0),
        };
        std::thread::scope(|s| {
            for _ in 0..500 {
                s.spawn(|| {
                    pc.inc_outbound(2);
                    pc.inc_replaced(1);
                    pc.dec(2);
                });
            }
        });
        assert_eq!(pc.outbound(), 0);
        assert_eq!(pc.replaced(), 0);
    }

    #[test]
    fn test_machine_timers_schedule_and_remove() {
        let mut timers = MachineTimers::new(4);
        let machine = MachineId::from_raw(1);
        timers.schedule_padding(machine, std::time::Duration::from_secs(1), false, false);
        assert_eq!(timers.0.len(), 1);
        timers.schedule_internal_timer(machine, std::time::Duration::from_secs(1), false);
        assert_eq!(timers.0.len(), 2);
        timers.remove_action(&machine);
        assert_eq!(timers.0.len(), 1);
        timers.remove_internal(&machine);
        assert_eq!(timers.0.len(), 0);
    }

    #[test]
    fn test_internal_machine_timer_replace() {
        let mut timers = MachineTimers::new(4);
        let machine = MachineId::from_raw(1);

        timers.schedule_internal_timer(machine, std::time::Duration::from_secs(1), false);
        timers.schedule_internal_timer(machine, std::time::Duration::from_secs(2), false);
        assert_eq!(timers.0.len(), 1);
        let (i, _, t) = timers.0.front().unwrap();
        assert!(matches!(t, MachineTimer::Internal));
        assert!(i.duration_since(Instant::now()) > std::time::Duration::from_secs(1));
    }

    // #[tokio::test]
    // async fn test_hooks_before_after_data_encapsulate() {
    //     let mut hooks = make_hooks();
    //     let packet = Packet::dummy();
    //     let packet = hooks.before_data_encapsulate(packet);
    //     let wg_packet = Packet::<Wg>::dummy_with_type(WgPacketType::Data);
    //     let result = hooks.after_data_encapsulate(wg_packet);
    //     assert!(result.is_some());
    // }

    // #[tokio::test]
    // async fn test_hooks_after_data_decapsulate_padding() {
    //     let mut hooks = make_hooks();
    //     // Create a fake padding packet
    //     let mut packet = Packet::dummy();
    //     let header = PaddingHeader {
    //         _daita_marker: DAITA_MARKER,
    //         _reserved: 0,
    //         length: 10u16.into(),
    //     };
    //     packet.buf_mut().clear();
    //     packet.buf_mut().extend_from_slice(header.as_bytes());
    //     packet.buf_mut().resize(10, 0);
    //     let result = hooks.after_data_decapsulate(packet);
    //     assert!(result.is_none());
    // }

    // #[tokio::test]
    // async fn test_hooks_after_data_decapsulate_normal() {
    //     let mut hooks = make_hooks();
    //     let packet = Packet::dummy();
    //     let result = hooks.after_data_decapsulate(packet);
    //     assert!(result.is_some());
    // }
}
