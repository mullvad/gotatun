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
//!
//!
//! ## Regarding <https://mullvad.atlassian.net/wiki/spaces/PPS/pages/4285923358/DAITA+version+3>
//! ### 1. Restore support for keep-alive packets
//! I would prefer to completely disregard any non-data packets for DAITA. This would be
//! less intrusive help decouple DAITA from WireGuard.
//! Keepalives should thus be left as-is and not padded to constant packet size.

use std::{
    collections::VecDeque,
    net::SocketAddr,
    pin::pin,
    sync::{
        Arc, Weak,
        atomic::{self, AtomicU32, AtomicUsize},
    },
};

use crate::{
    device::hooks::Hooks,
    packet::{self, Ipv6Header, Packet, Wg, WgPacketType},
    udp::UdpSend,
};

use super::peer::Peer;
use futures::{FutureExt, future::Fuse};
use maybenot::{Framework, Machine, MachineId, TriggerAction, TriggerEvent};
use rand::RngCore;
use tokio::sync::{
    RwLock,
    mpsc::{self, error::TrySendError},
};
use tokio::time::Instant;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned, big_endian};

use tokio::sync::Mutex;

// TODO: get real MTU
const MTU: u16 = 1300;

// TODO: Pick a good number
const MAX_BLOCKED_PACKETS: usize = 256;

enum ErrorAction {
    Close,
    Ignore, // TODO: log error?
}

type Result<T> = std::result::Result<T, ErrorAction>;

pub struct DaitaHooks {
    event_tx: mpsc::UnboundedSender<TriggerEvent>,
    packet_count: Arc<PacketCount>,
    blocking_queue_tx: mpsc::Sender<(Packet, SocketAddr)>,
    blocking_state: Arc<RwLock<BlockingState>>, // TODO: Replace with `tokio::sync::watch`?
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
    pub fn new<M, R, US, P>(
        maybenot: Framework<M, R>,
        peer: Weak<Mutex<Peer>>,
        udp_send: US,
        packet_pool: packet::PacketBufPool,
    ) -> Self
    where
        Framework<M, R>: Send + 'static,
        US: UdpSend + Clone + 'static,
        M: AsRef<[Machine]> + Send + Sync + 'static,
        R: RngCore + Send + Sync,
    {
        let (event_tx, event_rx) = mpsc::unbounded_channel();
        let packet_count = Arc::new(PacketCount {
            outbound_normal: AtomicU32::new(0),
            replaced_normal: AtomicU32::new(0),
        });
        let blocking = Arc::new(RwLock::new(BlockingState::Inactive));
        let (blocking_queue_tx, blocking_queue_rx) = mpsc::channel(MAX_BLOCKED_PACKETS);
        let tx_padding_packet_bytes = Arc::new(AtomicUsize::new(0));

        let daita = DAITA {
            maybenot,
            peer,
            packet_pool,
            packet_count: packet_count.clone(),
            blocking_queue_rx,
            blocking_queue_tx: blocking_queue_tx.clone(),
            blocking: blocking.clone(),
            udp_send: udp_send.clone(),
            tx_padding_packet_bytes: tx_padding_packet_bytes.clone(),
        };
        // TODO abort on drop?
        tokio::spawn(daita.handle_events(event_rx));
        DaitaHooks {
            event_tx: event_tx.clone(),
            packet_count,
            blocking_queue_tx,
            blocking_state: blocking,
            tx_padding_bytes: 0,
            tx_padding_packet_bytes,
            rx_padding_bytes: 0,
            rx_padding_packet_bytes: 0,
        }
    }

    /// Should be called on outgoing data packets, before encapsulation
    pub fn before_data_encapsulate(&self, mut packet: Packet) -> Packet {
        let _ = self.event_tx.send(TriggerEvent::NormalSent);
        self.packet_count.inc_outbound(1);

        // Pad to constant size
        debug_assert!(packet.len() <= MTU as usize);
        // self.tx_padding_bytes += MTU as usize - packet.len(); // TODO

        packet.buf_mut().resize(MTU as usize, 0);
        packet
    }

    /// Should be called on packets, before they are sent to the network.
    pub fn after_data_encapsulate(
        &self,
        packet: Packet<Wg>,
        addr: SocketAddr,
    ) -> Option<(Packet<Wg>, SocketAddr)> {
        let packet_type = packet.packet_type;
        let packet = packet.into();

        // DAITA only cares about data packets.
        if packet_type != WgPacketType::Data {
            return Some((packet, addr));
        }

        if let Ok(blocking) = self.blocking_state.try_read()
            && blocking.is_active()
        {
            // Send the packet anyway if the blocking queue is full
            // TODO: this would be an out of order packet, not ideal.
            // We should probably trigger the blocking the end here and flush
            // the queue (don't forget to send `TriggerEvent::BlockingEnd`)
            // before sending the packet
            if let Err(TrySendError::Full((returned_packet, _addr))) =
                self.blocking_queue_tx.try_send((packet.into_bytes(), addr))
            {
                let _ = self.event_tx.send(TriggerEvent::TunnelSent);
                self.packet_count.dec(1);
                return Some((returned_packet.try_into_wg().unwrap(), addr));
            }
            None
        } else {
            let _ = self.event_tx.send(TriggerEvent::TunnelSent);
            self.packet_count.dec(1);
            Some((packet, addr))
        }
    }

    /// Should be called on incoming validated encapsulated packets.
    pub fn before_data_decapsulate(&self) {
        let _ = self.event_tx.send(TriggerEvent::TunnelRecv);
    }

    /// Should be called on incoming decapsulated *data* packets.
    pub fn after_data_decapsulate(&self, mut packet: Packet) -> Option<Packet> {
        if let Ok(padding) = PaddingPacket::ref_from_bytes(packet.as_bytes())
            && padding.header._daita_marker == DAITA_MARKER
        {
            let _ = self.event_tx.send(TriggerEvent::PaddingRecv);
            // Count received padding
            // self.rx_padding_packet_bytes += u16::from(padding.header.length) as usize; // TODO
            return None;
        }

        let _ = self.event_tx.send(TriggerEvent::NormalRecv);

        Some(packet)
    }
}

impl Hooks for DaitaHooks {
    fn before_data_encapsulate(&self, packet: Packet) -> Packet {
        // TODO: check peer
        DaitaHooks::before_data_encapsulate(self, packet)
    }

    fn after_data_encapsulate(
        &self,
        packet: Packet<packet::Wg>,
        destination: SocketAddr,
    ) -> Option<(Packet<Wg>, SocketAddr)> {
        // TODO: check peer
        DaitaHooks::after_data_encapsulate(self, packet, destination)
    }

    fn before_data_decapsulate(&self) {
        // TODO: check peer
        self.before_data_decapsulate();
    }

    fn after_data_decapsulate(&self, packet: Packet) -> Option<Packet> {
        // TODO: check peer
        self.after_data_decapsulate(packet)
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

#[derive(Clone, Copy)]
enum ActionTimerType {
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

#[derive(Clone, Copy)]
enum MachineTimer {
    Internal,
    Action(ActionTimerType),
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

    fn insert_padding(
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
                MachineTimer::Action(ActionTimerType::Padding { replace, bypass }),
            ),
        );
        debug_assert!(self.0.iter().is_sorted_by_key(|(time, _, _)| *time));
    }

    fn insert_block(
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
                MachineTimer::Action(ActionTimerType::Block {
                    replace,
                    bypass,
                    duration,
                }),
            ),
        );
        debug_assert!(self.0.iter().is_sorted_by_key(|(time, _, _)| *time));
    }

    fn update_internal(
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

pub struct DAITA<M, R, US>
where
    M: AsRef<[Machine]> + Send + 'static,
    R: RngCore,
    US: UdpSend + Clone + 'static,
{
    maybenot: Framework<M, R>,
    packet_count: Arc<PacketCount>,
    blocking_queue_rx: mpsc::Receiver<(Packet, SocketAddr)>,
    blocking_queue_tx: mpsc::Sender<(Packet, SocketAddr)>,
    blocking: Arc<RwLock<BlockingState>>,
    peer: Weak<Mutex<Peer>>,
    packet_pool: packet::PacketBufPool,
    udp_send: US,
    tx_padding_packet_bytes: Arc<AtomicUsize>,
}

impl<M, R, US> DAITA<M, R, US>
where
    M: AsRef<[Machine]> + Send + 'static,
    R: RngCore,
    US: UdpSend + Clone + 'static,
{
    pub async fn handle_events(mut self, mut event_rx: mpsc::UnboundedReceiver<TriggerEvent>) {
        let mut machine_timers = MachineTimers::new(self.maybenot.num_machines() * 2);

        let mut event_buf = Vec::new();
        let mut blocked_packets_buf = Vec::new();

        let mut blocking_ended = pin!(Fuse::terminated());

        loop {
            // TODO: Try refactoring this into a function, I dare you
            blocking_ended.set(
                if let BlockingState::Active { expires_at, .. } = &*self.blocking.read().await {
                    tokio::time::sleep_until(*expires_at).fuse()
                } else {
                    Fuse::terminated()
                },
            );
            futures::select! {
                _ = event_rx.recv_many(&mut event_buf, usize::MAX).fuse() => {
                    if event_buf.is_empty() {
                        return; // channel closed
                    }
                },
                _ = blocking_ended => {
                    self.end_blocking(&mut blocked_packets_buf, &mut event_buf).await;
                }
                _ = machine_timers.wait_next_timer().fuse() => {
                    let (machine, timer) = machine_timers.pop_next_timer().unwrap();
                    if let Err(ErrorAction::Close) = self.on_machine_timer(machine, timer, &mut machine_timers, &mut event_buf).await {
                        return
                    }
                }
            }
            loop {
                let actions = self
                    .maybenot
                    .trigger_events(event_buf.as_slice(), Instant::now().into()); // TODO: support mocked time?
                event_buf.clear(); // Clear immediately after use so we can add new events generated by actions
                for action in actions {
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
                            // TODO: optimize for timeout==0?
                            machine_timers.insert_padding(*machine, *timeout, *replace, *bypass);
                        }
                        TriggerAction::BlockOutgoing {
                            timeout,
                            duration,
                            bypass,
                            replace,
                            machine,
                        } => {
                            // TODO: optimize for timeout==0?
                            machine_timers
                                .insert_block(*machine, *timeout, *duration, *replace, *bypass);
                        }
                        TriggerAction::UpdateTimer {
                            duration,
                            replace,
                            machine,
                        } => {
                            // TODO: optimize for timeout==0?
                            if machine_timers.update_internal(*machine, *duration, *replace) {
                                event_buf.push(TriggerEvent::TimerBegin { machine: *machine });
                            }
                        }
                    }
                }
                // If no new events were generated by actions, break the loop
                if event_buf.is_empty() {
                    break;
                }
            }
        }
    }

    async fn on_machine_timer(
        &mut self,
        machine: MachineId,
        timer: MachineTimer,
        machine_timers: &mut MachineTimers,
        event_buf: &mut Vec<TriggerEvent>,
    ) -> Result<()> {
        match timer {
            MachineTimer::Action(action_type) => match action_type {
                ActionTimerType::Padding { replace, bypass } => {
                    self.handle_padding(machine, machine_timers, replace, bypass, event_buf)
                        .await?;
                }
                ActionTimerType::Block {
                    replace,
                    bypass,
                    duration,
                } => {
                    event_buf.push(TriggerEvent::BlockingBegin { machine });
                    let mut blocking = self.blocking.write().await;
                    let new_expiry = Instant::now() + duration;
                    match &mut *blocking {
                        BlockingState::Active { expires_at, .. }
                            if !replace && new_expiry <= *expires_at => {}
                        _ => {
                            *blocking = BlockingState::Active {
                                bypass,
                                expires_at: new_expiry,
                            };
                        }
                    }
                }
            },
            MachineTimer::Internal => {
                event_buf.push(TriggerEvent::TimerEnd { machine });
            }
        }
        Ok(())
    }

    async fn handle_padding(
        &mut self,
        machine: MachineId,
        machine_timers: &mut MachineTimers,
        replace: bool,
        padding_bypass: bool,
        event_buf: &mut Vec<TriggerEvent>,
    ) -> Result<()> {
        let blocking_with_bypass = match &*self.blocking.read().await {
            BlockingState::Inactive => None,
            BlockingState::Active {
                bypass: blocking_bypass,
                ..
            } => Some(*blocking_bypass && padding_bypass),
        };
        match (blocking_with_bypass, replace) {
            (Some(true), true) => {
                if let Ok((packet, destination)) = self.blocking_queue_rx.try_recv() {
                    self.udp_send
                        .send_to(packet.into_bytes(), destination)
                        .await
                        .unwrap();
                }
                self.send_padding(event_buf, machine).await
            }
            (Some(true), false) => self.send_padding(event_buf, machine).await,
            (Some(false), true)
                if self.packet_count.replaced()
                    < self.packet_count.outbound() + self.blocking_queue_rx.len() as u32 =>
            {
                self.packet_count.inc_replaced(1);
                machine_timers.remove_action(&machine);
                Ok(())
            }
            // Padding packet should or cannot replace any blocked packet
            (Some(false), _) => {
                let (padding_packet, addr) = self.encapsulate_padding(event_buf, machine).await?;
                //  Drop the padding packet if blocking queue is full
                let _ = self
                    .blocking_queue_tx
                    .try_send((padding_packet.into_bytes(), addr));
                Ok(())
            }
            (None, true) if self.packet_count.replaced() < self.packet_count.outbound() => {
                self.packet_count.inc_replaced(1);
                machine_timers.remove_action(&machine);
                Ok(())
            }
            (None, _) => self.send_padding(event_buf, machine).await,
        }
    }

    async fn end_blocking(
        &mut self,
        packets: &mut Vec<(Packet, SocketAddr)>,
        event_buf: &mut Vec<TriggerEvent>,
    ) {
        *self.blocking.write().await = BlockingState::Inactive;
        event_buf.push(TriggerEvent::BlockingEnd);
        loop {
            let limit = self.udp_send.max_number_of_packets_to_send();
            futures::select! {
                count = self.blocking_queue_rx.recv_many(packets, limit - packets.len()).fuse() => {
                    if count == 0 {
                        break; // channel closed
                    }
                },
                default => break, // Packet queue is empty
            }

            let mut send_many_bufs = US::SendManyBuf::default();
            let count = packets.len();
            if let Ok(()) = self
                .udp_send
                .send_many_to(&mut send_many_bufs, packets)
                .await
            {
                // Trigger a TunnelSent for each packet sent
                let sent = count - packets.len();
                event_buf.resize(event_buf.len() + sent, TriggerEvent::TunnelSent);
            }
        }
    }

    async fn send_padding(
        &self,
        event_buf: &mut Vec<TriggerEvent>,
        machine: MachineId,
    ) -> Result<()> {
        let (packet, addr) = self.encapsulate_padding(event_buf, machine).await?;

        self.udp_send
            .send_to(packet.into_bytes(), addr)
            .await
            .map_err(|_| ErrorAction::Close)?;

        // TODO: do not increase if handshake
        self.tx_padding_packet_bytes
            .fetch_add(MTU as usize, atomic::Ordering::SeqCst);
        event_buf.push(TriggerEvent::TunnelSent);
        Ok(())
    }

    // TODO: handle the case where handle_outgoing_packet returns a handshake
    async fn encapsulate_padding(
        &self,
        event_buf: &mut Vec<TriggerEvent>,
        machine: MachineId,
    ) -> Result<(Packet<Wg>, SocketAddr)> {
        let Some(peer) = self.peer.upgrade() else {
            return Err(ErrorAction::Close);
        };
        let mut peer = peer.lock().await;

        // TODO: Reuse the same padding packet each time (unless MTU changes)?
        event_buf.push(TriggerEvent::PaddingSent { machine });
        match peer
            .tunnel
            .handle_outgoing_packet(self.create_padding_packet(MTU))
        {
            None => Err(ErrorAction::Ignore), // TODO: error?
            Some(packet) => {
                let endpoint_addr = peer.endpoint().addr;
                let Some(addr) = endpoint_addr else {
                    log::error!("No endpoint");
                    return Err(ErrorAction::Ignore);
                };
                Ok((packet, addr))
            }
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
}
