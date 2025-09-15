//! # NOTES
//!
//! ## TODO
//! - Constant packet size
//! - Implement correct hooks
//!   - Currently, `TunnelSent` is triggered on all outgoing packets, not just data packets.
//!   - Handle incoming packets and their non-ip header correctly.
//! - Add overhead counters (see point 3 below)
//!     - `tx_padding_bytes`, `tx_padding_packet_bytes`
//! - Upper limit for blocking.
//! - Consider using the existing packet queue instead of the separate channel solution for blocked packets.
//! - Tests and benches
//!
//!
//! ## Regarding <https://mullvad.atlassian.net/wiki/spaces/PPS/pages/4285923358/DAITA+version+3>
//! ### 1. Restore support for keep-alive packets
//! I would prefer to completely disregard any non-data packets for DAITA. This would be
//! less intrusive help decouple DAITA from WireGuard.
//! Keepalives should thus be left as-is and not padded to constant packet size.
//!
//! ### 2. Ensure counters for sent/received bytes are symmetrical
//! Should be handled by the hooks.
//!
//! ### 3. Measure overhead on the wire
//! Should be possible with the hooks.
//!
//! ### 4. Ensure DAITA padding packet header is being processed correctly
//! Not an issue.
//!
//! ### 5. Add support for Maybenot BlockOutgoing action in the client
//! Is implemented, but not the upper limit.

use std::{
    collections::VecDeque,
    net::SocketAddr,
    ops::Deref,
    pin::pin,
    sync::{
        Arc, Weak,
        atomic::{self, AtomicU32},
    },
};

use crate::{
    noise::{self, TunnResult},
    packet::Packet,
    tun::IpRecv,
    udp::UdpSend,
};

use super::peer::Peer;
use futures::{FutureExt, future::Fuse};
use maybenot::{Framework, Machine, MachineId, TriggerAction, TriggerEvent};
use rand::RngCore;
use tokio::sync::{RwLock, mpsc};
use tokio::time::Instant;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned, big_endian};

use tokio::sync::Mutex;

// TODO: get real MTU
const MTU: u16 = 1300;

enum ErrorAction {
    Close,
    Ignore,
}

type Result<T> = std::result::Result<T, ErrorAction>;

pub fn get_daita_hooks<M, R, IR, US, P>(
    maybenot: Framework<M, R>,
    peer: Weak<Mutex<P>>,
    ip_recv: IR,
    udp_send: US,
    packet_pool: crate::packet::PacketBufPool,
) -> DaitaPeer<P>
where
    Framework<M, R>: Send + 'static,
    IR: IpRecv,
    US: UdpSend + Clone + 'static,
    M: AsRef<[Machine]> + Send + 'static,
    R: RngCore,
    P: TunnelCapsule + Sync + Send,
{
    let (event_tx, event_rx) = mpsc::unbounded_channel();
    let packet_count = Arc::new(PacketCount {
        outbound: AtomicU32::new(0),
        replaced: AtomicU32::new(0),
    });
    let blocking = Arc::new(RwLock::new(Blocking::Inactive));
    let (blocking_queue_tx, blocking_queue_rx) = mpsc::unbounded_channel();

    let daita = DAITA {
        maybenot,
        padding_sender: PaddingSender::new(peer.clone(), packet_pool, udp_send.clone()), // TODO: Real MTU
        packet_count: packet_count.clone(),
        blocking_queue_rx,
        blocking: blocking.clone(),
        udp_send: udp_send.clone(),
    };
    tokio::spawn(daita.handle_events(event_rx));
    DaitaPeer {
        inner: peer,
        event_tx: event_tx.clone(),
        packet_count,
        blocking_queue_tx,
        blocking,
    }
}

#[derive(FromBytes, IntoBytes, KnownLayout, Unaligned, Immutable, PartialEq, Eq)]
#[repr(C)]
struct PaddingPacket<Payload: ?Sized = [u8]> {
    header: PaddingHeader,
    payload: Payload,
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

struct PacketCount {
    outbound: AtomicU32,
    replaced: AtomicU32,
}

impl PacketCount {
    fn sub(&self, amount: u32) {
        self.replaced
            .fetch_update(atomic::Ordering::SeqCst, atomic::Ordering::SeqCst, |x| {
                if x >= amount {
                    Some(x - amount)
                } else {
                    Some(0)
                }
            })
            .ok();
        self.outbound.fetch_sub(amount, atomic::Ordering::SeqCst);
        // TODO: Ordering?
    }

    fn inc_outbound(&self) {
        self.outbound.fetch_add(1, atomic::Ordering::SeqCst);
    }

    fn inc_replaced(&self) {
        self.replaced.fetch_add(1, atomic::Ordering::SeqCst);
    }

    fn outbound(&self) -> u32 {
        self.outbound.load(atomic::Ordering::SeqCst)
    }

    fn replaced(&self) -> u32 {
        self.replaced.load(atomic::Ordering::SeqCst)
    }
}

enum Blocking {
    Inactive,
    Active { bypass: bool, expires_at: Instant },
}

impl Blocking {
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

pub struct DAITA<M, R, P, US>
where
    M: AsRef<[Machine]> + Send + 'static,
    R: RngCore,
    P: TunnelCapsule,
    US: UdpSend + Clone + 'static,
{
    maybenot: Framework<M, R>,
    padding_sender: PaddingSender<P, US>,
    packet_count: Arc<PacketCount>,
    blocking_queue_rx: mpsc::UnboundedReceiver<(Packet, SocketAddr)>,
    blocking: Arc<RwLock<Blocking>>,
    udp_send: US,
}

impl<M, R, P, US> DAITA<M, R, P, US>
where
    M: AsRef<[Machine]> + Send + 'static,
    R: RngCore,
    P: TunnelCapsule,
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
                if let Blocking::Active { expires_at, .. } = &*self.blocking.read().await {
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
                    self.on_machine_timer(machine, timer, &mut machine_timers, &mut event_buf).await;
                }
            }
            loop {
                let actions = self
                    .maybenot
                    .trigger_events(event_buf.as_slice(), std::time::Instant::now()); // TODO: support mocked time?
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
                            machine_timers.insert_padding(*machine, *timeout, *replace, *bypass);
                        }
                        TriggerAction::BlockOutgoing {
                            timeout,
                            duration,
                            bypass,
                            replace,
                            machine,
                        } => {
                            machine_timers
                                .insert_block(*machine, *timeout, *duration, *replace, *bypass);
                        }
                        TriggerAction::UpdateTimer {
                            duration,
                            replace,
                            machine,
                        } => {
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
    ) {
        match timer {
            MachineTimer::Action(action_type) => match action_type {
                ActionTimerType::Padding { replace, bypass } => {
                    // TODO: Double check the spec for when to trigger these?
                    // What about if the padding is blocked or fails to send?
                    event_buf.push(TriggerEvent::PaddingSent { machine });
                    self.handle_padding(machine, machine_timers, replace, bypass)
                        .await
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
                        Blocking::Active { expires_at, .. }
                            if !replace && new_expiry <= *expires_at => {}
                        _ => {
                            *blocking = Blocking::Active {
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
    }

    async fn handle_padding(
        &mut self,
        machine: MachineId,
        machine_timers: &mut MachineTimers,
        replace: bool,
        padding_bypass: bool,
    ) {
        let blocking_with_bypass = match &*self.blocking.read().await {
            Blocking::Inactive => None,
            Blocking::Active {
                bypass: blocking_bypass,
                ..
            } => Some(*blocking_bypass && padding_bypass),
        };
        match (blocking_with_bypass, replace) {
            (Some(true), true) => {
                if let Ok((packet, destination)) = self.blocking_queue_rx.try_recv() {
                    self.udp_send.send_to(packet, destination).await.unwrap();
                } else if let Err(ErrorAction::Close) = self.padding_sender.send_padding().await {
                    return;
                }
            }
            (Some(true), false) => {
                if let Err(ErrorAction::Close) = self.padding_sender.send_padding().await {
                    return;
                }
            }
            (Some(false), true)
                if self.packet_count.replaced()
                    < self.packet_count.outbound() + self.blocking_queue_rx.len() as u32 =>
            {
                self.packet_count.inc_replaced();
                machine_timers.remove_action(&machine);
                return;
            }
            // Padding packet should or cannot replace any blocked packet
            (Some(false), _) => {
                // TODO: Generate a padding packing and add it to the blocking queue
            }
            (None, true) if self.packet_count.replaced() < self.packet_count.outbound() => {
                self.packet_count.inc_replaced();
                machine_timers.remove_action(&machine);
                return;
            }
            (None, _) => {
                if let Err(ErrorAction::Close) = self.padding_sender.send_padding().await {
                    return;
                }
            }
        };
        self.packet_count.inc_outbound();
    }

    async fn end_blocking(
        &mut self,
        packets: &mut Vec<(Packet, SocketAddr)>,
        event_buf: &mut Vec<TriggerEvent>,
    ) {
        *self.blocking.write().await = Blocking::Inactive;
        event_buf.push(TriggerEvent::BlockingEnd);
        loop {
            let limit = self.udp_send.max_number_of_packets_to_send();
            packets.clear();
            futures::select! {
                count = self.blocking_queue_rx.recv_many(packets, limit).fuse() => {
                    if count == 0 {
                        break; // channel closed
                    }
                },
                complete => break, // No more packets to receive
            }

            let mut send_many_bufs = US::SendManyBuf::default();
            // Trigger a TunnelSent for each packet sent
            event_buf.resize(event_buf.len() + packets.len(), TriggerEvent::TunnelSent);
            self.udp_send
                .send_many_to(&mut send_many_bufs, packets)
                .await
                .unwrap();
        }
    }
}

// TODO: unclear purpose of this type
struct PaddingSender<P, US>
where
    US: UdpSend + Clone + 'static,
    P: TunnelCapsule,
{
    peer: Weak<Mutex<P>>,
    packet_pool: crate::packet::PacketBufPool,
    udp_send: US,
}

impl<P, US> PaddingSender<P, US>
where
    US: UdpSend + Clone + 'static,
    P: TunnelCapsule,
{
    fn new(peer: Weak<Mutex<P>>, packet_pool: crate::packet::PacketBufPool, udp_send: US) -> Self {
        Self {
            peer,
            packet_pool,
            udp_send,
        }
    }

    async fn send_padding(&self) -> Result<()> {
        let mut dst_buf = self.packet_pool.get();
        let Some(peer) = self.peer.upgrade() else {
            return Err(ErrorAction::Close);
        };
        let mut peer = peer.lock().await;

        // TODO: Reuse the same padding packet each time (unless MTU changes)?
        match peer.handle_outgoing(self.create_padding_packet(MTU), &mut dst_buf[..]) {
            TunnResult::Done => Ok(()), // TODO: error?
            TunnResult::Err(e) => {
                log::error!("Encapsulate error={e:?}: {e:?}");
                Err(ErrorAction::Close)
            }
            TunnResult::WriteToNetwork(packet) => {
                // TODO: DAITA tunnel_sent here?
                let len = packet.len();
                dst_buf.truncate(len);
                let endpoint_addr = peer.endpoint().addr;
                let Some(addr) = endpoint_addr else {
                    log::error!("No endpoint");
                    return Err(ErrorAction::Ignore);
                };
                self.udp_send
                    .send_to(dst_buf, addr)
                    .await
                    .map_err(|_| ErrorAction::Close) // TODO: what action?
            }
            _ => panic!("Unexpected result from encapsulate"),
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

// This is intended to be a used as a hook for encapsulation and decapsulation
// so that we can can trigger `TunnelSent` on only outgoing data packets
// (e.g. not keepalives) destined for the DAITA peer.
// For incoming packets, it should trigger `PaddingReceived`/`NormalReceived` based on
// the header and subsequently filter out the padding packets before passing the
// data packets to the IP layer.
// TODO: better name
pub trait TunnelCapsule {
    fn handle_outgoing<'a>(&mut self, src: Packet, dst: &'a mut [u8]) -> TunnResult<'a>;

    fn endpoint(&self) -> impl Deref<Target = crate::device::peer::Endpoint>;

    fn handle_incoming<'a>(&mut self, packet: noise::Packet, dst: &'a mut [u8]) -> TunnResult<'a>;

    fn decapsulate_with_session<'a>(
        &mut self,
        packet: noise::PacketData<'_>,
        dst: &'a mut [u8],
    ) -> core::result::Result<&'a mut [u8], noise::errors::WireGuardError>;
    fn validate_decapsulated_packet<'a>(&mut self, packet: &'a mut [u8]) -> TunnResult<'a>;
}

impl TunnelCapsule for Peer {
    fn handle_outgoing<'a>(&mut self, src: Packet, dst: &'a mut [u8]) -> TunnResult<'a> {
        self.tunnel.handle_outgoing(src.as_bytes(), dst)
    }

    fn endpoint(&self) -> impl Deref<Target = crate::device::peer::Endpoint> {
        self.endpoint()
    }

    fn handle_incoming<'a>(&mut self, packet: noise::Packet, dst: &'a mut [u8]) -> TunnResult<'a> {
        self.tunnel.handle_verified_packet(packet, dst)
    }

    fn decapsulate_with_session<'a>(
        &mut self,
        packet: noise::PacketData<'_>,
        dst: &'a mut [u8],
    ) -> core::result::Result<&'a mut [u8], noise::errors::WireGuardError> {
        self.tunnel.decapsulate_with_session(packet, dst)
    }

    fn validate_decapsulated_packet<'a>(&mut self, packet: &'a mut [u8]) -> TunnResult<'a> {
        self.tunnel.validate_decapsulated_packet(packet)
    }
}

struct DaitaPeer<P> {
    inner: P, // TODO: use Capsulation instead of Peer?
    event_tx: mpsc::UnboundedSender<TriggerEvent>,
    packet_count: Arc<PacketCount>,
    blocking_queue_tx: mpsc::UnboundedSender<(Packet, SocketAddr)>,
    blocking: Arc<RwLock<Blocking>>,
}

impl<P: TunnelCapsule> TunnelCapsule for DaitaPeer<P> {
    fn handle_outgoing<'a>(&mut self, mut src: Packet, dst: &'a mut [u8]) -> TunnResult<'a> {
        self.event_tx.send(TriggerEvent::NormalSent).unwrap(); // TODO: Close on error?
        self.packet_count
            .outbound
            .fetch_add(1, atomic::Ordering::SeqCst); // TODO: Ordering?

        debug_assert!(src.len() <= MTU as usize);
        src.buf_mut().resize(MTU as usize, 0);
        let res = self.inner.handle_outgoing(src, dst);

        if let TunnResult::WriteToNetwork(packet) = &res {
            if let Ok(blocking) = self.blocking.try_read()
                && blocking.is_active()
            {
                let packet: Packet<[u8]> = todo!("make packet be this type");
                let _ = self
                    .blocking_queue_tx
                    .send((packet, self.endpoint().addr.unwrap()));
                return TunnResult::Done;
            }
            let _ = self.event_tx.send(TriggerEvent::TunnelSent);
            self.packet_count.sub(1);
        }
        res
    }

    fn endpoint(&self) -> impl Deref<Target = crate::device::peer::Endpoint> {
        self.inner.endpoint()
    }

    fn handle_incoming<'a>(&mut self, packet: noise::Packet, dst: &'a mut [u8]) -> TunnResult<'a> {
        match packet {
            noise::Packet::PacketData(data_packet) => {
                let _ = self.event_tx.send(TriggerEvent::TunnelRecv);
                let decapsulated_packet = self
                    .inner
                    .decapsulate_with_session(data_packet, dst)
                    .unwrap();

                // TODO: parse `PaddingPacket` from bytes
                if decapsulated_packet[0] == DAITA_MARKER
                    && decapsulated_packet.len() >= size_of::<PaddingHeader>()
                {
                    let _ = self.event_tx.send(TriggerEvent::PaddingRecv);
                    // TODO: Count padding packet bytes
                    TunnResult::Done
                } else {
                    let res = self.inner.validate_decapsulated_packet(decapsulated_packet);
                    if matches!(
                        res,
                        TunnResult::WriteToTunnelV4(..) | TunnResult::WriteToTunnelV6(..),
                    ) {
                        let _ = self.event_tx.send(TriggerEvent::NormalRecv);
                    }
                    res
                }
            }
            non_data_packet => self.inner.handle_incoming(non_data_packet, dst),
        }
    }

    fn decapsulate_with_session<'a>(
        &mut self,
        packet: noise::PacketData<'_>,
        dst: &'a mut [u8],
    ) -> core::result::Result<&'a mut [u8], noise::errors::WireGuardError> {
        self.inner.decapsulate_with_session(packet, dst)
    }

    fn validate_decapsulated_packet<'a>(&mut self, packet: &'a mut [u8]) -> TunnResult<'a> {
        self.inner.validate_decapsulated_packet(packet)
    }
}
