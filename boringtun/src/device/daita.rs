use std::{
    collections::VecDeque,
    net::SocketAddr,
    pin::pin,
    sync::{
        Arc, Weak,
        atomic::{self, AtomicU32},
    },
};

use crate::{noise::TunnResult, packet::Packet, tun::IpRecv, udp::UdpSend};

use super::peer::Peer;
use futures::{FutureExt, future::Fuse};
use maybenot::{Framework, Machine, MachineId, TriggerAction, TriggerEvent};
use rand::RngCore;
use tokio::sync::{RwLock, mpsc};
use tokio::time::Instant;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned, big_endian};

use tokio::sync::Mutex;

enum ErrorAction {
    Close,
    Ignore,
}

type Result<T> = std::result::Result<T, ErrorAction>;

pub fn get_daita_hooks<M, R, IR, US>(
    maybenot: Framework<M, R>,
    peer: Weak<Mutex<Peer>>,
    ip_recv: IR,
    udp_send: US,
    packet_pool: crate::packet::PacketBufPool,
) -> (DaitaIpRecv<IR>, DaitaUdpSend<US>)
where
    Framework<M, R>: Send + 'static,
    IR: IpRecv,
    US: UdpSend + Clone + 'static,
    M: AsRef<[Machine]> + Send + 'static,
    R: RngCore,
{
    let (event_tx, event_rx) = mpsc::unbounded_channel();
    let outbound_packet_count = Arc::new(AtomicU32::new(0));
    let replaced_packet_count = Arc::new(AtomicU32::new(0));
    let blocking = Arc::new(RwLock::new(Blocking::Inactive));
    let (blocking_queue_tx, blocking_queue_rx) = mpsc::unbounded_channel();
    let daita = DAITA {
        maybenot,
        padding_sender: PaddingSender::new(peer, packet_pool, udp_send.clone(), 1300), // TODO: Real MTU
        outbound_packet_count: outbound_packet_count.clone(),
        replaced_packet_count: replaced_packet_count.clone(),
        blocking_queue_rx,
        blocking: blocking.clone(),
        udp_send: udp_send.clone(),
    };
    tokio::spawn(daita.handle_events(event_rx));
    (
        DaitaIpRecv {
            inner: ip_recv,
            event_tx: event_tx.clone(),
            outbound_packet_count: outbound_packet_count.clone(),
        },
        DaitaUdpSend {
            inner: udp_send,
            event_tx,
            outbound_packet_count,
            replaced_packet_count,
            blocking_queue_tx,
            blocking,
        },
    )
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
    pub _daita_marker: u8,
    pub _reserved: u8,
    pub length: big_endian::U16,
}

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

pub struct DaitaIpRecv<I: IpRecv> {
    inner: I,
    event_tx: mpsc::UnboundedSender<TriggerEvent>,
    outbound_packet_count: Arc<AtomicU32>,
}

impl<I: IpRecv> IpRecv for DaitaIpRecv<I> {
    async fn recv<'a>(
        &'a mut self,
        pool: &mut crate::packet::PacketBufPool,
    ) -> std::io::Result<impl Iterator<Item = crate::packet::Packet<crate::packet::Ip>> + Send + 'a>
    {
        let res = self.inner.recv(pool).await;
        res.map(|packet_iter| {
            packet_iter.inspect(|_| {
                let _ = self.event_tx.send(TriggerEvent::NormalSent);
                // TODO: Close on error?
                self.outbound_packet_count
                    .fetch_add(1, atomic::Ordering::SeqCst); // TODO: Ordering?
            })
        })
    }
}

#[derive(Clone)]
pub struct DaitaUdpSend<I: UdpSend> {
    inner: I,
    event_tx: mpsc::UnboundedSender<TriggerEvent>,
    outbound_packet_count: Arc<AtomicU32>,
    replaced_packet_count: Arc<AtomicU32>,
    blocking_queue_tx: mpsc::UnboundedSender<(Packet, SocketAddr)>,
    blocking: Arc<RwLock<Blocking>>,
}

impl<I: UdpSend> UdpSend for DaitaUdpSend<I> {
    type SendManyBuf = I::SendManyBuf;

    async fn send_to(
        &self,
        packet: crate::packet::Packet,
        destination: SocketAddr,
    ) -> std::io::Result<()> {
        if self.blocking.read().await.is_active() {
            let _ = self.blocking_queue_tx.send((packet, destination));
            return Ok(());
        }

        let res = self.inner.send_to(packet, destination).await;
        if res.is_ok() {
            let _ = self.event_tx.send(TriggerEvent::TunnelSent);
        }
        self.decrement_packet_count(1);
        res
    }

    fn max_number_of_packets_to_send(&self) -> usize {
        self.inner.max_number_of_packets_to_send()
    }

    fn send_many_to(
        &self,
        send_buf: &mut Self::SendManyBuf,
        packets: &mut Vec<(Packet, SocketAddr)>,
    ) -> impl Future<Output = std::io::Result<()>> + Send {
        self.decrement_packet_count(packets.len() as u32);
        self.inner.send_many_to(send_buf, packets)
    }

    fn local_addr(&self) -> std::io::Result<Option<SocketAddr>> {
        self.inner.local_addr()
    }

    fn set_fwmark(&self, _mark: u32) -> std::io::Result<()> {
        self.inner.set_fwmark(_mark)
    }

    fn enable_udp_gro(&self) -> std::io::Result<()> {
        self.inner.enable_udp_gro()
    }
}

impl<I: UdpSend> DaitaUdpSend<I> {
    fn decrement_packet_count(&self, amount: u32) {
        self.replaced_packet_count
            .fetch_update(atomic::Ordering::SeqCst, atomic::Ordering::SeqCst, |x| {
                if x >= amount {
                    Some(x - amount)
                } else {
                    Some(0)
                }
            })
            .ok();
        self.outbound_packet_count
            .fetch_sub(amount, atomic::Ordering::SeqCst);
        // TODO: Ordering?
    }
}

pub struct DAITA<M, R, US>
where
    M: AsRef<[Machine]> + Send + 'static,
    R: RngCore,
    US: UdpSend + Clone + 'static,
{
    maybenot: Framework<M, R>,
    padding_sender: PaddingSender<US>,
    outbound_packet_count: Arc<AtomicU32>,
    replaced_packet_count: Arc<AtomicU32>,
    blocking_queue_rx: mpsc::UnboundedReceiver<(Packet, SocketAddr)>,
    blocking: Arc<RwLock<Blocking>>,
    udp_send: US,
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
                    self.end_blocking(&mut blocked_packets_buf).await;
                    event_buf.push(TriggerEvent::BlockingEnd);
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
                if self.replaced_packet_count.load(atomic::Ordering::SeqCst)
                    < self.outbound_packet_count.load(atomic::Ordering::SeqCst)
                        + self.blocking_queue_rx.len() as u32 =>
            {
                self.replaced_packet_count
                    .fetch_add(1, atomic::Ordering::SeqCst);
                machine_timers.remove_action(&machine);
                return;
            }
            // Padding packet should or cannot replace any blocked packet
            (Some(false), _) => {
                // TODO: Generate a padding packing and add it to the blocking queue
            }
            (None, true)
                if self.replaced_packet_count.load(atomic::Ordering::SeqCst)
                    < self.outbound_packet_count.load(atomic::Ordering::SeqCst) =>
            {
                self.replaced_packet_count
                    .fetch_add(1, atomic::Ordering::SeqCst);
                machine_timers.remove_action(&machine);
                return;
            }
            (None, _) => {
                if let Err(ErrorAction::Close) = self.padding_sender.send_padding().await {
                    return;
                }
            }
        };
        self.outbound_packet_count
            .fetch_add(1, atomic::Ordering::SeqCst);
    }

    async fn end_blocking(&mut self, packets: &mut Vec<(Packet, SocketAddr)>) {
        *self.blocking.write().await = Blocking::Inactive;
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
            self.udp_send
                .send_many_to(&mut send_many_bufs, packets)
                .await
                .unwrap();
        }
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

// TODO: unclear purpose of this type
struct PaddingSender<US>
where
    US: UdpSend + Clone + 'static,
{
    peer: Weak<Mutex<Peer>>,
    packet_pool: crate::packet::PacketBufPool,
    udp_send: US,
    padding_packet_buf: crate::packet::Packet,
}

impl<US> PaddingSender<US>
where
    US: UdpSend + Clone + 'static,
{
    fn new(
        peer: Weak<Mutex<Peer>>,
        packet_pool: crate::packet::PacketBufPool,
        udp_send: US,
        mtu: u16,
    ) -> Self {
        let padding_packet_buf = packet_pool.get();
        let mut self_ = Self {
            peer,
            packet_pool,
            udp_send,
            padding_packet_buf,
        };
        self_.update(mtu);
        self_
    }

    async fn send_padding(&self) -> Result<()> {
        let mut dst_buf = self.packet_pool.get();
        let Some(peer) = self.peer.upgrade() else {
            return Err(ErrorAction::Close);
        };
        let mut peer = peer.lock().await;
        match peer
            .tunnel
            .encapsulate(self.padding_packet_buf.as_bytes(), &mut dst_buf[..])
        {
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

    fn update(&mut self, mtu: u16) {
        let padding_packet_header = PaddingHeader {
            _daita_marker: 0xFF,
            _reserved: 0,
            length: mtu.into(),
        };
        self.padding_packet_buf.buf_mut().clear();
        self.padding_packet_buf
            .buf_mut()
            .extend_from_slice(padding_packet_header.as_bytes());
        self.padding_packet_buf.buf_mut().resize(mtu.into(), 0);
    }
}
