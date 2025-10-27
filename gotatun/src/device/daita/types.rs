use futures::{FutureExt, future::pending};
use maybenot::MachineId;
use std::{
    collections::VecDeque,
    sync::{
        Arc,
        atomic::{self, AtomicU32},
    },
};
use tokio::{
    sync::{
        Notify, RwLock,
        mpsc::{self, error::TrySendError},
    },
    time::Instant,
};
use zerocopy::{Immutable, IntoBytes, KnownLayout, TryFromBytes, Unaligned, big_endian};

use crate::packet::{Packet, WgData};

pub(crate) enum ErrorAction {
    Close,
    Ignore(IgnoreReason),
}

pub(crate) enum IgnoreReason {
    NoEndpoint,
    NoSession,
}

impl std::fmt::Display for IgnoreReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IgnoreReason::NoEndpoint => write!(f, "No endpoint"),
            IgnoreReason::NoSession => write!(f, "No session"),
        }
    }
}

pub(crate) type Result<T> = std::result::Result<T, ErrorAction>;

#[derive(TryFromBytes, KnownLayout, Unaligned, Immutable, PartialEq, Eq)]
#[repr(C)]
pub(crate) struct PaddingPacket {
    pub(crate) header: PaddingHeader,
    pub(crate) payload: [u8],
}

#[derive(
    TryFromBytes, IntoBytes, KnownLayout, Unaligned, Immutable, PartialEq, Eq, Clone, Copy,
)]
#[repr(C, packed)]
pub(crate) struct PaddingHeader {
    pub marker: PaddingMarker,
    _reserved: u8,
    pub length: big_endian::U16,
}

#[derive(
    TryFromBytes, IntoBytes, KnownLayout, Unaligned, Immutable, PartialEq, Eq, Clone, Copy,
)]
#[repr(u8)]
pub(crate) enum PaddingMarker {
    Padding = 0xff,
}

impl PaddingHeader {
    pub(crate) const fn new(length: big_endian::U16) -> Self {
        Self {
            marker: PaddingMarker::Padding,
            _reserved: 0,
            length,
        }
    }
}

/// Counter for the number of normal packets that have been received on the tunnel interface
/// but not yet sent to the network, and the number of those packets that have replaced
/// padding packets.
#[derive(Default)]
pub(crate) struct PacketCount {
    outbound_normal: AtomicU32,
}

impl PacketCount {
    pub fn dec(&self, amount: u32) {
        self.outbound_normal
            .fetch_sub(amount, atomic::Ordering::SeqCst);
    }

    pub fn inc(&self, amount: u32) {
        self.outbound_normal
            .fetch_add(amount, atomic::Ordering::SeqCst);
    }

    pub fn outbound(&self) -> u32 {
        self.outbound_normal.load(atomic::Ordering::SeqCst)
    }
}

#[derive(Clone, Copy)]
pub(crate) enum BlockingState {
    Inactive,
    Active { bypass: bool, expires_at: Instant },
}

impl BlockingState {
    /// Returns `true` if the blocking is [`Active`].
    ///
    /// [`Active`]: Blocking::Active
    #[must_use]
    pub(crate) fn is_active(&self) -> bool {
        matches!(self, Self::Active { .. })
    }
}

#[derive(Clone)]
pub struct BlockingWatcher {
    pub(super) blocking_queue_tx: mpsc::Sender<Packet<WgData>>,
    pub(super) blocking_state: Arc<RwLock<BlockingState>>,
    blocking_abort: Arc<Notify>,
    min_blocking_capacity: usize,
}

impl BlockingWatcher {
    pub fn new(
        blocking_queue_tx: mpsc::Sender<Packet<WgData>>,
        min_blocking_capacity: usize,
    ) -> Self {
        let blocking_state = Arc::new(RwLock::new(BlockingState::Inactive));
        let blocking_abort = Arc::new(Notify::const_new());
        Self {
            blocking_queue_tx,
            blocking_state,
            blocking_abort,
            min_blocking_capacity,
        }
    }

    /// Wait until the blocking timer expires, or until `blocking_abort` is notified.
    ///
    /// When this future resolves, blocked packets should be flushed.
    pub async fn wait_blocking_ended(&self) {
        if let BlockingState::Active { expires_at, .. } = &*self.blocking_state.read().await {
            futures::select! {
                _ = tokio::time::sleep_until(*expires_at).fuse() => {},
                _ = self.blocking_abort.notified().fuse() => {
                    log::trace!("Blocking aborted with remaining capacity {}", self.blocking_queue_tx.capacity());
                },
            }
        } else {
            pending().await
        };
    }

    /// Add the packet to the blocking queue if blocking is active, otherwise return it to be sent immediately.
    ///
    /// Returns `None` if the packet was queued for blocking.
    ///
    /// Returns `Some(packet)` if the packet should be sent immediately.
    /// This happens if blocking is inactive, or if the blocking queue is full/closed.
    pub fn maybe_block_packet(&self, packet: Packet<WgData>) -> Option<Packet<WgData>> {
        if let Ok(blocking) = self.blocking_state.try_read()
            && blocking.is_active()
        {
            // Notify the blocking handler to abort blocking when the capacity is low
            if self.blocking_queue_tx.capacity() < self.min_blocking_capacity {
                self.blocking_abort.notify_one();
            }

            if let Err(TrySendError::Closed(packet) | TrySendError::Full(packet)) =
                self.blocking_queue_tx.try_send(packet)
            {
                log::trace!("Packet sent as it couldn't be blocked");
                // If the queue is closed or full, we can't block anymore, so we
                // send the packet anyway.
                // TODO: this would be an out of order packet, not ideal.
                // Should we drop the packet instead?
                Some(packet)
            } else {
                None
            }
        } else {
            Some(packet)
        }
    }
}

/// Queue of timers for each machine.
///
/// Use [`MachineTimers::wait_next_timer`] to wait for the next time expiration.
// INVARIANT: VecDeque is sorted by Instant, which represents the time of expiration.
// INVARIANT: Only one internal and one action timer per machine can exist at a time.
pub(crate) struct MachineTimers(VecDeque<(Instant, MachineId, MachineTimer)>);

#[derive(Clone, Copy, Debug)]
pub(crate) enum Action {
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

/// Type of timer for a machine, see [`MachineTimers`].
#[derive(Clone, Copy, Debug)]
pub(crate) enum MachineTimer {
    /// The internal timer does not trigger any action directly, but is used to
    /// trigger [`maybenot::TriggerEvent::TimerEnd`], giving the machine a way
    /// to know when the time has passed.
    Internal,
    /// The action timer triggers a [`Action`], which can be either sending
    /// padding packets or blocking outgoing packets.
    Action(Action),
}

impl MachineTimers {
    pub(crate) fn new(cap: usize) -> Self {
        Self(VecDeque::with_capacity(cap))
    }

    pub(crate) fn remove_action(&mut self, machine: &MachineId) {
        self.0
            .retain(|&(_, m, t)| !(m == *machine && matches!(t, MachineTimer::Action(_))));
    }

    pub(crate) fn remove_internal(&mut self, machine: &MachineId) {
        self.0
            .retain(|&(_, m, t)| !(m == *machine && matches!(t, MachineTimer::Internal)));
    }

    pub(crate) fn remove_all(&mut self, machine: &MachineId) {
        self.0.retain(|&(_, m, _)| m != *machine);
    }

    /// Schedule padding timer according to [`maybenot::TriggerAction::SendPadding`].
    pub(crate) fn schedule_padding(
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

    /// Schedule blocking timer according to [`maybenot::TriggerAction::BlockOutgoing`].
    pub(crate) fn schedule_block(
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

    /// Schedule internal timer according to [`maybenot::TriggerAction::UpdateTimer`].
    pub(crate) fn schedule_internal_timer(
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

    /// Wait until the next timer expires and returns it.
    ///
    /// ## Cancel safety
    /// This function is cancellation safe, i.e. the timer will not
    /// be removed if the function is cancelled.
    pub(crate) async fn wait_next_timer(&mut self) -> (MachineId, MachineTimer) {
        if let Some((time, _, _)) = self.0.front() {
            tokio::time::sleep_until(*time).await;
            self.0
                .pop_front()
                .map(|(_, m, t)| (m, t))
                .expect("Front exists because we peeked it")
        } else {
            futures::future::pending().await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::daita::types;

    #[test]
    fn test_machine_timers_schedule_and_remove() {
        let mut timers = types::MachineTimers::new(4);
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
        let mut timers = types::MachineTimers::new(4);
        let machine = MachineId::from_raw(1);

        timers.schedule_internal_timer(machine, std::time::Duration::from_secs(1), false);
        timers.schedule_internal_timer(machine, std::time::Duration::from_secs(2), false);
        assert_eq!(timers.0.len(), 1);
        let i = timers.0.front().unwrap().0;
        assert!(
            i.duration_since(Instant::now()) > std::time::Duration::from_secs(1),
            "The longer timer should be kept"
        );

        timers.schedule_internal_timer(machine, std::time::Duration::from_secs(2), false);
        timers.schedule_internal_timer(machine, std::time::Duration::from_secs(1), false);

        assert_eq!(timers.0.len(), 1);
        let i = timers.0.front().unwrap().0;
        assert!(
            i.duration_since(Instant::now()) > std::time::Duration::from_secs(1),
            "The longer timer should be kept"
        );

        timers.schedule_internal_timer(machine, std::time::Duration::from_secs(2), true);
        timers.schedule_internal_timer(machine, std::time::Duration::from_secs(1), true);

        assert_eq!(timers.0.len(), 1);
        let i = timers.0.front().unwrap().0;
        assert!(
            i.duration_since(Instant::now()) < std::time::Duration::from_secs(2),
            "The last timer should be kept"
        );
    }
}
