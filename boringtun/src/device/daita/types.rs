use maybenot::MachineId;
use std::{
    collections::VecDeque,
    sync::atomic::{self, AtomicU32},
};
use tokio::time::Instant;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned, big_endian};

pub(crate) const DAITA_MARKER: u8 = 0xFF;

pub(crate) enum ErrorAction {
    Close,
    Ignore, // TODO: log error?
}

pub(crate) type Result<T> = std::result::Result<T, ErrorAction>;

#[derive(FromBytes, KnownLayout, Unaligned, Immutable, PartialEq, Eq)]
#[repr(C)]
pub(crate) struct PaddingPacket {
    pub(crate) header: PaddingHeader,
    pub(crate) payload: [u8],
}

#[derive(FromBytes, IntoBytes, KnownLayout, Unaligned, Immutable, PartialEq, Eq, Clone, Copy)]
#[repr(C, packed)]
pub(crate) struct PaddingHeader {
    pub _daita_marker: u8, // Must be `DAITA_MARKER`
    pub _reserved: u8,
    pub length: big_endian::U16,
}

/// Counter for the number of normal packets that have been received on the tunnel interface
/// but not yet sent to the network, and the number of those packets that have replaced
/// padding packets.
///
/// TODO: Is `Relaxed` atomic ordering fine?
pub(crate) struct PacketCount {
    pub(crate) outbound_normal: AtomicU32,
    pub(crate) replaced_normal: AtomicU32,
}

impl PacketCount {
    pub(crate) fn dec(&self, amount: u32) {
        self.replaced_normal
            .fetch_update(atomic::Ordering::Relaxed, atomic::Ordering::Relaxed, |x| {
                Some(x.saturating_sub(amount))
            })
            .ok();
        self.outbound_normal
            .fetch_sub(amount, atomic::Ordering::Relaxed);
    }

    pub(crate) fn inc_outbound(&self, amount: u32) {
        self.outbound_normal
            .fetch_add(amount, atomic::Ordering::Relaxed);
    }

    pub(crate) fn inc_replaced(&self, amount: u32) {
        self.replaced_normal
            .fetch_add(amount, atomic::Ordering::Relaxed);
    }

    pub(crate) fn outbound(&self) -> u32 {
        self.outbound_normal.load(atomic::Ordering::Relaxed)
    }

    pub(crate) fn replaced(&self) -> u32 {
        self.replaced_normal.load(atomic::Ordering::Relaxed)
    }
}

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

/// Queue of timers for each machine.
///
/// Use [`MachineTimers::wait_next_timer`] to wait for the next time expiration.
// INVARIANT: VecDeque is sorted by Instant, which represents the time of expiration.
// INVARIANT: Only one internal and one action timer per machine can exist at a time.
pub(crate) struct MachineTimers(pub(super) VecDeque<(Instant, MachineId, MachineTimer)>);

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

#[derive(Clone, Copy, Debug)]
pub(crate) enum MachineTimer {
    Internal,
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

    /// Wait until the next timer expires. Afterwards, use
    /// [`MachineTimers::pop_next_timer`] to get the expired timer.
    pub(crate) async fn wait_next_timer(&mut self) {
        if let Some((time, _, _)) = self.0.front() {
            tokio::time::sleep_until(*time).await;
        } else {
            futures::future::pending().await
        }
    }

    pub(crate) fn pop_next_timer(&mut self) -> Option<(MachineId, MachineTimer)> {
        self.0.pop_front().map(|(_, m, t)| (m, t))
    }
}
