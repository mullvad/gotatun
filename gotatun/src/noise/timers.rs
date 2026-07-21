// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// This file incorporates work covered by the following copyright and
// permission notice:
//
//   Copyright (c) Mullvad VPN AB. All rights reserved.
//   Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
//
// SPDX-License-Identifier: MPL-2.0

use super::errors::WireGuardError;
use crate::noise::Tunn;
use crate::packet::WgKind;

use std::ops::{Index, IndexMut, RangeInclusive};
use std::time::Duration;

use bytes::BytesMut;
#[cfg(feature = "mock_instant")]
use mock_instant::thread_local::Instant;
use rand::Rng;

#[cfg(not(feature = "mock_instant"))]
use crate::sleepyinstant::Instant;

// Some constants, represent time in seconds
// https://www.wireguard.com/papers/wireguard.pdf#page=14
pub(crate) const REKEY_AFTER_TIME: Duration = Duration::from_secs(120);
const REJECT_AFTER_TIME: Duration = Duration::from_secs(180);
const REKEY_ATTEMPT_TIME: Duration = Duration::from_secs(90);
pub(crate) const REKEY_TIMEOUT: Duration = Duration::from_secs(5);
const KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(10);
const COOKIE_EXPIRATION_TIME: Duration = Duration::from_secs(120);
pub(crate) const MAX_JITTER: Duration = Duration::from_millis(333);

#[derive(Debug)]
pub enum TimerName {
    /// Current time, updated each call to `update_timers`
    TimeCurrent,
    /// Time when last handshake was completed
    TimeSessionEstablished,
    /// Time the last attempt for a new handshake began
    TimeLastHandshakeStarted,
    /// Time we last received and authenticated a packet
    TimeLastPacketReceived,
    /// Time we last send a packet
    TimeLastPacketSent,
    /// Time we last received a valid [`crate::packet::WgData`] packet, except keepalives
    TimeLastDataPacketReceived,
    /// Time we last sent a [`crate::packet::WgData`] packet, except keepalives
    TimeLastDataPacketSent,
    /// Time we last received a cookie
    TimeCookieReceived,
    /// Time we last sent persistent keepalive
    TimePersistentKeepalive,
    Top,
}

use self::TimerName::*;

/// Tuning of WireGuard timers.
///
/// Each timeout is sampled uniformly from its range when the corresponding timer is armed.
///
/// The defaults match the timings from the WireGuard paper.
///
/// # Note
///
/// Tweaking these values will cause your tunnel to deviate from the WireGuard spec. Use with
/// caution.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TimerParams {
    /// How long to wait, after receiving a data packet without sending anything back, before
    /// sending a passive keepalive.
    ///
    /// Sampled when the passive keepalive timer is armed.
    pub keepalive_timeout: RangeInclusive<Duration>,
    /// How long to wait, after sending a data packet without hearing anything back, before
    /// initiating a new handshake.
    ///
    /// Sampled when the new-handshake timer is armed.
    pub new_handshake_timeout: RangeInclusive<Duration>,
    /// How long to wait before retransmitting an unanswered handshake initiation.
    ///
    /// Sampled each time a handshake initiation is sent.
    pub rekey_timeout: RangeInclusive<Duration>,
    /// Session age after which the initiator initiates a new handshake when sending data.
    ///
    /// Sampled when a session is established.
    pub rekey_after_time: RangeInclusive<Duration>,
}

impl Default for TimerParams {
    fn default() -> Self {
        TimerParams {
            keepalive_timeout: KEEPALIVE_TIMEOUT..=KEEPALIVE_TIMEOUT,
            new_handshake_timeout: (KEEPALIVE_TIMEOUT + REKEY_TIMEOUT)
                ..=(KEEPALIVE_TIMEOUT + REKEY_TIMEOUT + MAX_JITTER),
            rekey_timeout: REKEY_TIMEOUT..=(REKEY_TIMEOUT + MAX_JITTER),
            rekey_after_time: REKEY_AFTER_TIME..=REKEY_AFTER_TIME,
        }
    }
}

#[derive(Debug)]
pub struct Timers {
    /// Is the owner of the timer the initiator or the responder for the last handshake?
    is_initiator: bool,
    /// Start time of the tunnel
    time_started: Instant,
    timers: [Duration; TimerName::Top as usize],
    pub(super) session_timers: [Duration; super::N_SESSIONS],
    /// Time the first data packet was received without us sending anything back, if any.
    /// A passive keepalive is due `keepalive_timeout` after this time.
    want_keepalive: Option<Duration>,
    /// First data packet sent without hearing back
    want_handshake: Option<Duration>,
    persistent_keepalive: Option<Duration>,
    persistent_keepalive_due: bool,
    /// Timer deadline ranges that the sampled deadlines below are drawn from.
    pub(super) params: TimerParams,
    /// Current passive keepalive deadline.
    /// Sampled from [`TimerParams::keepalive_timeout`] when `want_keepalive` is armed.
    keepalive_timeout: Duration,
    /// Current new-handshake-after-silence deadline.
    /// Sampled from [`TimerParams::new_handshake_timeout`] when `want_handshake` is armed.
    new_handshake_timeout: Duration,
    /// Current handshake retransmit deadline (including jitter).
    /// Sampled from [`TimerParams::rekey_timeout`] on each handshake initiation.
    pub(super) rekey_timeout: Duration,
    /// Current rekey-after-time deadline.
    /// Sampled from [`TimerParams::rekey_after_time`] when a session is established.
    rekey_after_time: Duration,
}

impl Timers {
    pub(super) fn new(persistent_keepalive: Option<u16>) -> Timers {
        let persistent_keepalive = persistent_keepalive
            .filter(|&s| s > 0)
            .map(|s| Duration::from_secs(s.into()));
        let mut timers = Timers {
            is_initiator: false,
            time_started: Instant::now(),
            timers: Default::default(),
            session_timers: Default::default(),
            want_keepalive: Default::default(),
            want_handshake: Default::default(),
            persistent_keepalive,
            persistent_keepalive_due: persistent_keepalive.is_some(),
            params: TimerParams::default(),
            keepalive_timeout: Duration::ZERO,
            new_handshake_timeout: Duration::ZERO,
            rekey_timeout: Duration::ZERO,
            rekey_after_time: Duration::ZERO,
        };
        timers.dangerously_set_params(TimerParams::default());
        timers
    }

    /// Replace the timer params, resetting all sampled deadlines.
    ///
    /// See [TimerParams].
    pub(super) fn dangerously_set_params(&mut self, params: TimerParams) {
        self.keepalive_timeout = *params.keepalive_timeout.start();
        self.new_handshake_timeout = *params.new_handshake_timeout.start();
        self.rekey_timeout = *params.rekey_timeout.start();
        self.rekey_after_time = *params.rekey_after_time.end();
        self.params = params;
    }

    fn is_initiator(&self) -> bool {
        self.is_initiator
    }

    // We don't really clear the timers, but we set them to the current time to
    // so the reference time frame is the same
    pub(super) fn clear(&mut self) {
        let now = self.now();
        for t in &mut self.timers[..] {
            *t = now;
        }
        self.want_handshake = None;
        self.want_keepalive = None;
        self.persistent_keepalive_due = self.persistent_keepalive.is_some();
        self.dangerously_set_params(self.params.clone());
    }

    /// Compute the time elapsed since [`Self::time_started`] based on [`Instant::now`].
    /// This is guaranteed to be monotonic and no less than `self[TimeCurrent]`.
    /// It never panics.
    fn now(&self) -> Duration {
        Instant::now()
            .checked_duration_since(self.time_started)
            .unwrap_or(Duration::ZERO)
            .max(self[TimeCurrent])
    }
}

impl Index<TimerName> for Timers {
    type Output = Duration;
    fn index(&self, index: TimerName) -> &Duration {
        &self.timers[index as usize]
    }
}

impl IndexMut<TimerName> for Timers {
    fn index_mut(&mut self, index: TimerName) -> &mut Duration {
        &mut self.timers[index as usize]
    }
}

impl<R: rand::RngCore + Send> Tunn<R> {
    pub(super) fn timer_tick(&mut self, timer_name: TimerName) {
        let time = self.timers[TimeCurrent];

        match timer_name {
            TimeLastPacketReceived => {
                self.timers.want_handshake = None;
                self.timers.persistent_keepalive_due = false;

                // Reset persistent keepalive timer for any authenticated packet
                // Ref: https://github.com/torvalds/linux/blob/9716c086c8e8b141d35aa61f2e96a2e83de212a7/drivers/net/wireguard/timers.c#L215-L220
                self.timers[TimePersistentKeepalive] = time;
            }
            TimeLastDataPacketReceived if self.timers.want_keepalive.is_none() => {
                self.timers.keepalive_timeout = self.sample_timer(|p| &p.keepalive_timeout);
                self.timers.want_keepalive = Some(time);
            }
            // The Linux kernel schedules an extra keepalive here if one is already queued:
            // https://github.com/torvalds/linux/blob/9716c086c8e8b141d35aa61f2e96a2e83de212a7/drivers/net/wireguard/timers.c#L157-L166
            // This seems unnecessary?
            TimeLastDataPacketReceived => {}
            TimeLastPacketSent => {
                self.timers.want_keepalive = None;
                self.timers.persistent_keepalive_due = false;

                // Reset persistent keepalive timer for any authenticated packet
                // Ref: https://github.com/torvalds/linux/blob/9716c086c8e8b141d35aa61f2e96a2e83de212a7/drivers/net/wireguard/timers.c#L215-L220
                self.timers[TimePersistentKeepalive] = time;
            }
            TimeLastDataPacketSent if self.timers.want_handshake.is_none() => {
                self.timers.new_handshake_timeout = self.sample_timer(|p| &p.new_handshake_timeout);
                self.timers.want_handshake = Some(time);
            }
            _ => {}
        }

        self.timers[timer_name] = time;
    }

    /// Sample a deadline uniformly from one of the [`TimerParams`] ranges.
    pub(super) fn sample_timer(
        &mut self,
        range: impl FnOnce(&TimerParams) -> &RangeInclusive<Duration>,
    ) -> Duration {
        let range = range(&self.timers.params).clone();
        if range.start() >= range.end() {
            // Avoid consuming randomness for fixed deadlines.
            *range.start()
        } else {
            self.jitter_rng.random_range(range)
        }
    }

    pub(super) fn timer_tick_session_established(
        &mut self,
        is_initiator: bool,
        session_idx: usize,
    ) {
        self.timer_tick(TimeSessionEstablished);
        self.timers.session_timers[session_idx % crate::noise::N_SESSIONS] =
            self.timers[TimeCurrent];
        self.timers.is_initiator = is_initiator;
        self.timers.rekey_after_time = self.sample_timer(|p| &p.rekey_after_time);
    }

    // We don't really clear the timers, but we set them to the current time to
    // so the reference time frame is the same
    pub(super) fn clear_all(&mut self) {
        for session in &mut self.sessions {
            *session = None;
        }

        self.packet_queue.clear();

        self.timers.clear();
    }

    fn update_session_timers(&mut self, time_now: Duration) {
        let timers = &mut self.timers;

        for (i, t) in timers.session_timers.iter_mut().enumerate() {
            if time_now - *t > REJECT_AFTER_TIME {
                // Forget about expired sesssions
                if let Some(session) = self.sessions[i].take() {
                    tracing::trace!(
                        "SESSION_EXPIRED(REJECT_AFTER_TIME): {}",
                        session.receiving_index
                    );
                }
                *t = time_now;
            }
        }
    }

    /// Update the tunnel timers
    ///
    /// This returns `Ok(None)` if no action is needed, `Ok(Some(packet))` if a packet
    /// (keepalive or handshake) should be sent, or an error if something went wrong.
    pub fn update_timers(&mut self) -> Result<Option<WgKind>, WireGuardError> {
        let mut handshake_initiation_required = false;
        let mut keepalive_required = false;

        self.rate_limiter.try_reset_count();

        // All the times are counted from tunnel initiation, for efficiency our timers are rounded
        // to a second, as there is no real benefit to having highly accurate timers.
        let now = self.timers.now();
        self.timers[TimeCurrent] = now;

        self.update_session_timers(now);

        // Load timers only once:
        let session_established = self.timers[TimeSessionEstablished];
        let handshake_started = self.timers[TimeLastHandshakeStarted];
        let data_packet_received = self.timers[TimeLastDataPacketReceived];
        let data_packet_sent = self.timers[TimeLastDataPacketSent];
        let persistent_keepalive = self.timers.persistent_keepalive;

        {
            if self.handshake.is_expired() {
                return Err(WireGuardError::ConnectionExpired);
            }

            // Clear cookie after COOKIE_EXPIRATION_TIME
            if self.handshake.has_cookie()
                && now - self.timers[TimeCookieReceived] >= COOKIE_EXPIRATION_TIME
            {
                self.handshake.clear_cookie();
            }

            // All ephemeral private keys and symmetric session keys are zeroed out after
            // (REJECT_AFTER_TIME * 3) ms if no new keys have been exchanged.
            if now - session_established >= REJECT_AFTER_TIME * 3 {
                tracing::trace!("CONNECTION_EXPIRED(REJECT_AFTER_TIME * 3)");
                self.handshake.set_expired();
                self.clear_all();
                return Err(WireGuardError::ConnectionExpired);
            }

            if let Some(time_init_sent) = self.handshake.timer() {
                // Handshake Initiation Retransmission
                if now - handshake_started >= REKEY_ATTEMPT_TIME {
                    // After REKEY_ATTEMPT_TIME ms of trying to initiate a new handshake,
                    // the retries give up and cease, and clear all existing packets queued
                    // up to be sent. If a packet is explicitly queued up to be sent, then
                    // this timer is reset.
                    tracing::debug!("CONNECTION_EXPIRED(REKEY_ATTEMPT_TIME)");
                    self.handshake.set_expired();
                    self.clear_all();
                    return Err(WireGuardError::ConnectionExpired);
                }

                if time_init_sent.elapsed() >= self.timers.rekey_timeout {
                    // We avoid using `time` here, because it can be earlier than `time_init_sent`.
                    // Once `checked_duration_since` is stable we can use that.
                    // A handshake initiation is retried after the sampled rekey timeout,
                    // by default REKEY_TIMEOUT plus some random jitter between 0 and 333 ms.
                    tracing::debug!("HANDSHAKE(REKEY_TIMEOUT)");
                    handshake_initiation_required = true;
                }
            } else {
                if self.timers.is_initiator() {
                    // After sending a packet, if the sender was the original initiator
                    // of the handshake and if the current session key is REKEY_AFTER_TIME
                    // ms old, we initiate a new handshake. If the sender was the original
                    // responder of the handshake, it does not re-initiate a new handshake
                    // after REKEY_AFTER_TIME ms like the original initiator does.
                    if session_established < data_packet_sent
                        && now - session_established >= self.timers.rekey_after_time
                    {
                        tracing::trace!("HANDSHAKE(REKEY_AFTER_TIME (on send))");
                        handshake_initiation_required = true;
                    }

                    // After receiving a packet, if the receiver was the original initiator
                    // of the handshake and if the current session key is REJECT_AFTER_TIME
                    // - KEEPALIVE_TIMEOUT - REKEY_TIMEOUT ms old, we initiate a new
                    // handshake.
                    if session_established < data_packet_received
                        && now - session_established
                            >= REJECT_AFTER_TIME - KEEPALIVE_TIMEOUT - REKEY_TIMEOUT
                    {
                        tracing::trace!(
                            "HANDSHAKE(REJECT_AFTER_TIME - KEEPALIVE_TIMEOUT - \
                        REKEY_TIMEOUT \
                        (on receive))"
                        );
                        handshake_initiation_required = true;
                    }
                }

                // If we have sent a data packet to a given peer but have not received a
                // packet after from that peer for the sampled new-handshake timeout
                // (`KEEPALIVE + REKEY_TIMEOUT` by default), we initiate a new handshake.
                if let Some(since) = self.timers.want_handshake
                    && now.saturating_sub(since) >= self.timers.new_handshake_timeout
                {
                    tracing::trace!("HANDSHAKE(KEEPALIVE + REKEY_TIMEOUT)");
                    handshake_initiation_required = true;
                    self.timers.want_handshake = None;
                }

                if !handshake_initiation_required {
                    // If a data packet has been received from a given peer, but we have not sent
                    // anything back within the sampled keepalive timeout (KEEPALIVE ms by
                    // default), we send an empty packet.
                    if let Some(since) = self.timers.want_keepalive
                        && now.saturating_sub(since) >= self.timers.keepalive_timeout
                    {
                        tracing::trace!("KEEPALIVE(KEEPALIVE_TIMEOUT)");
                        keepalive_required = true;
                        self.timers.want_keepalive = None;
                    }

                    // Persistent KEEPALIVE
                    if let Some(persistent_keepalive) = persistent_keepalive
                        && (self.timers.persistent_keepalive_due
                            || now.saturating_sub(self.timers[TimePersistentKeepalive])
                                >= persistent_keepalive)
                    {
                        tracing::trace!("KEEPALIVE(PERSISTENT_KEEPALIVE)");
                        self.timers.persistent_keepalive_due = false;
                        self.timer_tick(TimePersistentKeepalive);
                        keepalive_required = true;
                    }
                }
            }
        }

        if handshake_initiation_required {
            return Ok(self.format_handshake_initiation(true).map(Into::into));
        }

        if keepalive_required {
            return Ok(self
                .handle_outgoing_packet(crate::packet::Packet::from_bytes(BytesMut::new()), None));
        }

        Ok(None)
    }

    /// Get the time elapsed since the last successful handshake.
    ///
    /// Returns `None` if no session has been established.
    pub fn time_since_last_handshake(&self) -> Option<Duration> {
        let current_session = self.current;
        if self.sessions[current_session % super::N_SESSIONS].is_some() {
            let duration_since_tun_start = self.timers.now();
            let duration_since_session_established = self.timers[TimeSessionEstablished];

            Some(duration_since_tun_start.saturating_sub(duration_since_session_established))
        } else {
            None
        }
    }

    /// Get the persistent keepalive interval in seconds.
    ///
    /// Returns `None` if persistent keepalive is disabled.
    pub fn persistent_keepalive(&self) -> Option<u16> {
        self.timers
            .persistent_keepalive
            .map(|keepalive| keepalive.as_secs() as u16)
            .filter(|&keepalive| keepalive > 0)
    }

    /// Get the timer params for this tunnel.
    pub fn timer_params(&self) -> &TimerParams {
        &self.timers.params
    }

    /// Set the timer params for this tunnel, controlling when WireGuard timers fire.
    ///
    /// See [TimerParams].
    pub fn dangerously_set_timer_params(&mut self, params: TimerParams) {
        self.timers.dangerously_set_params(params);
    }

    /// Set the persistent keepalive interval in seconds.
    ///
    /// Pass `None` or `Some(0)` to disable persistent keepalive.
    pub fn set_persistent_keepalive(&mut self, seconds: Option<u16>) {
        let was_enabled = self.timers.persistent_keepalive.is_some();
        self.timers.persistent_keepalive = seconds
            .filter(|&s| s > 0)
            .map(|s| Duration::from_secs(s.into()));
        self.timers.persistent_keepalive_due = self.timers.persistent_keepalive.is_some()
            && (self.timers.persistent_keepalive_due || !was_enabled);
        if self.timers.persistent_keepalive.is_none() {
            self.timers[TimePersistentKeepalive] = Duration::ZERO;
        } else {
            self.timers[TimePersistentKeepalive] = self.timers[TimeCurrent];
        }
    }
}
