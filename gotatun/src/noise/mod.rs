// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
//
// Modified by Mullvad VPN.
// Copyright (c) 2025 Mullvad VPN.
//
// SPDX-License-Identifier: BSD-3-Clause

pub mod errors;
pub mod handshake;
pub mod index_table;
pub mod rate_limiter;

mod session;
mod timers;

use zerocopy::IntoBytes;

use crate::noise::errors::WireGuardError;
use crate::noise::handshake::Handshake;
use crate::noise::index_table::IndexTable;
use crate::noise::rate_limiter::RateLimiter;
use crate::noise::timers::{TimerName, Timers};
use crate::packet::{Packet, WgCookieReply, WgData, WgHandshakeInit, WgHandshakeResp, WgKind};
use crate::x25519;

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Duration;

const MAX_QUEUE_DEPTH: usize = 256;
/// number of sessions in the ring, better keep a PoT.
const N_SESSIONS: usize = 8;

#[derive(Debug)]
pub enum TunnResult {
    Done,
    Err(WireGuardError),
    WriteToNetwork(WgKind),
    WriteToTunnel(Packet),
}

impl From<WireGuardError> for TunnResult {
    fn from(err: WireGuardError) -> TunnResult {
        TunnResult::Err(err)
    }
}

/// Tunnel represents a point-to-point WireGuard connection.
pub struct Tunn {
    /// The handshake currently in progress.
    handshake: handshake::Handshake,
    /// The [`N_SESSIONS`] most recent sessions.
    sessions: [Option<session::Session>; N_SESSIONS],
    /// Index of the most recently used session.
    current: usize,
    /// Counter for slot selection when inserting new sessions.
    session_counter: u8,
    /// Queue to store blocked packets.
    packet_queue: VecDeque<Packet>,

    /// Keeps tabs on the expiring timers.
    timers: timers::Timers,
    tx_bytes: usize,
    rx_bytes: usize,
    rate_limiter: Arc<RateLimiter>,
}

impl Tunn {
    pub fn is_expired(&self) -> bool {
        self.handshake.is_expired()
    }

    /// Create a new tunnel using own private key and the peer public key.
    pub fn new(
        static_private: x25519::StaticSecret,
        peer_static_public: x25519::PublicKey,
        preshared_key: Option<[u8; 32]>,
        persistent_keepalive: Option<u16>,
        index_table: IndexTable,
        rate_limiter: Arc<RateLimiter>,
    ) -> Self {
        let static_public = x25519::PublicKey::from(&static_private);

        Tunn {
            handshake: Handshake::new(
                static_private,
                static_public,
                peer_static_public,
                index_table,
                preshared_key,
            ),
            sessions: Default::default(),
            current: Default::default(),
            session_counter: Default::default(),
            tx_bytes: Default::default(),
            rx_bytes: Default::default(),

            packet_queue: VecDeque::new(),
            timers: Timers::new(persistent_keepalive),

            rate_limiter,
        }
    }

    /// Update the private key and clear existing sessions.
    pub fn set_static_private(
        &mut self,
        static_private: x25519::StaticSecret,
        static_public: x25519::PublicKey,
        rate_limiter: Arc<RateLimiter>,
    ) {
        self.rate_limiter = rate_limiter;
        self.handshake
            .set_static_private(static_private, static_public);
        for s in &mut self.sessions {
            *s = None;
        }
    }

    /// Encapsulate a single packet.
    ///
    /// If there's an active session, return the encapsulated packet. Otherwise, if needed, return
    /// a handshake initiation. `None` is returned if a handshake is already in progress. In that
    /// case, the packet is added to a queue.
    pub fn handle_outgoing_packet(&mut self, packet: Packet) -> Option<WgKind> {
        match self.encapsulate_with_session(packet) {
            Ok(encapsulated_packet) => Some(encapsulated_packet.into()),
            Err(packet) => {
                // If there is no session, queue the packet for future retry
                self.queue_packet(packet);
                // Initiate a new handshake if none is in progress
                self.format_handshake_initiation(false).map(Into::into)
            }
        }
    }

    /// Encapsulate a single packet into a [`WgData`].
    ///
    /// Returns `Err(original_packet)` if there is no active session.
    pub fn encapsulate_with_session(&mut self, packet: Packet) -> Result<Packet<WgData>, Packet> {
        let current = self.current;
        if let Some(ref session) = self.sessions[current % N_SESSIONS] {
            // Send the packet using an established session
            let packet = session.format_packet_data(packet);
            self.timer_tick(TimerName::TimeLastPacketSent);
            // Exclude Keepalive packets from timer update.
            if !packet.is_keepalive() {
                self.timer_tick(TimerName::TimeLastDataPacketSent);
            }
            self.tx_bytes += packet.as_bytes().len();
            Ok(packet)
        } else {
            Err(packet)
        }
    }

    pub fn handle_incoming_packet(&mut self, packet: WgKind) -> TunnResult {
        match packet {
            WgKind::HandshakeInit(p) => self.handle_handshake_init(p),
            WgKind::HandshakeResp(p) => self.handle_handshake_response(p),
            WgKind::CookieReply(p) => self.handle_cookie_reply(&p),
            WgKind::Data(p) => self.handle_data(p),
        }
        .unwrap_or_else(TunnResult::from)
    }

    fn handle_handshake_init(
        &mut self,
        p: Packet<WgHandshakeInit>,
    ) -> Result<TunnResult, WireGuardError> {
        log::debug!("Received handshake_initiation: {}", p.sender_idx);

        let (packet, session) = self.handshake.receive_handshake_initialization(p)?;

        // Store new session in next slot
        let slot = self.next_session_slot();
        self.put_session(slot, session);

        self.timer_tick(TimerName::TimeLastPacketReceived);
        self.timer_tick(TimerName::TimeLastPacketSent);
        self.timer_tick_session_established(false, slot); // New session established, we are not the initiator

        log::debug!("Sending handshake_response: {slot}");

        Ok(TunnResult::WriteToNetwork(packet.into()))
    }

    fn handle_handshake_response(
        &mut self,
        p: Packet<WgHandshakeResp>,
    ) -> Result<TunnResult, WireGuardError> {
        log::debug!(
            "Received handshake_response: {} {}",
            p.receiver_idx,
            p.sender_idx,
        );

        let session = self.handshake.receive_handshake_response(&p)?;

        let mut p = p.into_bytes();
        p.truncate(0);

        let keepalive_packet = session.format_packet_data(p);
        // Store new session in next slot
        let slot = self.next_session_slot();
        self.put_session(slot, session);

        self.timer_tick(TimerName::TimeLastPacketReceived);
        self.timer_tick_session_established(true, slot); // New session established, we are the initiator
        self.set_current_session(slot);

        log::debug!("Sending keepalive");

        Ok(TunnResult::WriteToNetwork(keepalive_packet.into())) // Send a keepalive as a response
    }

    fn handle_cookie_reply(&mut self, p: &WgCookieReply) -> Result<TunnResult, WireGuardError> {
        log::debug!("Received cookie_reply: {}", p.receiver_idx);

        self.handshake.receive_cookie_reply(p)?;
        self.timer_tick(TimerName::TimeLastPacketReceived);
        self.timer_tick(TimerName::TimeCookieReceived);

        log::debug!("Did set cookie");

        Ok(TunnResult::Done)
    }

    /// Update the slot index of the currently used session, if needed.
    fn set_current_session(&mut self, new_slot: usize) {
        let cur_slot = self.current;
        if cur_slot == new_slot {
            // There is nothing to do, already using this session, this is the common case
            return;
        }
        if self.sessions[cur_slot % N_SESSIONS].is_none()
            || self.timers.session_timers[new_slot % N_SESSIONS]
                >= self.timers.session_timers[cur_slot % N_SESSIONS]
        {
            self.current = new_slot;
            log::debug!("New session slot: {new_slot}");
        }
    }

    /// Get the next round-robin session slot index.
    fn next_session_slot(&mut self) -> usize {
        let slot = (self.session_counter as usize) % N_SESSIONS;
        self.session_counter = self.session_counter.wrapping_add(1);
        slot
    }

    /// Place a session into the given slot.
    ///
    /// If the slot was occupied, the old session (and its [`Index`](index_table::Index)) is dropped,
    /// which automatically frees the index from the shared table.
    fn put_session(&mut self, slot: usize, session: session::Session) {
        self.sessions[slot % N_SESSIONS] = Some(session);
    }

    /// Decrypt a data packet, and return a [`TunnResult::WriteToTunnel`] (`Ipv4` or `Ipv6`) if successful.
    fn handle_data(&mut self, packet: Packet<WgData>) -> Result<TunnResult, WireGuardError> {
        let decapsulated_packet = self.decapsulate_with_session(packet)?;

        self.timer_tick(TimerName::TimeLastDataPacketReceived);
        self.rx_bytes += decapsulated_packet.as_bytes().len();

        Ok(TunnResult::WriteToTunnel(decapsulated_packet))
    }

    pub fn decapsulate_with_session(
        &mut self,
        packet: Packet<WgData>,
    ) -> Result<Packet, WireGuardError> {
        let r_idx = packet.header.receiver_idx.get();

        // Search for the matching session.
        // Is this ever not `self.current`?
        let (slot, session) = self
            .sessions
            .iter()
            .enumerate()
            .cycle()
            .skip(self.current)
            .take(N_SESSIONS)
            .filter_map(|(i, s)| s.as_ref().map(|s| (i, s)))
            .find(|(_, s)| s.receiving_index.value() == r_idx)
            .ok_or_else(|| {
                log::trace!("No current session available: {r_idx}");
                WireGuardError::NoCurrentSession
            })?;

        let decapsulated_packet = session.receive_packet_data(packet)?;

        self.set_current_session(slot);

        self.timer_tick(TimerName::TimeLastPacketReceived);

        Ok(decapsulated_packet)
    }

    /// Return a new handshake if appropriate, or `None` otherwise.
    ///
    /// If `force_resend` is true will send a new handshake, even if a handshake
    /// is already in progress (for example when a handshake times out).
    pub fn format_handshake_initiation(
        &mut self,
        force_resend: bool,
    ) -> Option<Packet<WgHandshakeInit>> {
        if self.handshake.is_in_progress() && !force_resend {
            return None;
        }

        if self.handshake.is_expired() {
            self.timers.clear();
        }

        let starting_new_handshake = !self.handshake.is_in_progress();

        let packet = self.handshake.format_handshake_initiation();
        log::debug!("Sending handshake_initiation");

        if starting_new_handshake {
            self.timer_tick(TimerName::TimeLastHandshakeStarted);
        }
        self.timer_tick(TimerName::TimeLastPacketSent);
        Some(packet)
    }

    /// Encapsulate and return all queued packets.
    pub fn get_queued_packets(&mut self) -> impl Iterator<Item = WgKind> {
        std::iter::from_fn(|| {
            self.dequeue_packet()
                .and_then(|packet| self.handle_outgoing_packet(packet))
        })
    }

    /// Push packet to the back of the queue.
    fn queue_packet(&mut self, packet: Packet) {
        if self.packet_queue.len() < MAX_QUEUE_DEPTH {
            // Drop if too many are already in queue
            self.packet_queue.push_back(packet);
        }
    }

    fn dequeue_packet(&mut self) -> Option<Packet> {
        self.packet_queue.pop_front()
    }

    fn estimate_loss(&self) -> f32 {
        let session_idx = self.current;

        let mut weight = 9.0;
        let mut cur_avg = 0.0;
        let mut total_weight = 0.0;

        for i in 0..N_SESSIONS {
            if let Some(ref session) = self.sessions[session_idx.wrapping_sub(i) % N_SESSIONS] {
                let (expected, received) = session.current_packet_cnt();

                let loss = if expected == 0 {
                    0.0
                } else {
                    1.0 - received as f32 / expected as f32
                };

                cur_avg += loss * weight;
                total_weight += weight;
                weight /= 3.0;
            }
        }

        if total_weight == 0.0 {
            0.0
        } else {
            cur_avg / total_weight
        }
    }

    /// Return the receiving indices of all active sessions.
    pub fn active_receiving_indices(&self) -> impl Iterator<Item = u32> + '_ {
        self.sessions
            .iter()
            .filter_map(|s| s.as_ref().map(|s| s.receiving_index.value()))
    }

    /// Return stats from the tunnel:
    /// * Time since last handshake in seconds
    /// * Data bytes sent
    /// * Data bytes received
    pub fn stats(&self) -> (Option<Duration>, usize, usize, f32, Option<u32>) {
        let time = self.time_since_last_handshake();
        let tx_bytes = self.tx_bytes;
        let rx_bytes = self.rx_bytes;
        let loss = self.estimate_loss();
        let rtt = self.handshake.last_rtt;

        (time, tx_bytes, rx_bytes, loss, rtt)
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    #[cfg(feature = "mock_instant")]
    use crate::noise::timers::{REKEY_AFTER_TIME, REKEY_TIMEOUT, TimerName};
    use crate::packet::Ipv4;

    const HANDSHAKE_RATE_LIMIT: u64 = 100;

    use super::*;
    use bytes::BytesMut;
    #[cfg(feature = "mock_instant")]
    use mock_instant::thread_local::MockClock;
    use rand_core::OsRng;

    fn create_two_tuns() -> (Tunn, Tunn) {
        let my_secret_key = x25519_dalek::StaticSecret::random_from_rng(OsRng);
        let my_public_key = x25519_dalek::PublicKey::from(&my_secret_key);

        let their_secret_key = x25519_dalek::StaticSecret::random_from_rng(OsRng);
        let their_public_key = x25519_dalek::PublicKey::from(&their_secret_key);

        let rate_limiter = Arc::new(RateLimiter::new(&my_public_key, HANDSHAKE_RATE_LIMIT));
        let my_tun = Tunn::new(
            my_secret_key,
            their_public_key,
            None,
            None,
            IndexTable::default(),
            rate_limiter,
        );

        let rate_limiter = Arc::new(RateLimiter::new(&their_public_key, HANDSHAKE_RATE_LIMIT));
        let their_tun = Tunn::new(
            their_secret_key,
            my_public_key,
            None,
            None,
            IndexTable::default(),
            rate_limiter,
        );

        (my_tun, their_tun)
    }

    fn create_handshake_init(tun: &mut Tunn) -> Packet<WgHandshakeInit> {
        tun.format_handshake_initiation(false)
            .expect("expected handshake init")
    }

    fn create_handshake_response(
        tun: &mut Tunn,
        handshake_init: Packet<WgHandshakeInit>,
    ) -> Packet<WgHandshakeResp> {
        let handshake_resp = tun.handle_incoming_packet(WgKind::HandshakeInit(handshake_init));
        assert!(
            matches!(handshake_resp, TunnResult::WriteToNetwork(_)),
            "expected WriteToNetwork, {handshake_resp:?}"
        );

        let TunnResult::WriteToNetwork(handshake_resp) = handshake_resp else {
            unreachable!("expected WriteToNetwork");
        };

        let WgKind::HandshakeResp(handshake_resp) = handshake_resp else {
            unreachable!("expected WgHandshakeResp, got {handshake_resp:?}");
        };

        handshake_resp
    }

    fn parse_handshake_resp(
        tun: &mut Tunn,
        handshake_resp: Packet<WgHandshakeResp>,
    ) -> Packet<WgData> {
        let keepalive = tun.handle_incoming_packet(WgKind::HandshakeResp(handshake_resp));
        assert!(matches!(keepalive, TunnResult::WriteToNetwork(_)));

        let TunnResult::WriteToNetwork(keepalive) = keepalive else {
            unreachable!("expected WriteToNetwork")
        };

        let WgKind::Data(keepalive) = keepalive else {
            unreachable!("expected WgData, got {keepalive:?}");
        };

        keepalive
    }

    fn parse_keepalive(tun: &mut Tunn, keepalive: Packet<WgData>) {
        let result = tun.handle_incoming_packet(WgKind::Data(keepalive));
        assert!(matches!(result, TunnResult::WriteToTunnel(p) if p.is_empty()));
    }

    fn create_two_tuns_and_handshake() -> (Tunn, Tunn) {
        let (mut my_tun, mut their_tun) = create_two_tuns();
        let init = create_handshake_init(&mut my_tun);
        let resp = create_handshake_response(&mut their_tun, init);
        let keepalive = parse_handshake_resp(&mut my_tun, resp);
        parse_keepalive(&mut their_tun, keepalive);

        (my_tun, their_tun)
    }

    fn create_ipv4_udp_packet() -> Packet<Ipv4> {
        let header =
            etherparse::PacketBuilder::ipv4([192, 168, 1, 2], [192, 168, 1, 3], 5).udp(5678, 23);
        let payload = [0, 1, 2, 3];
        let mut packet = Vec::<u8>::with_capacity(header.size(payload.len()));
        header.write(&mut packet, &payload).unwrap();
        let packet = Packet::from_bytes(BytesMut::from(&packet[..]));

        packet.try_into_ipvx().unwrap().unwrap_left()
    }

    #[cfg(feature = "mock_instant")]
    fn update_timer_results_in_handshake(tun: &mut Tunn) {
        let packet = tun
            .update_timers()
            .expect("update_timers should succeed")
            .unwrap();
        assert!(matches!(packet, WgKind::HandshakeInit(..)));
    }

    #[test]
    fn create_two_tunnels_linked_to_eachother() {
        let (_my_tun, _their_tun) = create_two_tuns();
    }

    #[test]
    fn handshake_init() {
        let (mut my_tun, _their_tun) = create_two_tuns();
        let _init = create_handshake_init(&mut my_tun);
    }

    #[test]
    // Verify that a valid hanshake is accepted by two linked peers when rate limiting is not
    // applied.
    fn verify_handshake() {
        let (mut my_tun, mut their_tun) = create_two_tuns();
        let init = create_handshake_init(&mut my_tun);
        let resp = create_handshake_response(&mut their_tun, init.clone());

        their_tun
            .rate_limiter
            .verify_handshake(Ipv4Addr::LOCALHOST.into(), init)
            .expect("Handshake init to be valid");

        my_tun
            .rate_limiter
            .verify_handshake(Ipv4Addr::LOCALHOST.into(), resp)
            .expect("Handshake response to be valid");
    }

    #[test]
    #[cfg(feature = "mock_instant")]
    /// Verify that cookie reply is sent when rate limit is hit.
    /// And that handshakes are accepted under load with a valid mac2.
    fn verify_cookie_reply() {
        let forced_handshake_init = |tun: &mut Tunn| {
            tun.format_handshake_initiation(true)
                .expect("expected handshake init")
        };

        let (mut my_tun, their_tun) = create_two_tuns();

        for _ in 0..HANDSHAKE_RATE_LIMIT {
            let init = forced_handshake_init(&mut my_tun);
            their_tun
                .rate_limiter
                .verify_handshake(Ipv4Addr::LOCALHOST.into(), init)
                .expect("Handshake init to be valid");

            MockClock::advance(Duration::from_micros(1));
        }

        // Next handshake should trigger rate limiting
        let init = forced_handshake_init(&mut my_tun);
        let Err(TunnResult::WriteToNetwork(WgKind::CookieReply(cookie_resp))) = their_tun
            .rate_limiter
            .verify_handshake(Ipv4Addr::LOCALHOST.into(), init)
        else {
            panic!("expected cookie reply due to rate limiting");
        };

        // Verify that cookie reply can be processed
        // And that the peer accepts our handshake after that
        my_tun
            .handle_cookie_reply(&cookie_resp)
            .expect("expected cookie reply to be valid");

        let init = forced_handshake_init(&mut my_tun);
        their_tun
            .rate_limiter
            .verify_handshake(Ipv4Addr::LOCALHOST.into(), init)
            .expect("should accept handshake with cookie");
    }

    #[test]
    // Verify that an invalid hanshake is rejected by both linked peers.
    fn reject_handshake() {
        let (mut my_tun, mut their_tun) = create_two_tuns();
        let mut init = create_handshake_init(&mut my_tun);
        let mut resp = create_handshake_response(&mut their_tun, init.clone());

        // Mess with the mac of both the handshake init & handshake response packets.
        std::mem::swap(&mut init.mac1, &mut resp.mac1);

        their_tun
            .rate_limiter
            .verify_handshake(Ipv4Addr::LOCALHOST.into(), init.clone())
            .map(|packet| packet.mac1)
            .expect_err("Handshake init to be invalid");

        my_tun
            .rate_limiter
            .verify_handshake(Ipv4Addr::LOCALHOST.into(), resp)
            .map(|packet| packet.mac1)
            .expect_err("Handshake response to be invalid");
    }

    #[test]
    fn handshake_init_and_response() {
        let (mut my_tun, mut their_tun) = create_two_tuns();
        let init = create_handshake_init(&mut my_tun);
        let _resp = create_handshake_response(&mut their_tun, init);
    }

    #[test]
    fn full_handshake() {
        let (mut my_tun, mut their_tun) = create_two_tuns();
        let init = create_handshake_init(&mut my_tun);
        let resp = create_handshake_response(&mut their_tun, init);
        let _keepalive = parse_handshake_resp(&mut my_tun, resp);
    }

    #[test]
    fn full_handshake_plus_timers() {
        let (mut my_tun, mut their_tun) = create_two_tuns_and_handshake();
        // Time has not yet advanced so their is nothing to do
        assert!(matches!(my_tun.update_timers(), Ok(None)));
        assert!(matches!(their_tun.update_timers(), Ok(None)));
    }

    #[test]
    #[cfg(feature = "mock_instant")]
    fn new_handshake_after_two_mins() {
        let (mut my_tun, mut their_tun) = create_two_tuns_and_handshake();

        // Advance time 1 second and "send" 1 packet so that we send a handshake
        // after the timeout
        MockClock::advance(Duration::from_secs(1));
        assert!(matches!(their_tun.update_timers(), Ok(None)));
        assert!(matches!(my_tun.update_timers(), Ok(None)));
        let sent_packet_buf = create_ipv4_udp_packet();
        let _data = my_tun
            .handle_outgoing_packet(sent_packet_buf.into_bytes())
            .expect("expected encapsulated packet");

        //Advance to timeout
        MockClock::advance(REKEY_AFTER_TIME);
        assert!(matches!(their_tun.update_timers(), Ok(None)));
        update_timer_results_in_handshake(&mut my_tun);
    }

    #[test]
    #[cfg(feature = "mock_instant")]
    fn handshake_no_resp_rekey_timeout() {
        let (mut my_tun, _their_tun) = create_two_tuns();

        let _init = create_handshake_init(&mut my_tun);

        MockClock::advance(REKEY_TIMEOUT);
        update_timer_results_in_handshake(&mut my_tun)
    }

    #[test]
    fn one_ip_packet() {
        let (mut my_tun, mut their_tun) = create_two_tuns_and_handshake();

        let sent_packet_buf = create_ipv4_udp_packet();

        let data = my_tun
            .handle_outgoing_packet(sent_packet_buf.clone().into_bytes())
            .unwrap();

        assert!(matches!(data, WgKind::Data(..)));

        let data = their_tun.handle_incoming_packet(data);
        let recv_packet_buf = if let TunnResult::WriteToTunnel(recv) = data {
            recv
        } else {
            unreachable!("expected WritetoTunnelV4");
        };
        assert_eq!(sent_packet_buf.as_bytes(), recv_packet_buf.as_bytes());
    }

    /// Test that [`Tunn::update_timers`] does not panic if clock jumps back.
    #[test]
    #[cfg(feature = "mock_instant")]
    fn update_timers_handles_backward_time_jump() {
        const PRESENT: Duration = Duration::from_secs(10);
        const PAST: Duration = Duration::from_secs(5);

        MockClock::set_time(Duration::ZERO);

        let (mut my_tun, mut _their_tun) = create_two_tuns_and_handshake();

        // Advance time and update timers
        MockClock::advance(PRESENT);
        my_tun.update_timers().unwrap();

        let time_current_before = my_tun.timers[TimerName::TimeCurrent];
        assert_eq!(time_current_before, PRESENT);
        // Jump back in time
        MockClock::set_time(PAST);

        my_tun.update_timers().unwrap();

        // TimeCurrent timer should never decrease
        let time_current_after = my_tun.timers[TimerName::TimeCurrent];
        assert_eq!(
            time_current_after, PRESENT,
            "TimeCurrent should never decrease"
        );
    }

    /// Test that [`Tunn::time_since_last_handshake`] never decreases if clock jumps back.
    #[test]
    #[cfg(feature = "mock_instant")]
    fn time_since_last_handshake_doesnt_decrease_on_backward_jump() {
        const PRESENT: Duration = Duration::from_secs(60);

        MockClock::set_time(Duration::ZERO);

        let (mut my_tun, mut _their_tun) = create_two_tuns_and_handshake();

        MockClock::advance(PRESENT);
        my_tun.update_timers().unwrap();

        // Verify we have a valid time_since_last_handshake
        let time_since = my_tun.time_since_last_handshake().expect("have handshake");
        assert!(time_since >= PRESENT);
        assert!(time_since > Duration::ZERO);

        // Verify that `time_since_last_handshake` doesn't decrease
        MockClock::set_time(Duration::ZERO);
        my_tun.update_timers().unwrap();

        let time_since_after_jump = my_tun.time_since_last_handshake();
        assert_eq!(
            time_since_after_jump,
            Some(PRESENT),
            "time_since_last_handshake should never decrease"
        );
    }

    /// Test that timers "freeze" if clock jumps back.
    #[test]
    #[cfg(feature = "mock_instant")]
    fn timers_freeze_during_backward_jump() {
        const INITIAL_TIME: Duration = Duration::from_secs(100);
        const JUMPED_BACK_TIME: Duration = Duration::from_secs(95);
        const RESUMED_TIME: Duration = Duration::from_secs(105);

        MockClock::set_time(Duration::ZERO);

        let (mut my_tun, mut _their_tun) = create_two_tuns_and_handshake();

        MockClock::set_time(INITIAL_TIME);
        my_tun.update_timers().unwrap();
        assert_eq!(my_tun.timers[TimerName::TimeCurrent], INITIAL_TIME);

        // Jump backward
        MockClock::set_time(JUMPED_BACK_TIME);
        my_tun.update_timers().unwrap();
        // Time should be frozen at `INITIAL_TIME`
        assert_eq!(my_tun.timers[TimerName::TimeCurrent], INITIAL_TIME);

        // Time should resume after `INITIAL_TIME`
        MockClock::set_time(RESUMED_TIME);
        my_tun.update_timers().unwrap();
        assert_eq!(my_tun.timers[TimerName::TimeCurrent], RESUMED_TIME);
    }
}
