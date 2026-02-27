// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
//
// Modified by Mullvad VPN.
// Copyright (c) 2025 Mullvad VPN.
//
// SPDX-License-Identifier: BSD-3-Clause

use super::handshake::{b2s_hash, b2s_keyed_mac_16, b2s_keyed_mac_16_2, b2s_mac_24};
use crate::noise::handshake::{LABEL_COOKIE, LABEL_MAC1};
use crate::noise::{TunnResult, WireGuardError};
use crate::packet::{Packet, WgCookieReply, WgHandshakeBase, WgKind};

use constant_time_eq::constant_time_eq;
#[cfg(feature = "mock_instant")]
use mock_instant::thread_local::Instant;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

#[cfg(not(feature = "mock_instant"))]
use crate::sleepyinstant::Instant;

use aead::generic_array::GenericArray;
use aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{Key, XChaCha20Poly1305};
use parking_lot::Mutex;
use rand_core::{OsRng, RngCore};

const COOKIE_REFRESH: u64 = 128; // Use 128 and not 120 so the compiler can optimize out the division
const COOKIE_SIZE: usize = 16;
const COOKIE_NONCE_SIZE: usize = 24;

/// How often to reset the under-load counter
const RESET_PERIOD: Duration = Duration::from_secs(1);

type Cookie = [u8; COOKIE_SIZE];

struct IpCounts {
    counts: HashMap<IpAddr, u64>,
    last_reset: Instant,
}

/// There are two places where WireGuard requires "randomness" for cookies
/// * The 24 byte nonce in the cookie massage - here the only goal is to avoid nonce reuse
/// * A secret value that changes every two minutes
///
/// Because the main goal of the cookie is simply for a party to prove ownership of an IP address
/// we can relax the randomness definition a bit, in order to avoid locking, because using less
/// resources is the main goal of any DoS prevention mechanism.
/// In order to avoid locking and calls to rand we derive pseudo random values using the AEAD and
/// some counters.
pub struct RateLimiter {
    /// The key we use to derive the nonce
    nonce_key: [u8; 32],
    /// The key we use to derive the cookie
    secret_key: [u8; 16],
    start_time: Instant,
    /// A single 64 bit counter (should suffice for many years)
    nonce_ctr: AtomicU64,
    mac1_key: [u8; 32],
    cookie_key: Key,
    limit: u64,
    /// Per-source-IP packet counts, reset every `RESET_PERIOD`
    ip_counts: Mutex<IpCounts>,
}

impl RateLimiter {
    /// Create a new rate limiter for handshake packets.
    ///
    /// # Arguments
    ///
    /// * `public_key` - The device's public key, used for cookie generation
    /// * `limit` - Maximum number of packets allowed per rate limiting period
    pub fn new(public_key: &crate::x25519::PublicKey, limit: u64) -> Self {
        let mut secret_key = [0u8; 16];
        OsRng.fill_bytes(&mut secret_key);
        RateLimiter {
            nonce_key: Self::rand_bytes(),
            secret_key,
            start_time: Instant::now(),
            nonce_ctr: AtomicU64::new(0),
            mac1_key: b2s_hash(LABEL_MAC1, public_key.as_bytes()),
            cookie_key: b2s_hash(LABEL_COOKIE, public_key.as_bytes()).into(),
            limit,
            ip_counts: Mutex::new(IpCounts {
                counts: HashMap::new(),
                last_reset: Instant::now(),
            }),
        }
    }

    fn rand_bytes() -> [u8; 32] {
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        key
    }

    /// Reset packet counts (ideally should be called with a period of 1 second)
    pub fn try_reset_count(&self) {
        let current_time = Instant::now();
        let mut ip_counts = self.ip_counts.lock();
        if current_time.duration_since(ip_counts.last_reset) >= RESET_PERIOD {
            ip_counts.counts.clear();
            ip_counts.last_reset = current_time;
        }
    }

    /// Compute the correct cookie value based on the current secret value and the source IP
    fn current_cookie(&self, addr: IpAddr) -> Cookie {
        let mut addr_bytes = [0u8; 16];

        match addr {
            IpAddr::V4(a) => addr_bytes[..4].copy_from_slice(&a.octets()[..]),
            IpAddr::V6(a) => addr_bytes[..].copy_from_slice(&a.octets()[..]),
        }

        // The current cookie for a given IP is the MAC(responder.changing_secret_every_two_minutes,
        // initiator.ip_address) First we derive the secret from the current time, the value
        // of cur_counter would change with time.
        let cur_counter = Instant::now().duration_since(self.start_time).as_secs() / COOKIE_REFRESH;

        // Next we derive the cookie
        b2s_keyed_mac_16_2(&self.secret_key, &cur_counter.to_le_bytes(), &addr_bytes)
    }

    fn nonce(&self) -> [u8; COOKIE_NONCE_SIZE] {
        let ctr = self.nonce_ctr.fetch_add(1, Ordering::Relaxed);

        b2s_mac_24(&self.nonce_key, &ctr.to_le_bytes())
    }

    /// Increment the per-source-IP handshake counter and return whether it exceeds `self.limit`.
    ///
    /// Counters are cleared every `RESET_PERIOD` by [`try_reset_count`](Self::try_reset_count),
    /// so each IP is independently allowed `limit` handshakes per period.
    fn is_under_load(&self, src_addr: IpAddr) -> bool {
        let mut ip_counts = self.ip_counts.lock();
        let count = ip_counts.counts.entry(src_addr).or_insert(0);
        *count += 1;
        *count > self.limit
    }

    pub(crate) fn format_cookie_reply(
        &self,
        idx: u32,
        cookie: Cookie,
        mac1: &[u8],
    ) -> WgCookieReply {
        let mut wg_cookie_reply = WgCookieReply::new();

        // msg.message_type = 3
        // msg.reserved_zero = { 0, 0, 0 }
        // msg.receiver_index = little_endian(initiator.sender_index)
        wg_cookie_reply.receiver_idx.set(idx);
        wg_cookie_reply.nonce = self.nonce();

        let cipher = XChaCha20Poly1305::new(&self.cookie_key);

        let iv = GenericArray::from_slice(&wg_cookie_reply.nonce);

        wg_cookie_reply.encrypted_cookie.encrypted = cookie;
        let tag = cipher
            .encrypt_in_place_detached(iv, mac1, &mut wg_cookie_reply.encrypted_cookie.encrypted)
            .expect("wg_cookie_reply is large enough");

        wg_cookie_reply.encrypted_cookie.tag = tag.into();
        wg_cookie_reply
    }

    /// Decode the packet as wireguard packet.
    /// Then, verify the MAC fields on the packet (if any), and apply rate limiting if needed.
    pub fn verify_packet(&self, src_addr: IpAddr, packet: Packet) -> Result<WgKind, TunnResult> {
        let packet = packet
            .try_into_wg()
            .map_err(|_err| TunnResult::Err(WireGuardError::InvalidPacket))?;

        // Verify and rate limit handshake messages only
        match packet {
            WgKind::HandshakeInit(packet) => self
                .verify_handshake(src_addr, packet)
                .map(WgKind::HandshakeInit),
            WgKind::HandshakeResp(packet) => self
                .verify_handshake(src_addr, packet)
                .map(WgKind::HandshakeResp),
            _ => Ok(packet),
        }
    }

    /// Verify the MAC fields on the handshake, and apply rate limiting if needed.
    pub(crate) fn verify_handshake<P: WgHandshakeBase>(
        &self,
        src_addr: IpAddr,
        handshake: Packet<P>,
    ) -> Result<Packet<P>, TunnResult> {
        let sender_idx = handshake.sender_idx();
        let mac1 = handshake.mac1();
        let mac2 = handshake.mac2();

        let computed_mac1 = b2s_keyed_mac_16(&self.mac1_key, handshake.until_mac1());
        if !constant_time_eq(&computed_mac1, mac1) {
            return Err(TunnResult::Err(WireGuardError::InvalidMac));
        }

        if self.is_under_load(src_addr) {
            let cookie = self.current_cookie(src_addr);
            let computed_mac2 = b2s_keyed_mac_16_2(&cookie, handshake.until_mac1(), mac1);

            if !constant_time_eq(&computed_mac2, mac2) {
                let cookie_reply = self.format_cookie_reply(sender_idx, cookie, mac1);
                let packet = handshake.overwrite_with(&cookie_reply);
                return Err(TunnResult::WriteToNetwork(packet.into()));
            }

            // If under load but mac2 is valid, allow the handshake
            return Ok(handshake);
        }

        Ok(handshake)
    }
}
