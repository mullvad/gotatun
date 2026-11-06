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

use ipnetwork::IpNetwork;

use std::net::SocketAddr;

use tokio::sync::watch;

use crate::Instant;
use crate::device::AllowedIps;
#[cfg(feature = "daita")]
use crate::device::daita::{DaitaHooks, DaitaSettings};
use crate::noise::errors::WireGuardError;
use crate::noise::{Tunn, TunnResult};
#[cfg(feature = "daita")]
use crate::packet;
use crate::packet::{Packet, WgHandshakeInit, WgKind};
#[cfg(feature = "daita")]
use crate::tun::MtuWatcher;
#[cfg(feature = "daita")]
use crate::udp::UdpSend;

#[derive(Default, Debug)]
pub struct Endpoint {
    pub addr: Option<SocketAddr>,
}

/// A handshake initiated by [`PeerState::force_handshake`].
pub struct PendingHandshake {
    /// Notified when a handshake initiated by us completes.
    pub completed: watch::Receiver<()>,
    /// The initiation to send and where to send it, or `None` if one is already in flight.
    pub initiation: Option<(Packet<WgHandshakeInit>, SocketAddr)>,
}

pub struct PeerState {
    /// The associated tunnel struct
    pub(crate) tunnel: Tunn,
    pub(crate) endpoint: Endpoint,
    pub(crate) allowed_ips: AllowedIps<()>,

    #[cfg(feature = "daita")]
    daita_settings: Option<DaitaSettings>,
    #[cfg(feature = "daita")]
    pub(crate) daita: Option<DaitaHooks>,

    /// Notified whenever a handshake that we initiated completes.
    handshake_completed: watch::Sender<()>,
}

impl PeerState {
    pub fn new(
        tunnel: Tunn,
        endpoint: Option<SocketAddr>,
        allowed_ips: &[IpNetwork],
        #[cfg(feature = "daita")] daita_settings: Option<DaitaSettings>,
    ) -> PeerState {
        Self {
            tunnel,
            endpoint: Endpoint { addr: endpoint },
            allowed_ips: allowed_ips.iter().map(|ip| (ip, ())).collect(),
            #[cfg(feature = "daita")]
            daita_settings,
            #[cfg(feature = "daita")]
            daita: None,
            handshake_completed: watch::Sender::new(()),
        }
    }

    /// Process an incoming packet received from `addr`.
    ///
    /// Any authenticated packet updates the peer endpoint to `addr`. Waiters are notified if the
    /// packet completes a handshake that we initiated.
    pub fn handle_incoming_packet(&mut self, packet: WgKind, addr: SocketAddr) -> TunnResult {
        let is_handshake_resp = matches!(packet, WgKind::HandshakeResp(_));
        let result = self.tunnel.handle_incoming_packet(packet);
        match result {
            TunnResult::WriteToNetwork(_) => {
                self.endpoint.addr = Some(addr);
                if is_handshake_resp {
                    self.notify_handshake_completed();
                }
            }
            TunnResult::WriteToTunnel(_) => self.endpoint.addr = Some(addr),
            // Don't update the peer endpoint on cookie replies, for consistency
            // with both the Linux kernel and wireguard-go.
            TunnResult::Done | TunnResult::Err(_) => {}
        }
        result
    }

    /// Subscribe to completions of handshakes that we initiated.
    ///
    /// The receiver only sees completions that happen after this call.
    fn subscribe_handshake_completed(&self) -> watch::Receiver<()> {
        self.handshake_completed.subscribe()
    }

    /// Wake everyone waiting on [`Self::subscribe_handshake_completed`].
    fn notify_handshake_completed(&self) {
        self.handshake_completed.send_replace(());
    }

    #[cfg(feature = "daita")]
    pub(crate) async fn maybe_start_daita<US: UdpSend + Clone + 'static>(
        peer: &std::sync::Arc<tokio::sync::Mutex<PeerState>>,
        pool: packet::PacketBufPool,
        tun_rx_mtu: MtuWatcher,
        udp_tx: US,
    ) -> Result<(), super::Error> {
        let mut peer_g = peer.lock().await;
        let Some(daita_settings) = peer_g.daita_settings.clone() else {
            // No DAITA settings; disabled
            return Ok(());
        };

        peer_g.daita = Some(DaitaHooks::new(
            daita_settings,
            std::sync::Arc::downgrade(peer),
            tun_rx_mtu,
            udp_tx,
            pool,
        )?);

        Ok(())
    }

    pub fn update_timers(&mut self) -> Result<Option<WgKind>, WireGuardError> {
        self.tunnel.update_timers()
    }

    /// The earliest instant at which [`Self::update_timers`] could next produce work for
    /// this peer, or `None` if nothing is pending.
    ///
    /// See [`Tunn::next_timer_deadline`] for when the answer stops being valid, and for
    /// what it does not cover. A device that waits on this instead of polling must also
    /// keep driving the device-wide work that is not part of a peer's timers: the shared
    /// [`RateLimiter::try_reset_count`](crate::noise::rate_limiter::RateLimiter::try_reset_count)
    /// and the stale-index sweep.
    // `PeerState` is crate-internal and `Device::handle_timers` still polls on a fixed
    // tick, so nothing in the crate calls this yet. It is the peer-level mirror of
    // `Tunn::next_timer_deadline`, kept beside `update_timers` for a deadline-driven
    // device loop.
    #[expect(
        dead_code,
        reason = "mirrors update_timers for a future deadline-driven loop"
    )]
    pub fn next_timer_deadline(&self) -> Option<Instant> {
        self.tunnel.next_timer_deadline()
    }

    /// How long until [`Self::next_timer_deadline`], or `None` if nothing is pending.
    ///
    /// See [`Tunn::time_to_next_timer`].
    #[expect(
        dead_code,
        reason = "mirrors update_timers for a future deadline-driven loop"
    )]
    pub fn time_to_next_timer(&self) -> Option<std::time::Duration> {
        self.tunnel.time_to_next_timer()
    }

    /// Drop all sessions and reset the tunnel, forcing a fresh handshake.
    pub fn reset(&mut self) {
        self.tunnel.reset();
    }

    /// Start a handshake unless there is an active session or our own initiation is in flight.
    ///
    /// Returns `None` if there is an active session.
    pub fn force_handshake(&mut self) -> Result<Option<PendingHandshake>, super::Error> {
        if self.tunnel.has_active_session() {
            return Ok(None);
        }
        let endpoint_addr = self.endpoint.addr.ok_or(super::Error::NoEndpoint)?;

        // Subscribe before creating the initiation so that a fast response cannot be missed
        let completed = self.subscribe_handshake_completed();

        // `None` means that our own initiation is already in flight
        let initiation = self
            .tunnel
            .format_handshake_initiation(false)
            .map(|packet| (packet, endpoint_addr));

        Ok(Some(PendingHandshake {
            completed,
            initiation,
        }))
    }

    #[cfg(feature = "daita")]
    pub fn daita_settings(&self) -> Option<&DaitaSettings> {
        self.daita_settings.as_ref()
    }

    #[cfg(feature = "daita")]
    pub fn daita(&self) -> Option<&DaitaHooks> {
        self.daita.as_ref()
    }

    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    pub fn allowed_ips(&self) -> impl Iterator<Item = IpNetwork> + '_ {
        self.allowed_ips.iter().map(|((), network)| network)
    }

    pub fn time_since_last_handshake(&self) -> Option<std::time::Duration> {
        self.tunnel.time_since_last_handshake()
    }

    pub fn persistent_keepalive(&self) -> Option<u16> {
        self.tunnel.persistent_keepalive()
    }

    pub fn preshared_key(&self) -> Option<[u8; 32]> {
        self.tunnel.preshared_key()
    }
}
