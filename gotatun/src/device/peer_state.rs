// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
//
// Modified by Mullvad VPN.
// Copyright (c) 2025 Mullvad VPN.
//
// SPDX-License-Identifier: BSD-3-Clause

use ipnetwork::IpNetwork;

use std::net::{IpAddr, SocketAddr};

use crate::device::AllowedIps;
#[cfg(feature = "daita")]
use crate::device::daita::{DaitaHooks, DaitaSettings};
use crate::noise::Tunn;
use crate::noise::errors::WireGuardError;
#[cfg(feature = "daita")]
use crate::packet;
use crate::packet::WgKind;
#[cfg(feature = "daita")]
use crate::tun::MtuWatcher;
#[cfg(feature = "daita")]
use crate::udp::UdpSend;

#[derive(Default, Debug)]
pub struct Endpoint {
    pub addr: Option<SocketAddr>,
}

pub struct PeerState {
    /// The associated tunnel struct
    pub(crate) tunnel: Tunn,
    pub(crate) endpoint: Endpoint,
    pub(crate) allowed_ips: AllowedIps<()>,
    pub(crate) preshared_key: Option<[u8; 32]>,

    #[cfg(feature = "daita")]
    daita_settings: Option<DaitaSettings>,
    #[cfg(feature = "daita")]
    pub(crate) daita: Option<DaitaHooks>,
}

impl PeerState {
    pub fn new(
        tunnel: Tunn,
        endpoint: Option<SocketAddr>,
        allowed_ips: &[IpNetwork],
        preshared_key: Option<[u8; 32]>,
        #[cfg(feature = "daita")] daita_settings: Option<DaitaSettings>,
    ) -> PeerState {
        Self {
            tunnel,
            endpoint: Endpoint { addr: endpoint },
            allowed_ips: allowed_ips.iter().map(|ip| (ip, ())).collect(),
            preshared_key,
            #[cfg(feature = "daita")]
            daita_settings,
            #[cfg(feature = "daita")]
            daita: None,
        }
    }

    #[cfg(feature = "daita")]
    pub(crate) async fn maybe_start_daita<US: UdpSend + Clone + 'static>(
        peer: &std::sync::Arc<tokio::sync::Mutex<PeerState>>,
        pool: packet::PacketBufPool,
        tun_rx_mtu: MtuWatcher,
        udp_tx_v4: US,
        udp_tx_v6: US,
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
            udp_tx_v4,
            udp_tx_v6,
            pool,
        )?);

        Ok(())
    }

    pub fn update_timers(&mut self) -> Result<Option<WgKind>, WireGuardError> {
        self.tunnel.update_timers()
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

    pub fn set_endpoint(&mut self, addr: SocketAddr) {
        self.endpoint.addr = Some(addr);
    }

    pub fn is_allowed_ip<I: Into<IpAddr>>(&self, addr: I) -> bool {
        self.allowed_ips.find(addr.into()).is_some()
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
}
