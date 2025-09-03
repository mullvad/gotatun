// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use parking_lot::RwLock;
use tokio::sync::Mutex;

use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;

use crate::device::AllowedIps;
use crate::device::daita::{DaitaHooks, DaitaSettings};
use crate::noise::Tunn;
use crate::noise::errors::WireGuardError;
use crate::packet::{self, WgKind};
use crate::tun::MtuWatcher;
use crate::udp::UdpSend;

#[derive(Default, Debug)]
pub struct Endpoint {
    pub addr: Option<SocketAddr>,
}

pub struct Peer {
    /// The associated tunnel struct
    pub(crate) tunnel: Tunn,
    /// The index the tunnel uses
    index: u32,
    endpoint: RwLock<Endpoint>,
    allowed_ips: AllowedIps<()>,
    preshared_key: Option<[u8; 32]>,

    daita_settings: Option<DaitaSettings>,
    pub(crate) daita: Option<DaitaHooks>,
}

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub struct AllowedIP {
    pub addr: IpAddr,
    pub cidr: u8,
}

impl FromStr for AllowedIP {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let ip: Vec<&str> = s.split('/').collect();
        if ip.len() != 2 {
            return Err("Invalid IP format".to_owned());
        }

        let (addr, cidr) = (ip[0].parse::<IpAddr>(), ip[1].parse::<u8>());
        match (addr, cidr) {
            (Ok(addr @ IpAddr::V4(_)), Ok(cidr)) if cidr <= 32 => Ok(AllowedIP { addr, cidr }),
            (Ok(addr @ IpAddr::V6(_)), Ok(cidr)) if cidr <= 128 => Ok(AllowedIP { addr, cidr }),
            _ => Err("Invalid IP format".to_owned()),
        }
    }
}

impl Peer {
    pub fn new(
        tunnel: Tunn,
        index: u32,
        endpoint: Option<SocketAddr>,
        allowed_ips: &[AllowedIP],
        preshared_key: Option<[u8; 32]>,
        daita_settings: Option<DaitaSettings>,
    ) -> Peer {
        Peer {
            tunnel,
            index,
            endpoint: RwLock::new(Endpoint { addr: endpoint }),
            allowed_ips: allowed_ips.iter().map(|ip| (ip, ())).collect(),
            preshared_key,
            daita_settings,
            daita: None,
        }
    }

    pub async fn maybe_start_daita<US: UdpSend + Clone + 'static>(
        peer: &Arc<Mutex<Peer>>,
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
            Arc::downgrade(peer),
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

    pub fn daita_settings(&self) -> Option<&DaitaSettings> {
        self.daita_settings.as_ref()
    }

    pub fn daita(&self) -> Option<&DaitaHooks> {
        self.daita.as_ref()
    }

    pub fn endpoint(&self) -> parking_lot::RwLockReadGuard<'_, Endpoint> {
        self.endpoint.read()
    }

    pub fn set_endpoint(&self, addr: SocketAddr) {
        self.endpoint.write().addr = Some(addr);
    }

    pub fn is_allowed_ip<I: Into<IpAddr>>(&self, addr: I) -> bool {
        self.allowed_ips.find(addr.into()).is_some()
    }

    pub fn allowed_ips(&self) -> impl Iterator<Item = (IpAddr, u8)> + '_ {
        self.allowed_ips.iter().map(|(_, ip, cidr)| (ip, cidr))
    }

    pub fn time_since_last_handshake(&self) -> Option<std::time::Duration> {
        self.tunnel.time_since_last_handshake()
    }

    pub fn persistent_keepalive(&self) -> Option<u16> {
        self.tunnel.persistent_keepalive()
    }

    pub fn preshared_key(&self) -> Option<&[u8; 32]> {
        self.preshared_key.as_ref()
    }

    pub fn index(&self) -> u32 {
        self.index
    }
}
