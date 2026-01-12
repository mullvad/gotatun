// Copyright (c) 2026 Mullvad VPN AB. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use std::sync::Arc;

use tokio::sync::{Mutex, RwLock};

#[cfg(feature = "tun")]
use crate::device::Error;
use crate::{
    device::{
        Device, DeviceState, allowed_ips::AllowedIps, api::ApiServer, peer::builder::PeerBuilder,
    },
    task::Task,
    tun::{IpRecv, IpSend, tun_async_device::TunDevice},
    udp::{UdpTransportFactory, socket::UdpSocketFactory},
};

use super::Connection;

pub struct Nul;

pub struct DeviceBuilder<Udp, TunTx, TunRx> {
    udp: Udp,
    tun_tx: TunTx,
    tun_rx: TunRx,
    uapi: Option<ApiServer>,

    // TODO: consider turning this into a typestate, and adding a special case for single peer
    peers: Vec<PeerBuilder>,
}

impl DeviceBuilder<Nul, Nul, Nul> {
    pub const fn new() -> Self {
        Self {
            udp: Nul,
            tun_tx: Nul,
            tun_rx: Nul,
            uapi: None,
            peers: Vec::new(),
        }
    }
}

impl<X, Y> DeviceBuilder<Nul, X, Y> {
    pub fn with_default_udp(self) -> DeviceBuilder<UdpSocketFactory, X, Y> {
        self.with_udp(UdpSocketFactory)
    }

    pub fn with_udp<Udp: UdpTransportFactory>(self, udp: Udp) -> DeviceBuilder<Udp, X, Y> {
        DeviceBuilder {
            udp,
            tun_tx: self.tun_tx,
            tun_rx: self.tun_rx,
            uapi: self.uapi,
            peers: self.peers,
        }
    }
}

impl<X> DeviceBuilder<X, Nul, Nul> {
    /// Create a TUN device with the given name.
    ///
    /// # Warning
    ///
    /// If this is used on Windows, you are recommended to enable the `verify_binary_signature`
    /// feature for the `tun` crate. By default, `tun` will load `wintun.dll` using the
    /// [default search order], which includes the `PATH` environment variable.
    ///
    /// The recommended way is to use [`Self::with_ip`] and pass an absolute path to `wintun.dll`
    /// to the `tun` config.
    ///
    /// [default search order]: <https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order>
    #[cfg(feature = "tun")]
    pub fn create_tun(
        self,
        tun_name: &str,
    ) -> Result<DeviceBuilder<X, TunDevice, TunDevice>, Error> {
        let mut tun_config = tun::Configuration::default();
        tun_config.tun_name(tun_name);
        #[cfg(target_os = "macos")]
        tun_config.platform_config(|p| {
            p.enable_routing(false);
        });
        // FIXME: for wintun, must set path or enable signature check
        let tun = tun::create_as_async(&tun_config)?;
        let tun = TunDevice::from_tun_device(tun)?;

        Ok(self.with_ip(tun))
    }

    /// Add a channel where the device will read and write IP packets. This is normally a a [`TunDevice`],
    /// but can be any type that implements both [`IpSend`] and [`IpRecv`].
    pub fn with_ip<Ip: IpSend + IpRecv + Clone>(self, ip: Ip) -> DeviceBuilder<X, Ip, Ip> {
        self.with_ip_pair(ip.clone(), ip)
    }

    /// Add separate channels for sending and receiving IP packets.
    pub fn with_ip_pair<IpTx: IpSend, IpRx: IpRecv>(
        self,
        ip_tx: IpTx,
        ip_rx: IpRx,
    ) -> DeviceBuilder<X, IpTx, IpRx> {
        DeviceBuilder {
            udp: self.udp,
            tun_tx: ip_tx,
            tun_rx: ip_rx,
            uapi: self.uapi,
            peers: self.peers,
        }
    }
}

impl<X, Y, Z> DeviceBuilder<X, Y, Z> {
    pub fn with_uapi(mut self, uapi: ApiServer) -> Self {
        self.uapi = Some(uapi);
        self
    }

    pub fn with_peer(mut self, peer: PeerBuilder) -> Self {
        self.peers.push(peer);
        self
    }
}

impl<Udp: UdpTransportFactory, TunTx: IpSend, TunRx: IpRecv> DeviceBuilder<Udp, TunTx, TunRx> {
    pub async fn build(self) -> Result<Device<(Udp, TunTx, TunRx)>, Error> {
        let mut state = DeviceState {
            api: None,
            udp_factory: self.udp,
            tun_tx: Arc::new(Mutex::new(self.tun_tx)),
            tun_rx_mtu: self.tun_rx.mtu(),
            tun_rx: Arc::new(Mutex::new(self.tun_rx)),
            fwmark: Default::default(),
            key_pair: Default::default(),
            next_index: Default::default(),
            peers: Default::default(),
            peers_by_idx: Default::default(),
            peers_by_ip: AllowedIps::new(),
            rate_limiter: None,
            port: 0,
            connection: None,
        };

        let has_peers = !self.peers.is_empty();
        for peer in self.peers {
            let index = state.next_index();
            state.add_peer(peer, index);
        }

        let inner = Arc::new(RwLock::new(state));

        if let Some(uapi) = self.uapi {
            inner.try_write().expect("lock is not taken").api = Some(Task::spawn(
                "uapi",
                DeviceState::handle_api(Arc::downgrade(&inner), uapi),
            ))
        }

        if has_peers {
            let con = Connection::set_up(inner.clone()).await?;
            let mut state = inner.write().await;
            state.connection = Some(con);
        }

        Ok(Device { inner })
    }
}
