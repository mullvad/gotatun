// Copyright (c) 2026 Mullvad VPN AB. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use std::sync::Arc;

use tokio::sync::{Mutex, RwLock};

#[cfg(feature = "tun")]
use crate::device::Error;
use crate::{
    device::{Device, DeviceState, allowed_ips::AllowedIps, api::ApiServer},
    task::Task,
    tun::{IpRecv, IpSend, tun_async_device::TunDevice},
    udp::{UdpTransportFactory, socket::UdpSocketFactory},
};

pub struct Nul;

pub struct DeviceBuilder<Udp, TunTx, TunRx> {
    udp: Udp,
    tun_tx: TunTx,
    tun_rx: TunRx,
    uapi: Option<ApiServer>,
}

impl DeviceBuilder<Nul, Nul, Nul> {
    pub fn new() -> Self {
        Self {
            udp: Nul,
            tun_tx: Nul,
            tun_rx: Nul,
            uapi: None,
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
        }
    }
}

impl<X> DeviceBuilder<X, Nul, Nul> {
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
        let tun = tun::create_as_async(&tun_config)?;
        let tun = TunDevice::from_tun_device(tun)?;

        Ok(self.with_tun(tun))
    }

    pub fn with_tun<Tun: IpSend + IpRecv + Clone>(self, tun: Tun) -> DeviceBuilder<X, Tun, Tun> {
        self.with_tun_pair(tun.clone(), tun)
    }

    pub fn with_tun_pair<TunTx: IpSend, TunRx: IpRecv>(
        self,
        tun_tx: TunTx,
        tun_rx: TunRx,
    ) -> DeviceBuilder<X, TunTx, TunRx> {
        DeviceBuilder {
            udp: self.udp,
            tun_tx,
            tun_rx,
            uapi: self.uapi,
        }
    }
}

impl<X, Y, Z> DeviceBuilder<X, Y, Z> {
    pub fn with_uapi(mut self, uapi: ApiServer) -> Self {
        self.uapi = Some(uapi);
        self
    }
}

impl<Udp: UdpTransportFactory, TunTx: IpSend, TunRx: IpRecv> DeviceBuilder<Udp, TunTx, TunRx> {
    pub fn build(self) -> Device<(Udp, TunTx, TunRx)> {
        let state = DeviceState {
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

        let inner = Arc::new(RwLock::new(state));

        if let Some(uapi) = self.uapi {
            inner.try_write().expect("lock is not taken").api = Some(Task::spawn(
                "uapi",
                DeviceState::handle_api(Arc::downgrade(&inner), uapi),
            ))
        }

        Device { inner }
    }
}
