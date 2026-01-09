// Copyright (c) 2026 Mullvad VPN AB. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use std::sync::Arc;

use tokio::sync::{Mutex, RwLock};

#[cfg(feature = "tun")]
use crate::{device::Error, tun::tun_async_device::TunDevice};
use crate::{
    device::{Device, DeviceState, allowed_ips::AllowedIps, transports::DeviceTransports},
    tun::IpRecv,
};

#[cfg(feature = "tun")]
impl<T: DeviceTransports<IpRecv = TunDevice, IpSend = TunDevice>> Device<T> {
    /// Create a [`Device`] with a new TUN device.
    pub async fn from_tun_name(
        udp_factory: T::UdpTransportFactory,
        tun_name: &str,
    ) -> Result<Device<T>, Error> {
        let mut tun_config = tun::Configuration::default();
        tun_config.tun_name(tun_name);
        #[cfg(target_os = "macos")]
        tun_config.platform_config(|p| {
            p.enable_routing(false);
        });
        let tun = tun::create_as_async(&tun_config)?;
        let tun = TunDevice::from_tun_device(tun)?;
        let (tun_tx, tun_rx) = (tun.clone(), tun);
        Ok(Device::new(udp_factory, tun_tx, tun_rx).await)
    }
}

impl<T: DeviceTransports> Device<T> {
    /// Create a [`Device`] using the provided transports.
    ///
    /// - See also: [`Device::from_tun_name`].
    pub async fn new(
        udp_factory: T::UdpTransportFactory,
        tun_tx: T::IpSend,
        tun_rx: T::IpRecv,
    ) -> Device<T> {
        let state = DeviceState {
            api: None,
            udp_factory: udp_factory,
            tun_tx: Arc::new(Mutex::new(tun_tx)),
            tun_rx_mtu: tun_rx.mtu(),
            tun_rx: Arc::new(Mutex::new(tun_rx)),
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

        Device { inner }
    }
}
