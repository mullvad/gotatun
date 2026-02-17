// Copyright (c) 2026 Mullvad VPN AB. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use std::sync::Arc;

use tokio::sync::{Mutex, RwLock};
use x25519_dalek::{PublicKey, StaticSecret};

#[cfg(feature = "tun")]
use crate::tun::tun_async_device::TunDevice;
use crate::{device::Error, noise::rate_limiter::RateLimiter};
use crate::{
    device::{Device, DeviceState, allowed_ips::AllowedIps, peer::Peer, uapi::UapiServer},
    task::Task,
    tun::{IpRecv, IpSend},
    udp::{UdpTransportFactory, socket::UdpSocketFactory},
};

use super::{Connection, HANDSHAKE_RATE_LIMIT};

/// Uninitialized [`DeviceBuilder`] transport parameter.
pub struct Nul;

/// Builder for a [`Device`].
///
/// The type-parameters represent the final [device transport] implementation.
///
/// [device transport]: crate::device::transports::DeviceTransports
pub struct DeviceBuilder<Udp, TunTx, TunRx> {
    udp: Udp,
    tun_tx: TunTx,
    tun_rx: TunRx,
    private_key: Option<StaticSecret>,
    port: u16,
    uapi: Option<UapiServer>,

    // TODO: consider turning this into a typestate, and adding a special case for single peer
    peers: Vec<Peer>,

    #[cfg(target_os = "linux")]
    fwmark: Option<u32>,
}

impl Default for DeviceBuilder<Nul, Nul, Nul> {
    fn default() -> Self {
        Self::new()
    }
}

impl DeviceBuilder<Nul, Nul, Nul> {
    /// Create a new [`DeviceBuilder`].
    /// A final [`Device`] is assembled with [`DeviceBuilder::build`].
    ///
    /// # Example
    /// ```no_run
    /// use gotatun::device::DeviceBuilder;
    ///
    /// let device = DeviceBuilder::new()
    ///     .with_default_udp()
    ///     .create_tun("tun").unwrap()
    ///     .build();
    /// ```
    pub const fn new() -> Self {
        Self {
            udp: Nul,
            tun_tx: Nul,
            tun_rx: Nul,
            private_key: None,
            uapi: None,
            port: 0,
            peers: Vec::new(),
            #[cfg(target_os = "linux")]
            fwmark: None,
        }
    }
}

impl<X, Y> DeviceBuilder<Nul, X, Y> {
    /// Create a WireGuard device that reads/writes incoming/outgoing packets using a UDP socket. This is the conventional device kind.
    pub fn with_default_udp(self) -> DeviceBuilder<UdpSocketFactory, X, Y> {
        self.with_udp(UdpSocketFactory)
    }

    pub fn with_udp<Udp: UdpTransportFactory>(self, udp: Udp) -> DeviceBuilder<Udp, X, Y> {
        DeviceBuilder {
            udp,
            tun_tx: self.tun_tx,
            tun_rx: self.tun_rx,
            private_key: self.private_key,
            uapi: self.uapi,
            port: self.port,
            peers: self.peers,
            #[cfg(target_os = "linux")]
            fwmark: self.fwmark,
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
        let tun = TunDevice::from_name(tun_name)?;
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
            private_key: self.private_key,
            uapi: self.uapi,
            port: self.port,
            peers: self.peers,
            #[cfg(target_os = "linux")]
            fwmark: self.fwmark,
        }
    }
}

impl<X, Y, Z> DeviceBuilder<X, Y, Z> {
    /// Set the private key of the device.
    pub fn with_private_key(mut self, private_key: StaticSecret) -> Self {
        self.private_key = Some(private_key);
        self
    }

    pub fn with_uapi(mut self, uapi: UapiServer) -> Self {
        self.uapi = Some(uapi);
        self
    }

    pub fn with_peer(mut self, peer: Peer) -> Self {
        self.peers.push(peer);
        self
    }

    pub fn with_peers(mut self, peers: impl IntoIterator<Item = Peer>) -> Self {
        self.peers.extend(peers);
        self
    }

    pub const fn with_listen_port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }

    #[cfg(target_os = "linux")]
    pub const fn with_fwmark(mut self, fwmark: u32) -> Self {
        self.fwmark = Some(fwmark);
        self
    }
}

impl<Udp: UdpTransportFactory, TunTx: IpSend, TunRx: IpRecv> DeviceBuilder<Udp, TunTx, TunRx> {
    pub async fn build(self) -> Result<Device<(Udp, TunTx, TunRx)>, Error> {
        #[cfg(target_os = "linux")]
        let fwmark = self.fwmark;
        #[cfg(not(target_os = "linux"))]
        let fwmark = None;

        let mut state = DeviceState {
            api: None,
            udp_factory: self.udp,
            tun_tx: Arc::new(Mutex::new(self.tun_tx)),
            tun_rx_mtu: self.tun_rx.mtu(),
            tun_rx: Arc::new(Mutex::new(self.tun_rx)),
            fwmark,
            key_pair: None,
            next_index: Default::default(),
            peers: Default::default(),
            peers_by_idx: Default::default(),
            peers_by_ip: AllowedIps::new(),
            rate_limiter: None,
            port: self.port,
            connection: None,
        };

        if let Some(private_key) = self.private_key {
            let _ = state.set_key(private_key);
        }

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
