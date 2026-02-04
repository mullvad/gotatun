// Copyright (c) 2026 Mullvad VPN AB. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use std::sync::Arc;

use tokio::sync::{Mutex, RwLock};

use crate::device::Error;
#[cfg(feature = "tun")]
use crate::tun::tun_async_device::TunDevice;
use crate::{
    device::{Device, DeviceState, allowed_ips::AllowedIps, peer::Peer, uapi::UapiServer},
    task::Task,
    tun::{IpRecv, IpSend},
    udp::{UdpTransportFactory, socket::UdpSocketFactory},
};

use super::Connection;

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

    /// Create a WireGuard device with a custom [`UdpTransportFactory`].
    ///
    /// See also [`with_default_udp`](Self::with_default_udp).
    pub fn with_udp<Udp: UdpTransportFactory>(self, udp: Udp) -> DeviceBuilder<Udp, X, Y> {
        DeviceBuilder {
            udp,
            tun_tx: self.tun_tx,
            tun_rx: self.tun_rx,
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

    /// Set the channel where the device will read and write IP packets. This is normally a
    /// [`TunDevice`], but can be any type that implements both [`IpSend`] and [`IpRecv`].
    pub fn with_ip<Ip: IpSend + IpRecv + Clone>(self, ip: Ip) -> DeviceBuilder<X, Ip, Ip> {
        self.with_ip_pair(ip.clone(), ip)
    }

    /// Like [`with_ip`](Self::with_ip), but with separate channels for sending and receiving IP packets.
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
            port: self.port,
            peers: self.peers,
            #[cfg(target_os = "linux")]
            fwmark: self.fwmark,
        }
    }
}

impl<X, Y, Z> DeviceBuilder<X, Y, Z> {
    /// Add an UAPI server to this WireGuard device.
    ///
    /// Calling this twice will overwrite the previous `uapi`.
    pub fn with_uapi(mut self, uapi: UapiServer) -> Self {
        self.uapi = Some(uapi);
        self
    }

    /// Add a [`Peer`] to this WireGuard device. May be called multiple times.
    ///
    /// Peers can also be added using [`Device::write`].
    pub fn with_peer(mut self, peer: Peer) -> Self {
        self.peers.push(peer);
        self
    }

    /// Add multiple [`Peer`] to this WireGuard device. May be called multiple times.
    ///
    /// Peers can also be added using [`Device::write`].
    pub fn with_peers(mut self, peers: impl IntoIterator<Item = Peer>) -> Self {
        self.peers.extend(peers);
        self
    }

    /// Specify the port argument to the [`UdpTransportFactory`].
    ///
    /// You probably only want this when using [`with_default_udp`](Self::with_default_udp).
    pub const fn with_listen_port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }

    /// Specify the `SO_MARK` argument to the [`UdpTransportFactory`].
    ///
    /// You probably only want this when using [`with_default_udp`](Self::with_default_udp).
    #[cfg(target_os = "linux")]
    pub const fn with_fwmark(mut self, fwmark: u32) -> Self {
        self.fwmark = Some(fwmark);
        self
    }
}

impl<Udp: UdpTransportFactory, TunTx: IpSend, TunRx: IpRecv> DeviceBuilder<Udp, TunTx, TunRx> {
    /// Build the final [`Device`] from this builder.
    ///
    /// This will initialize the device state, add all configured peers, and optionally
    /// start the UAPI server if one was provided via [`with_uapi`](Self::with_uapi).
    ///
    /// # Errors
    ///
    /// Returns an error if the UDP socket cannot be bound or if peer initialization fails.
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
            key_pair: Default::default(),
            next_index: Default::default(),
            peers: Default::default(),
            peers_by_idx: Default::default(),
            peers_by_ip: AllowedIps::new(),
            rate_limiter: None,
            port: self.port,
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
