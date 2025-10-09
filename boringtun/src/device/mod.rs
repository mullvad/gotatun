// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

pub mod allowed_ips;

pub mod api;
pub mod daita;
#[cfg(unix)]
pub mod drop_privileges;
#[cfg(test)]
mod integration_tests;
pub mod peer;

use ip_network::IpNetwork;
use std::collections::HashMap;
use std::io::{self};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4};
use std::ops::BitOrAssign;
use std::sync::{Arc, Weak};
use std::time::Duration;
use tokio::join;
use tokio::sync::Mutex;
use tokio::sync::RwLock;

use crate::device::daita::DaitaSettings;
use crate::noise::errors::WireGuardError;
use crate::noise::handshake::parse_handshake_anon;
use crate::noise::rate_limiter::RateLimiter;
use crate::noise::{Tunn, TunnResult};
use crate::packet::{PacketBufPool, WgKind};
use crate::task::Task;
use crate::tun::buffer::{BufferedIpRecv, BufferedIpSend};
#[cfg(feature = "tun")]
use crate::tun::tun_async_device::TunDevice;
use crate::tun::{IpRecv, IpSend, LinkMtuWatcher};
use crate::udp::buffer::{BufferedUdpReceive, BufferedUdpSend};
use crate::udp::{
    UdpRecv, UdpSend, UdpTransportFactory, UdpTransportFactoryParams, socket::UdpSocketFactory,
};
use crate::x25519;
use allowed_ips::AllowedIps;
use peer::{AllowedIP, Peer};
use rand_core::{OsRng, RngCore};

const HANDSHAKE_RATE_LIMIT: u64 = 100; // The number of handshakes per second we can tolerate before using cookies

/// Maximum number of packet buffers that each channel may contain
const MAX_PACKET_BUFS: usize = 4000;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("i/o error: {0}")]
    IoError(#[from] io::Error),
    #[error("{0}")]
    Socket(io::Error),
    #[error("{1}: {0}")]
    Bind(#[source] io::Error, String),
    #[error("{0}")]
    FCntl(io::Error),
    #[error("{0}")]
    EventQueue(io::Error),
    #[error("{0}")]
    IOCtl(io::Error),
    #[error("{0}")]
    Connect(String),
    #[error("{0}")]
    SetSockOpt(String),
    #[error("Invalid tunnel name")]
    InvalidTunnelName,
    #[cfg(any(target_os = "macos", target_os = "ios", target_os = "tvos"))]
    #[error("{0}")]
    GetSockOpt(io::Error),
    #[error("{0}")]
    GetSockName(String),
    #[cfg(target_os = "linux")]
    #[error("{0}")]
    Timer(io::Error),
    #[error("iface read: {0}")]
    IfaceRead(io::Error),
    #[error("{0}")]
    DropPrivileges(String),
    #[error("API socket error: {0}")]
    ApiSocket(io::Error),
    #[error("Device error: {0}")]
    OpenDevice(#[from] tun::Error),
    #[error("Failed to initialize DAITA hooks")]
    DaitaHooks(#[from] maybenot::Error),
}

pub struct DeviceHandle<T: DeviceTransports> {
    device: Arc<RwLock<Device<T>>>,
}

#[derive(Default)]
pub struct DeviceConfig {
    pub api: Option<api::ApiServer>,
}

/// By default, use a UDP socket for sending datagrams and a tunnel device for IP packets.
#[cfg(feature = "tun")]
pub type DefaultDeviceTransports = (UdpSocketFactory, TunDevice);

pub trait DeviceTransports: 'static {
    type UdpTransportFactory: UdpTransportFactory;
    type IpSend: IpSend;
    type IpRecv: IpRecv;
}

impl<UF, IS, IR> DeviceTransports for (UF, IS, IR)
where
    UF: UdpTransportFactory,
    IS: IpSend,
    IR: IpRecv,
{
    type UdpTransportFactory = UF;
    type IpSend = IS;
    type IpRecv = IR;
}

impl<UF, IP> DeviceTransports for (UF, IP)
where
    UF: UdpTransportFactory,
    IP: IpSend + IpRecv + Clone,
{
    type UdpTransportFactory = UF;
    type IpSend = IP;
    type IpRecv = IP;
}

pub struct Device<T: DeviceTransports> {
    key_pair: Option<(x25519::StaticSecret, x25519::PublicKey)>,
    fwmark: Option<u32>,

    tun_tx: Arc<Mutex<T::IpSend>>,
    /// The tun device reader.
    ///
    /// This is `Arc<Mutex>`:ed because:
    /// - The task responsible from reading from the tun_rx must have ownership of it.
    /// - We must be able to claim the ownership after that task is stopped.
    ///
    /// This is implemented by the task taking the lock upon startup, and holding it until it is
    /// stopped.
    tun_rx: Arc<Mutex<T::IpRecv>>,

    /// Link-MTU wather of the TUN device.
    tun_rx_mtu: LinkMtuWatcher,

    peers: HashMap<x25519::PublicKey, Arc<Mutex<Peer>>>,
    peers_by_ip: AllowedIps<Arc<Mutex<Peer>>>,
    peers_by_idx: HashMap<u32, Arc<Mutex<Peer>>>,
    next_index: IndexLfsr,

    rate_limiter: Option<Arc<RateLimiter>>,

    port: u16,
    udp_factory: T::UdpTransportFactory,
    connection: Option<Connection<T>>,

    /// The task that responds to API requests.
    api: Option<Task>,
}

pub(crate) struct Connection<T: DeviceTransports> {
    udp4: <T::UdpTransportFactory as UdpTransportFactory>::Send,
    udp6: <T::UdpTransportFactory as UdpTransportFactory>::Send,

    listen_port: Option<u16>,

    /// The task that reads IPv4 traffic from the UDP socket.
    incoming_ipv4: Task,

    /// The task that reads IPv6 traffic from the UDP socket.
    incoming_ipv6: Task,

    /// The task that handles keepalives/heartbeats/etc.
    timers: Task,

    /// The task that reads traffic from the TUN device.
    outgoing: Task,
}

impl<T: DeviceTransports> Connection<T> {
    pub async fn set_up(device: Arc<RwLock<Device<T>>>) -> Result<Self, Error> {
        let pool = PacketBufPool::new(MAX_PACKET_BUFS);

        let mut device_guard = device.write().await;
        // clean up existing connection
        if let Some(conn) = device_guard.connection.take() {
            conn.stop().await;
        }

        let (udp4_tx, udp4_rx, udp6_tx, udp6_rx) = device_guard.open_listen_socket().await?;
        let buffered_ip_rx = BufferedIpRecv::new(
            MAX_PACKET_BUFS,
            pool.clone(),
            Arc::clone(&device_guard.tun_rx),
        );
        let buffered_ip_tx = BufferedIpSend::new(MAX_PACKET_BUFS, Arc::clone(&device_guard.tun_tx));

        let buffered_udp_tx_v4 = BufferedUdpSend::new(MAX_PACKET_BUFS, udp4_tx.clone());
        let buffered_udp_tx_v6 = BufferedUdpSend::new(MAX_PACKET_BUFS, udp6_tx.clone());

        let buffered_udp_rx_v4 = BufferedUdpReceive::new::<
            <T::UdpTransportFactory as UdpTransportFactory>::RecvV4,
        >(MAX_PACKET_BUFS, udp4_rx, pool.clone());
        let buffered_udp_rx_v6 = BufferedUdpReceive::new::<
            <T::UdpTransportFactory as UdpTransportFactory>::RecvV6,
        >(MAX_PACKET_BUFS, udp6_rx, pool.clone());

        // Start DAITA/hooks tasks
        for peer_arc in device_guard.peers.values() {
            Peer::maybe_start_daita(
                peer_arc,
                pool.clone(),
                device_guard.tun_rx_mtu.clone(),
                buffered_udp_tx_v4.clone(),
                buffered_udp_tx_v6.clone(),
            )
            .await?;
        }

        drop(device_guard);

        // Start device tasks
        let outgoing = Task::spawn(
            "handle_outgoing",
            Device::handle_outgoing(
                Arc::downgrade(&device),
                buffered_ip_rx,
                buffered_udp_tx_v4.clone(),
                buffered_udp_tx_v6.clone(),
                pool.clone(),
            ),
        );
        let timers = Task::spawn(
            "handle_timers",
            Device::handle_timers(
                Arc::downgrade(&device),
                buffered_udp_tx_v4.clone(),
                buffered_udp_tx_v6.clone(),
            ),
        );

        let incoming_ipv4 = Task::spawn(
            "handle_incoming ipv4",
            Device::handle_incoming(
                Arc::downgrade(&device),
                buffered_ip_tx.clone(),
                buffered_udp_tx_v4,
                buffered_udp_rx_v4,
                pool.clone(),
            ),
        );
        let incoming_ipv6 = Task::spawn(
            "handle_incoming ipv6",
            Device::handle_incoming(
                Arc::downgrade(&device),
                buffered_ip_tx,
                buffered_udp_tx_v6,
                buffered_udp_rx_v6,
                pool.clone(),
            ),
        );

        Ok(Connection {
            listen_port: udp4_tx.local_addr()?.map(|sa| sa.port()),
            udp4: udp4_tx,
            udp6: udp6_tx,
            incoming_ipv4,
            incoming_ipv6,
            timers,
            outgoing,
        })
    }
}

#[cfg(feature = "tun")]
impl<T: DeviceTransports<IpRecv = TunDevice, IpSend = TunDevice>> DeviceHandle<T> {
    pub async fn from_tun_name(
        udp_factory: T::UdpTransportFactory,
        tun_name: &str,
        config: DeviceConfig,
    ) -> Result<DeviceHandle<T>, Error> {
        let mut tun_config = tun::Configuration::default();
        tun_config.tun_name(tun_name);
        #[cfg(target_os = "macos")]
        tun_config.platform_config(|p| {
            p.enable_routing(false);
        });
        let tun = tun::create_as_async(&tun_config)?;
        let tun = TunDevice::from_tun_device(tun)?;
        let (tun_tx, tun_rx) = (tun.clone(), tun);
        Ok(DeviceHandle::new(udp_factory, tun_tx, tun_rx, config).await)
    }
}

impl<T: DeviceTransports> DeviceHandle<T> {
    pub async fn new(
        udp_factory: T::UdpTransportFactory,
        tun_tx: T::IpSend,
        tun_rx: T::IpRecv,
        config: DeviceConfig,
    ) -> DeviceHandle<T> {
        DeviceHandle {
            device: Device::new(udp_factory, tun_tx, tun_rx, config).await,
        }
    }

    pub async fn stop(self) {
        Self::stop_inner(self.device.clone()).await
    }

    async fn stop_inner(device: Arc<RwLock<Device<T>>>) {
        log::debug!("Stopping boringtun device");

        let mut device = device.write().await;

        if let Some(api_task) = device.api.take() {
            api_task.stop().await;
        };

        if let Some(connection) = device.connection.take() {
            connection.stop().await;
        }
    }
}

impl<T: DeviceTransports> Drop for DeviceHandle<T> {
    fn drop(&mut self) {
        log::debug!("Dropping boringtun device");
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            log::warn!("Failed to get tokio runtime handle");
            return;
        };
        log::info!(
            "DeviceHandle strong count: {}",
            Arc::strong_count(&self.device)
        );
        log::info!("DeviceHandle weak count: {}", Arc::weak_count(&self.device));
        let device = self.device.clone();
        handle.spawn(async move {
            Self::stop_inner(device).await;
        });
    }
}

/// Do we need to reconfigure the socket?
#[derive(Clone, Copy, PartialEq, Eq)]
enum Reconfigure {
    Yes,
    No,
}

impl BitOrAssign for Reconfigure {
    fn bitor_assign(&mut self, rhs: Self) {
        *self = match (*self, rhs) {
            (Reconfigure::No, Reconfigure::No) => Reconfigure::No,
            _ => Reconfigure::Yes,
        };
    }
}

impl<T: DeviceTransports> Device<T> {
    fn next_index(&mut self) -> u32 {
        self.next_index.next()
    }

    async fn remove_peer(&mut self, pub_key: &x25519::PublicKey) -> Option<Arc<Mutex<Peer>>> {
        if let Some(peer) = self.peers.remove(pub_key) {
            // Found a peer to remove, now purge all references to it:
            {
                let p = peer.lock().await;
                self.peers_by_idx.remove(&p.index());
            }
            self.peers_by_ip
                .remove(&|p: &Arc<Mutex<Peer>>| Arc::ptr_eq(&peer, p));

            log::info!("Peer removed");

            Some(peer)
        } else {
            None
        }
    }

    /// Update or add peer
    #[allow(clippy::too_many_arguments)]
    async fn update_peer(
        &mut self,
        pub_key: x25519::PublicKey,
        remove: bool,
        replace_allowed_ips: bool,
        endpoint: Option<SocketAddr>,
        new_allowed_ips: &[AllowedIP],
        keepalive: Option<u16>,
        preshared_key: Option<[u8; 32]>,
        daita_settings: Option<DaitaSettings>,
    ) {
        if remove {
            // Completely remove a peer
            self.remove_peer(&pub_key).await;
            return;
        }

        let (index, old_allowed_ips, old_daita_settings) =
            if let Some(old_peer) = self.remove_peer(&pub_key).await {
                // TODO: Update existing peer?
                let peer = old_peer.lock().await;
                let index = peer.index();
                let old_allowed_ips = peer
                    .allowed_ips()
                    .map(|(addr, cidr)| AllowedIP { addr, cidr })
                    .collect();
                let old_daita_settings = peer.daita_settings().cloned();

                drop(peer);

                // TODO: Match pubkey instead of index
                let mut remove_list = vec![];
                for (peer, addr, cidr) in self.peers_by_ip.iter() {
                    if peer.lock().await.index() == index {
                        remove_list.push(IpNetwork::new(addr, cidr).unwrap());
                    }
                }
                for network in remove_list {
                    self.peers_by_ip.remove_network(network);
                }

                (index, old_allowed_ips, old_daita_settings)
            } else {
                (self.next_index(), vec![], None)
            };

        // Update an existing peer or add peer
        let device_key_pair = self
            .key_pair
            .as_ref()
            .expect("Private key must be set first");

        let tunn = Tunn::new(
            device_key_pair.0.clone(),
            pub_key,
            preshared_key,
            keepalive,
            index,
            None,
        );

        let allowed_ips = if !replace_allowed_ips {
            // append old allowed IPs
            old_allowed_ips
                .into_iter()
                .chain(new_allowed_ips.iter().copied())
                .collect()
        } else {
            new_allowed_ips.to_vec()
        };

        let peer = Peer::new(
            tunn,
            index,
            endpoint,
            &allowed_ips,
            preshared_key,
            daita_settings.or_else(|| old_daita_settings),
        );
        let peer = Arc::new(Mutex::new(peer));

        self.peers_by_idx.insert(index, Arc::clone(&peer));
        self.peers.insert(pub_key, Arc::clone(&peer));

        for AllowedIP { addr, cidr } in &allowed_ips {
            self.peers_by_ip
                .insert(*addr, *cidr as _, Arc::clone(&peer));
        }

        log::info!("Peer added");
    }

    pub async fn new(
        udp_factory: T::UdpTransportFactory,
        tun_tx: T::IpSend,
        tun_rx: T::IpRecv,
        config: DeviceConfig,
    ) -> Arc<RwLock<Device<T>>> {
        let device = Device {
            api: None,
            udp_factory,
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
        let device = Arc::new(RwLock::new(device));
        if let Some(channel) = config.api {
            device.write().await.api = Some(Task::spawn(
                "handle_api",
                Device::handle_api(Arc::downgrade(&device), channel),
            ));
        }
        device
    }

    async fn set_port(&mut self, port: u16) -> Reconfigure {
        if self.port != port {
            self.port = port;
            Reconfigure::Yes
        } else {
            Reconfigure::No
        }
    }

    /// Bind two UDP sockets. One for IPv4, one for IPv6.
    async fn open_listen_socket(
        &mut self,
    ) -> Result<
        (
            <T::UdpTransportFactory as UdpTransportFactory>::Send,
            <T::UdpTransportFactory as UdpTransportFactory>::RecvV4,
            <T::UdpTransportFactory as UdpTransportFactory>::Send,
            <T::UdpTransportFactory as UdpTransportFactory>::RecvV6,
        ),
        Error,
    > {
        let params = UdpTransportFactoryParams {
            addr_v4: Ipv4Addr::UNSPECIFIED,
            addr_v6: Ipv6Addr::UNSPECIFIED,
            port: self.port,
            #[cfg(target_os = "linux")]
            fwmark: self.fwmark,
        };
        let ((udp4_tx, udp4_rx), (udp6_tx, udp6_rx)) = self.udp_factory.bind(&params).await?;
        Ok((udp4_tx, udp4_rx, udp6_tx, udp6_rx))
    }

    async fn set_key(&mut self, private_key: x25519::StaticSecret) -> Reconfigure {
        let public_key = x25519::PublicKey::from(&private_key);
        let key_pair = Some((private_key.clone(), public_key));

        // x25519 (rightly) doesn't let us expose secret keys for comparison.
        // If the public keys are the same, then the private keys are the same.
        if Some(&public_key) == self.key_pair.as_ref().map(|p| &p.1) {
            return Reconfigure::No;
        }

        let rate_limiter = Arc::new(RateLimiter::new(&public_key, HANDSHAKE_RATE_LIMIT));

        for peer in self.peers.values_mut() {
            peer.lock().await.tunnel.set_static_private(
                private_key.clone(),
                public_key,
                Some(Arc::clone(&rate_limiter)),
            )
        }

        self.key_pair = key_pair;
        self.rate_limiter = Some(rate_limiter);

        Reconfigure::Yes
    }

    #[cfg(any(target_os = "fuchsia", target_os = "linux"))]
    fn set_fwmark(&mut self, mark: u32) -> Result<(), Error> {
        self.fwmark = Some(mark);

        if let Some(conn) = &mut self.connection {
            // TODO: errors
            conn.udp4.set_fwmark(mark).unwrap();
            conn.udp6.set_fwmark(mark).unwrap();
        }

        // // Then on all currently connected sockets
        // for peer in self.peers.values() {
        //     if let Some(ref sock) = peer.blocking_lock().endpoint().conn {
        //         sock.set_mark(mark)?
        //     }
        // }

        Ok(())
    }

    fn clear_peers(&mut self) {
        self.peers.clear();
        self.peers_by_idx.clear();
        self.peers_by_ip.clear();
    }

    async fn handle_timers(device: Weak<RwLock<Self>>, udp4: impl UdpSend, udp6: impl UdpSend) {
        // TODO: fix rate limiting
        /*
        self.queue.new_periodic_event(
            // Reset the rate limiter every second give or take
            Box::new(|d, _| {
                if let Some(r) = d.rate_limiter.as_ref() {
                    r.reset_count()
                }
                Action::Continue
            }),
            std::time::Duration::from_secs(1),
        )?;
        */

        loop {
            tokio::time::sleep(Duration::from_millis(250)).await;

            let Some(device) = device.upgrade() else {
                break;
            };
            let device = device.read().await;
            // TODO: pass in peers instead?
            let peer_map = &device.peers;

            // Go over each peer and invoke the timer function
            for peer in peer_map.values() {
                let mut p = peer.lock().await;
                let endpoint_addr = match p.endpoint().addr {
                    Some(addr) => addr,
                    None => continue,
                };

                match p.update_timers() {
                    Ok(Some(packet)) => {
                        drop(p);
                        match endpoint_addr {
                            SocketAddr::V4(_) => {
                                udp4.send_to(packet.into_bytes(), endpoint_addr).await.ok()
                            }
                            SocketAddr::V6(_) => {
                                udp6.send_to(packet.into_bytes(), endpoint_addr).await.ok()
                            }
                        };
                    }
                    Ok(None) => {}
                    Err(WireGuardError::ConnectionExpired) => {}
                    Err(e) => log::error!("Timer error = {e:?}: {e:?}"),
                };
            }
        }
    }

    /// Read from UDP socket, decapsulate, write to tunnel device
    async fn handle_incoming(
        device: Weak<RwLock<Self>>,
        mut tun_tx: impl IpSend,
        udp_tx: impl UdpSend,
        mut udp_rx: impl UdpRecv,
        mut packet_pool: PacketBufPool,
    ) -> Result<(), Error> {
        let (private_key, public_key, rate_limiter) = {
            let Some(device) = device.upgrade() else {
                return Ok(());
            };
            let device = device.read().await;

            let (private_key, public_key) = device.key_pair.clone().expect("Key not set");
            let rate_limiter = device.rate_limiter.clone().unwrap();
            (private_key, public_key, rate_limiter)
        };

        while let Ok((src_buf, addr)) = udp_rx.recv_from(&mut packet_pool).await {
            let parsed_packet = match rate_limiter.verify_packet(Some(addr.ip()), src_buf) {
                Ok(packet) => packet,
                Err(TunnResult::WriteToNetwork(cookie)) => {
                    if let Err(_err) = udp_tx.send_to(cookie.into_bytes(), addr).await {
                        log::trace!("udp.send_to failed");
                        break;
                    }
                    continue;
                }
                Err(_) => continue,
            };

            let Some(device) = device.upgrade() else {
                return Ok(());
            };

            let device_guard = device.read().await;
            let peers = &device_guard.peers;
            let peers_by_idx = &device_guard.peers_by_idx;
            let peer = match &parsed_packet {
                WgKind::HandshakeInit(p) => {
                    let peer = parse_handshake_anon(&private_key, &public_key, p)
                        .ok()
                        .and_then(|hh| peers.get(&x25519::PublicKey::from(hh.peer_static_public)));

                    if let Some(peer) = peer {
                        // Remember peer endpoint
                        peer.lock().await.set_endpoint(addr);
                    }

                    peer
                }
                WgKind::HandshakeResp(p) => peers_by_idx.get(&(p.receiver_idx.get() >> 8)),
                WgKind::CookieReply(p) => peers_by_idx.get(&(p.receiver_idx.get() >> 8)),
                WgKind::Data(p) => peers_by_idx.get(&(p.header.receiver_idx.get() >> 8)),
            };
            let Some(peer) = peer else { continue };
            let mut peer = peer.lock().await;

            let Peer { tunnel, daita, .. } = &mut *peer;

            if let Some(daita) = daita {
                // TODO: what about keepalives?
                if let WgKind::Data(_) = &parsed_packet {
                    daita.before_data_decapsulate();
                };
            }

            match tunnel.handle_incoming_packet(parsed_packet) {
                TunnResult::Done => (),
                TunnResult::Err(_) => continue,
                TunnResult::WriteToNetwork(packet) => {
                    if let Err(_err) = udp_tx.send_to(packet.into_bytes(), addr).await {
                        log::trace!("udp.send_to failed");
                        break;
                    }

                    // Flush pending queue
                    while let Some(packet) = tunnel.next_queued_packet() {
                        if let Err(_err) = udp_tx.send_to(packet.into_bytes(), addr).await {
                            log::trace!("udp.send_to failed");
                            break;
                        }
                    }
                }
                TunnResult::WriteToTunnel(mut packet) => {
                    if let Some(daita) = daita {
                        match daita.after_data_decapsulate(packet) {
                            Some(new) => packet = new,
                            None => continue,
                        }
                    }

                    // keepalive
                    if packet.is_empty() {
                        continue;
                    }
                    let Ok(packet) = packet.try_into_ipvx() else {
                        continue;
                    };

                    // check whether `peer` is allowed to send us packets from `source`
                    let (source, packet): (IpAddr, _) = packet.either(
                        |ipv4| (ipv4.header.source().into(), ipv4.into()),
                        |ipv6| (ipv6.header.source().into(), ipv6.into()),
                    );
                    if !peer.is_allowed_ip(source) {
                        if cfg!(debug_assertions) {
                            let unspecified = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0).into();
                            log::warn!(
                                "peer at {} is not allowed to send us packets from: {source}",
                                peer.endpoint().addr.unwrap_or(unspecified)
                            );
                        }
                        continue;
                    }

                    if let Err(_err) = tun_tx.send(packet).await {
                        log::trace!("buffered_tun_send.send failed");
                        break;
                    }
                }
            };
        }

        Ok(())
    }

    /// Read from tunnel device, encapsulate, and write to UDP socket for the corresponding peer
    async fn handle_outgoing(
        device: Weak<RwLock<Self>>,
        mut tun_rx: impl IpRecv,
        udp4: impl UdpSend,
        udp6: impl UdpSend,
        mut packet_pool: PacketBufPool,
    ) {
        loop {
            let packets = match tun_rx.recv(&mut packet_pool).await {
                Ok(packets) => packets,
                Err(e) => {
                    log::error!("Unexpected error on tun interface: {e:?}");
                    break;
                }
            };

            for packet in packets {
                // Determine peer to use from the destination address
                let Some(dst_addr) = packet.destination() else {
                    continue;
                };

                let packet = packet.into_bytes();

                let Some(device) = device.upgrade() else {
                    return;
                };

                let peer = {
                    let device = device.read().await;
                    let Some(peer) = device.peers_by_ip.find(dst_addr).cloned() else {
                        // Drop packet if no peer has allowed IPs for destination
                        continue;
                    };
                    peer
                };

                let mut peer = peer.lock().await;
                let Some(peer_addr) = peer.endpoint().addr else {
                    log::error!("No endpoint");
                    continue;
                };

                let Peer { tunnel, daita, .. } = &mut *peer;

                let packet = match daita {
                    Some(daita) => daita.before_data_encapsulate(packet),
                    None => packet,
                };

                let Some(packet) = tunnel.handle_outgoing_packet(packet) else {
                    continue;
                };

                let packet = match daita {
                    None => packet,
                    Some(daita) => match daita.after_data_encapsulate(packet) {
                        Some(packet) => packet,
                        None => continue,
                    },
                };

                drop(peer); // release lock

                let result = match peer_addr {
                    SocketAddr::V4(..) => udp4.send_to(packet.into(), peer_addr).await,
                    SocketAddr::V6(..) => udp6.send_to(packet.into(), peer_addr).await,
                };

                if result.is_err() {
                    break;
                }
            }
        }
    }
}

/// A basic linear-feedback shift register implemented as xorshift, used to
/// distribute peer indexes across the 24-bit address space reserved for peer
/// identification.
/// The purpose is to obscure the total number of peers using the system and to
/// ensure it requires a non-trivial amount of processing power and/or samples
/// to guess other peers' indices. Anything more ambitious than this is wasted
/// with only 24 bits of space.
struct IndexLfsr {
    initial: u32,
    lfsr: u32,
    mask: u32,
}

impl IndexLfsr {
    /// Generate a random 24-bit nonzero integer
    fn random_index() -> u32 {
        const LFSR_MAX: u32 = 0xffffff; // 24-bit seed
        loop {
            let i = OsRng.next_u32() & LFSR_MAX;
            if i > 0 {
                // LFSR seed must be non-zero
                return i;
            }
        }
    }

    /// Generate the next value in the pseudorandom sequence
    fn next(&mut self) -> u32 {
        // 24-bit polynomial for randomness. This is arbitrarily chosen to
        // inject bitflips into the value.
        const LFSR_POLY: u32 = 0xd80000; // 24-bit polynomial
        let value = self.lfsr - 1; // lfsr will never have value of 0
        self.lfsr = (self.lfsr >> 1) ^ ((0u32.wrapping_sub(self.lfsr & 1u32)) & LFSR_POLY);
        assert!(self.lfsr != self.initial, "Too many peers created");
        value ^ self.mask
    }
}

impl Default for IndexLfsr {
    fn default() -> Self {
        let seed = Self::random_index();
        IndexLfsr {
            initial: seed,
            lfsr: seed,
            mask: Self::random_index(),
        }
    }
}

impl<T: DeviceTransports> Connection<T> {
    async fn stop(self) {
        let Self {
            udp4,
            udp6,
            listen_port: _,
            incoming_ipv4,
            incoming_ipv6,
            timers,
            outgoing,
        } = self;
        drop((udp4, udp6));

        join!(
            incoming_ipv4.stop(),
            incoming_ipv6.stop(),
            timers.stop(),
            outgoing.stop(),
        );
    }
}

impl<T: DeviceTransports> Drop for Device<T> {
    fn drop(&mut self) {
        log::info!("Stopping Device");
    }
}
