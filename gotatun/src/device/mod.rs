// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
//
// Modified by Mullvad VPN.
// Copyright (c) 2025 Mullvad VPN.
//
// SPDX-License-Identifier: BSD-3-Clause

//! WireGuard device implementation with support for peers, handshakes, and packet routing.
pub(crate) mod allowed_ips;
mod builder;
pub mod configure;
#[cfg(feature = "daita")]
pub mod daita;
#[cfg(test)]
mod integration_tests;
mod peer;
mod peer_state;
#[cfg(test)]
mod tests;
mod transports;
pub mod uapi;

use crate::noise::index_table::IndexTable;
use builder::Nul;
use std::collections::HashMap;
use std::io::{self};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4};
use std::ops::BitOrAssign;
use std::sync::{Arc, Weak};
use std::time::Duration;
use tokio::join;
use tokio::sync::Mutex;
use tokio::sync::RwLock;

use crate::noise::errors::WireGuardError;
use crate::noise::handshake::parse_handshake_anon;
use crate::noise::rate_limiter::RateLimiter;
use crate::noise::{Tunn, TunnResult};
use crate::packet::{PacketBufPool, WgKind};
use crate::task::Task;
use crate::tun::buffer::{BufferedIpRecv, BufferedIpSend};
use crate::tun::{IpRecv, IpSend, MtuWatcher};
use crate::udp::buffer::{BufferedUdpReceive, BufferedUdpSend};
use crate::udp::{UdpRecv, UdpSend, UdpTransportFactory, UdpTransportFactoryParams};
use crate::x25519;
use allowed_ips::AllowedIps;
use peer_state::PeerState;

#[cfg(feature = "tun")]
pub use crate::device::transports::DefaultDeviceTransports;
pub use crate::device::transports::DeviceTransports;
pub use builder::DeviceBuilder;
pub use peer::Peer;

/// The number of handshakes per second to tolerate before using cookies
const HANDSHAKE_RATE_LIMIT: u64 = 100;

/// Maximum number of packet buffers that each channel may contain
const MAX_PACKET_BUFS: usize = 4000;

/// Error of [`Device`]-related operations.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// I/O error
    #[error("i/o error: {0}")]
    IoError(#[from] io::Error),

    /// Failed to bind UDP sockets
    #[error("Failed to bind UDP sockets (params={1:?}): {0}")]
    Bind(#[source] io::Error, UdpTransportFactoryParams),

    /// TUN device error
    #[error("TUN device error: {0}")]
    #[cfg(feature = "tun")]
    TunDevice(#[from] crate::tun::tun_async_device::Error),

    /// Failed to initialize DAITA hooks
    #[error("Failed to initialize DAITA hooks")]
    #[cfg(feature = "daita")]
    DaitaHooks(#[from] daita::Error),
}

/// A reference-counted handle to a WireGuard device.
#[derive(Clone)]
pub struct Device<T: DeviceTransports> {
    inner: Arc<RwLock<DeviceState<T>>>,
}

/// Entry point for building a [`Device`].
///
/// See [`DeviceBuilder`] for options.
pub const fn build() -> DeviceBuilder<Nul, Nul, Nul> {
    DeviceBuilder::new()
}

pub(crate) struct DeviceState<T: DeviceTransports> {
    key_pair: Option<(x25519::StaticSecret, x25519::PublicKey)>,
    fwmark: Option<u32>,

    tun_tx: Arc<Mutex<T::IpSend>>,
    /// The tun device reader.
    ///
    /// This is `Arc<Mutex>`:ed because:
    /// - The task responsible from reading from the `tun_rx` must have ownership of it.
    /// - We must be able to claim the ownership after that task is stopped.
    ///
    /// This is implemented by the task taking the lock upon startup, and holding it until it is
    /// stopped.
    tun_rx: Arc<Mutex<T::IpRecv>>,

    /// MTU watcher of the TUN device.
    tun_rx_mtu: MtuWatcher,

    peers: HashMap<x25519::PublicKey, Arc<Mutex<PeerState>>>,
    peers_by_ip: AllowedIps<Arc<Mutex<PeerState>>>,
    peers_by_idx: parking_lot::Mutex<HashMap<u32, Arc<Mutex<PeerState>>>>,
    index_table: IndexTable,

    rate_limiter: Option<Arc<RateLimiter>>,

    port: u16,
    udp_factory: T::UdpTransportFactory,
    connection: Option<Connection<T>>,

    /// The task that responds to API requests.
    api: Option<Task>,
}

pub(crate) struct Connection<T: DeviceTransports> {
    udp4: <T::UdpTransportFactory as UdpTransportFactory>::SendV4,
    udp6: <T::UdpTransportFactory as UdpTransportFactory>::SendV6,

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
    pub async fn set_up(device: Arc<RwLock<DeviceState<T>>>) -> Result<Self, Error> {
        let mut device_guard = device.write().await;
        let pool = PacketBufPool::new(MAX_PACKET_BUFS);

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
        #[cfg(feature = "daita")]
        for peer_arc in device_guard.peers.values() {
            PeerState::maybe_start_daita(
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
            DeviceState::handle_outgoing(
                Arc::downgrade(&device),
                buffered_ip_rx,
                buffered_udp_tx_v4.clone(),
                buffered_udp_tx_v6.clone(),
                pool.clone(),
            ),
        );
        let timers = Task::spawn(
            "handle_timers",
            DeviceState::handle_timers(
                Arc::downgrade(&device),
                buffered_udp_tx_v4.clone(),
                buffered_udp_tx_v6.clone(),
            ),
        );

        let incoming_ipv4 = Task::spawn(
            "handle_incoming ipv4",
            DeviceState::handle_incoming(
                Arc::downgrade(&device),
                buffered_ip_tx.clone(),
                buffered_udp_tx_v4,
                buffered_udp_rx_v4,
                pool.clone(),
            ),
        );
        let incoming_ipv6 = Task::spawn(
            "handle_incoming ipv6",
            DeviceState::handle_incoming(
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

impl<T: DeviceTransports> Device<T> {
    /// Stop tunneling traffic and shut down the [`Device`].
    pub async fn stop(self) {
        Self::stop_inner(self.inner.clone()).await
    }

    async fn stop_inner(device: Arc<RwLock<DeviceState<T>>>) {
        log::debug!("Stopping gotatun device");

        let mut device = device.write().await;

        if let Some(api_task) = device.api.take() {
            api_task.stop().await;
        }

        if let Some(connection) = device.connection.take() {
            connection.stop().await;
        }
    }
}

impl<T: DeviceTransports> Drop for Device<T> {
    fn drop(&mut self) {
        log::debug!("Dropping gotatun device");
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            log::warn!("Failed to get tokio runtime handle");
            return;
        };
        log::debug!(
            "DeviceHandle strong count: {}",
            Arc::strong_count(&self.inner)
        );
        log::debug!("DeviceHandle weak count: {}", Arc::weak_count(&self.inner));
        let device = self.inner.clone();
        handle.spawn(async move {
            Self::stop_inner(device).await;
        });
    }
}

/// Do we need to reconfigure the socket?
#[must_use]
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

impl<T: DeviceTransports> DeviceState<T> {
    async fn remove_peer(&mut self, pub_key: &x25519::PublicKey) -> Option<Arc<Mutex<PeerState>>> {
        if let Some(peer) = self.peers.remove(pub_key) {
            // Remove all session index entries that point to this peer
            self.peers_by_idx
                .lock()
                .retain(|_idx, p| !Arc::ptr_eq(&peer, p));
            self.peers_by_ip
                .remove(&|p: &Arc<Mutex<PeerState>>| Arc::ptr_eq(&peer, p));

            log::info!("Peer removed");

            Some(peer)
        } else {
            None
        }
    }

    fn add_peer(&mut self, peer_builder: Peer) {
        let pub_key = peer_builder.public_key;
        let allowed_ips = peer_builder.allowed_ips.clone();
        let peer = self.create_peer(peer_builder);
        let peer = Arc::new(Mutex::new(peer));

        self.peers.insert(pub_key, Arc::clone(&peer));

        for allowed_ip in allowed_ips {
            let addr = allowed_ip.network();
            let cidr = allowed_ip.prefix();
            self.peers_by_ip.insert(addr, cidr, Arc::clone(&peer));
        }

        log::info!("Peer added");
    }

    fn create_peer(&mut self, peer_builder: Peer) -> PeerState {
        let device_key_pair = self
            .key_pair
            .as_ref()
            .expect("Private key must be set first");
        let rate_limiter = self
            .rate_limiter
            .as_ref()
            .expect("Setting private key creates rate limiter")
            .clone();

        let tunn = Tunn::new(
            device_key_pair.0.clone(),
            peer_builder.public_key,
            peer_builder.preshared_key,
            peer_builder.keepalive,
            self.index_table.clone(),
            rate_limiter,
        );

        PeerState::new(
            tunn,
            peer_builder.endpoint,
            peer_builder.allowed_ips.as_slice(),
            peer_builder.preshared_key,
            #[cfg(feature = "daita")]
            peer_builder.daita_settings,
        )
    }

    fn set_port(&mut self, port: u16) -> Reconfigure {
        if self.port == port {
            Reconfigure::No
        } else {
            self.port = port;
            Reconfigure::Yes
        }
    }

    /// Bind two UDP sockets. One for IPv4, one for IPv6.
    async fn open_listen_socket(
        &mut self,
    ) -> Result<
        (
            <T::UdpTransportFactory as UdpTransportFactory>::SendV4,
            <T::UdpTransportFactory as UdpTransportFactory>::RecvV4,
            <T::UdpTransportFactory as UdpTransportFactory>::SendV6,
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
        let ((udp4_tx, udp4_rx), (udp6_tx, udp6_rx)) = self
            .udp_factory
            .bind(&params)
            .await
            .map_err(|e| Error::Bind(e, params))?;
        Ok((udp4_tx, udp4_rx, udp6_tx, udp6_rx))
    }

    async fn set_key(&mut self, private_key: x25519::StaticSecret) -> Reconfigure {
        let public_key = x25519::PublicKey::from(&private_key);
        // x25519 (rightly) doesn't let us expose secret keys for comparison.
        // If the public keys are the same, then the private keys are the same.
        if let Some(key_pair) = self.key_pair.as_ref()
            && key_pair.1 == public_key
        {
            return Reconfigure::No;
        }

        let rate_limiter = Arc::new(RateLimiter::new(&public_key, HANDSHAKE_RATE_LIMIT));

        for peer in self.peers.values_mut() {
            peer.lock().await.tunnel.set_static_private(
                private_key.clone(),
                public_key,
                Arc::clone(&rate_limiter),
            )
        }

        self.key_pair = Some((private_key, public_key));
        self.rate_limiter = Some(rate_limiter);

        Reconfigure::Yes
    }

    #[cfg(target_os = "linux")]
    fn set_fwmark(&mut self, mark: u32) -> Result<(), Error> {
        self.fwmark = Some(mark);

        if let Some(conn) = &mut self.connection {
            conn.udp4.set_fwmark(mark)?;
            conn.udp6.set_fwmark(mark)?;
        }

        // // Then on all currently connected sockets
        // for peer in self.peers.values() {
        //     if let Some(ref sock) = peer.delay_lock().endpoint().conn {
        //         sock.set_mark(mark)?
        //     }
        // }

        Ok(())
    }

    /// Remove all peers.
    ///
    /// # Returns
    /// Returns the number of peers removed.
    fn clear_peers(&mut self) -> usize {
        let n = self.peers.len();
        self.peers.clear();
        self.peers_by_idx.lock().clear();
        self.peers_by_ip.clear();
        // TODO: tear down connection?
        n
    }

    /// If `packet` is a handshake init or response, register its `sender_idx` in `peers_by_idx`.
    fn register_handshake_idx(
        peers_by_idx: &parking_lot::Mutex<HashMap<u32, Arc<Mutex<PeerState>>>>,
        packet: &WgKind,
        peer: &Arc<Mutex<PeerState>>,
    ) {
        let sender_idx = match packet {
            WgKind::HandshakeInit(p) => p.sender_idx.get(),
            WgKind::HandshakeResp(p) => p.sender_idx.get(),
            _ => return,
        };
        peers_by_idx.lock().insert(sender_idx, Arc::clone(peer));
    }

    async fn handle_timers(device: Weak<RwLock<Self>>, udp4: impl UdpSend, udp6: impl UdpSend) {
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

                // Remove stale session indices.
                device.peers_by_idx.lock().retain(|idx, map_peer| {
                    !Arc::ptr_eq(peer, map_peer)
                        || p.tunnel.active_receiving_indices().any(|i| i == *idx)
                });

                match p.update_timers() {
                    Ok(Some(packet)) => {
                        // Register sender_idx from outgoing handshake packets
                        Self::register_handshake_idx(&device.peers_by_idx, &packet, peer);

                        drop(p);

                        // NOTE: we don't bother with triggering TunnelRecv DAITA events here.

                        match endpoint_addr {
                            SocketAddr::V4(_) => {
                                udp4.send_to(packet.into(), endpoint_addr).await.ok()
                            }
                            SocketAddr::V6(_) => {
                                udp6.send_to(packet.into(), endpoint_addr).await.ok()
                            }
                        };
                    }
                    Ok(None) => {}
                    Err(WireGuardError::ConnectionExpired) => {}
                    Err(e) => log::error!("Timer error = {e:?}: {e:?}"),
                }
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
        let (private_key, public_key, rate_limiter, mut tun_mtu) = {
            let Some(device) = device.upgrade() else {
                return Ok(());
            };
            let device = device.read().await;

            let (private_key, public_key) = device.key_pair.clone().expect("Key not set");
            let rate_limiter = device.rate_limiter.clone().unwrap();
            let tun_mtu = device.tun_rx_mtu.clone();
            (private_key, public_key, rate_limiter, tun_mtu)
        };

        while let Ok((src_buf, addr)) = udp_rx.recv_from(&mut packet_pool).await {
            let parsed_packet = match rate_limiter.verify_packet(addr.ip(), src_buf) {
                Ok(packet) => packet,
                Err(TunnResult::WriteToNetwork(WgKind::CookieReply(cookie))) => {
                    if let Err(_err) = udp_tx.send_to(cookie.into(), addr).await {
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
            let peer = match &parsed_packet {
                WgKind::HandshakeInit(p) => parse_handshake_anon(&private_key, &public_key, p)
                    .ok()
                    .and_then(|hh| peers.get(&x25519::PublicKey::from(hh.peer_static_public)))
                    .cloned(),
                WgKind::HandshakeResp(p) => device_guard
                    .peers_by_idx
                    .lock()
                    .get(&p.receiver_idx.get())
                    .cloned(),
                WgKind::CookieReply(p) => device_guard
                    .peers_by_idx
                    .lock()
                    .get(&p.receiver_idx.get())
                    .cloned(),
                WgKind::Data(p) => device_guard
                    .peers_by_idx
                    .lock()
                    .get(&p.header.receiver_idx.get())
                    .cloned(),
            };
            let Some(peer_arc) = peer else { continue };
            let mut peer = peer_arc.lock().await;

            #[cfg(feature = "daita")]
            let PeerState { tunnel, daita, .. } = &mut *peer;
            #[cfg(not(feature = "daita"))]
            let PeerState { tunnel, .. } = &mut *peer;

            match tunnel.handle_incoming_packet(parsed_packet) {
                TunnResult::Done => {
                    // Update the peer endpoint if we received any authenticated packet
                    peer.set_endpoint(addr);
                }
                TunnResult::Err(_) => continue,
                // Flush pending queue
                TunnResult::WriteToNetwork(packet) => {
                    // Register sender_idx from outgoing handshake packets
                    Self::register_handshake_idx(&device_guard.peers_by_idx, &packet, &peer_arc);

                    // TODO: does this end up with the packets being out-of-order?
                    let packets =
                        std::iter::once(packet).chain(tunnel.get_queued_packets(&mut tun_mtu));

                    #[cfg(feature = "daita")]
                    let packets = packets.filter_map(|p| match daita {
                        Some(daita) => daita.after_data_encapsulate(p),
                        None => Some(p),
                    });

                    for packet in packets {
                        if let Err(_err) = udp_tx.send_to(packet.into(), addr).await {
                            log::trace!("udp.send_to failed");
                            break;
                        }
                    }

                    // Update the peer endpoint if we received any authenticated packet
                    peer.set_endpoint(addr);
                }
                #[cfg_attr(not(feature = "daita"), expect(unused_mut))]
                TunnResult::WriteToTunnel(mut packet) => {
                    #[cfg(feature = "daita")]
                    if let Some(daita) = daita {
                        // NOTE: This hook should ideally be called before the packet is decapsulated,
                        // but after the encrypted payload is authenticated by its tag/MAC. The available
                        // API does not allow us to separate these steps, so the hook must be called after
                        // decryption to prevent injection of `TunnelRecv` events on garbage data.
                        daita.before_data_decapsulate(&packet);
                        match daita.after_data_decapsulate(packet) {
                            Some(new) => packet = new,
                            None => continue,
                        }
                    }

                    // Update the peer endpoint if we received any authenticated packet
                    peer.set_endpoint(addr);

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
            }
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
        let mut tun_mtu = {
            let Some(device) = device.upgrade() else {
                return;
            };
            let device = device.read().await;
            device.tun_rx_mtu.clone()
        };

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

                let Some(device_arc) = device.upgrade() else {
                    return;
                };

                let device_guard = device_arc.read().await;

                let Some(peer_arc) = device_guard.peers_by_ip.find(dst_addr).cloned() else {
                    if cfg!(debug_assertions) {
                        log::trace!("Dropping packet with no routable peer");
                    }

                    // Drop packet if no peer has allowed IPs for destination
                    drop(packet);
                    continue;
                };

                let mut peer = peer_arc.lock().await;
                let Some(peer_addr) = peer.endpoint().addr else {
                    // TODO: Implement the following error handling from section 3 of the
                    // whitepaper: If [peer_addr] matches no peer, it is dropped, and the sender is
                    // informed by a standard ICMP “no route to host” packet, as well as returning
                    // -ENOKEY to user space.
                    log::error!("No endpoint");
                    continue;
                };

                #[cfg(feature = "daita")]
                let PeerState { tunnel, daita, .. } = &mut *peer;
                #[cfg(not(feature = "daita"))]
                let PeerState { tunnel, .. } = &mut *peer;

                #[cfg(feature = "daita")]
                let packet = match daita {
                    Some(daita) => daita.before_data_encapsulate(packet),
                    None => packet.into(),
                };
                #[cfg(not(feature = "daita"))]
                let packet = packet.into();

                let Some(packet) = tunnel.handle_outgoing_packet(packet, Some(&mut tun_mtu)) else {
                    continue;
                };

                // Register sender_idx from outgoing handshake packets
                Self::register_handshake_idx(&device_guard.peers_by_idx, &packet, &peer_arc);

                #[cfg(feature = "daita")]
                let packet = match daita {
                    None => packet.into(),
                    Some(daita) => match daita.after_data_encapsulate(packet) {
                        Some(packet) => packet.into(),
                        None => continue,
                    },
                };
                #[cfg(not(feature = "daita"))]
                let packet = packet.into();

                drop(peer); // release lock
                drop(device_guard);

                let result = match peer_addr {
                    SocketAddr::V4(..) => udp4.send_to(packet, peer_addr).await,
                    SocketAddr::V6(..) => udp6.send_to(packet, peer_addr).await,
                };

                if result.is_err() {
                    break;
                }
            }
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

impl<T: DeviceTransports> Drop for DeviceState<T> {
    fn drop(&mut self) {
        log::info!("Stopping Device");
    }
}
