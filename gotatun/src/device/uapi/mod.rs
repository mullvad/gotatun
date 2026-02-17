// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
//
// Modified by Mullvad VPN.
// Copyright (c) 2025 Mullvad VPN.
//
// SPDX-License-Identifier: BSD-3-Clause

//! Userspace API.
//!
//! The most common use-case is probably to create a unix socket with
//! [`UapiServer::default_unix_socket`] and pass it to [`DeviceBuilder::with_uapi`]:
//!
//! ```no_run,ignore-windows
//! use gotatun::device::{self, uapi::UapiServer};
//!
//! let uapi = UapiServer::default_unix_socket("my-gotatun", None, None)
//!     .expect("Failed to create unix socket");
//!
//! let device = device::build()
//!     .with_uapi(uapi)
//! #   .with_default_udp()
//! #   .create_tun("tun").unwrap()
//!     /* .with_xyz(..) */
//!     .build();
//! ```
//!
//! [configuration protocol]: https://www.wireguard.com/xplatform/#configuration-protocol
//! [`DeviceBuilder::with_uapi`]: crate::device::builder::DeviceBuilder::with_uapi
#![doc = include_str!("../../../../UAPI.md")]

pub mod command;

use super::{Connection, DeviceState, Reconfigure};
use crate::device::DeviceTransports;
#[cfg(feature = "daita-uapi")]
use crate::device::uapi::command::SetUnset;
use crate::serialization::KeyBytes;
use command::{Get, GetPeer, GetResponse, Peer, Request, Response, Set, SetPeer, SetResponse};
use eyre::{Context, bail, eyre};
use libc::EINVAL;
#[cfg(unix)]
use nix::unistd::{Gid, Uid};
use std::fmt::Debug;
use std::io::{BufRead, BufReader, Read, Write};
use std::str::FromStr;
use std::sync::Weak;
#[cfg(feature = "daita-uapi")]
use std::sync::atomic;
use std::time::SystemTime;
use tokio::sync::{RwLock, mpsc, oneshot};

#[cfg(unix)]
const SOCK_DIR: &str = "/var/run/wireguard/";

/// A server that receives [`Request`]s. Should be passed to [`DeviceBuilder::with_uapi`].
///
/// [`DeviceBuilder::with_uapi`]: crate::device::builder::DeviceBuilder::with_uapi
pub struct UapiServer {
    rx: mpsc::Receiver<(Request, oneshot::Sender<Response>)>,
}

/// An API client to a gotatun [`Device`].
///
/// Use [`UapiClient::send`] or [`UapiClient::send_sync`] to configure the [`Device`] by adding peers, etc.
///
/// [`Device`]: crate::device::Device
#[derive(Clone)]
pub struct UapiClient {
    tx: mpsc::Sender<(Request, oneshot::Sender<Response>)>,
}

impl UapiClient {
    pub async fn send(&self, request: impl Into<Request>) -> eyre::Result<Response> {
        let request = request.into();
        log::trace!("Handling API request: {request:?}");
        let (response_tx, response_rx) = oneshot::channel();
        self.tx
            .send((request, response_tx))
            .await
            .map_err(|_| eyre!("Channel closed"))?;
        response_rx
            .await
            .inspect(|response| log::trace!("Sending API response: {response:?}"))
            .map_err(|_| eyre!("Channel closed"))
    }

    pub fn send_sync(&self, request: impl Into<Request>) -> eyre::Result<Response> {
        let request = request.into();
        log::trace!("Handling API request: {request:?}");
        let (response_tx, response_rx) = oneshot::channel();
        self.tx
            .blocking_send((request, response_tx))
            .map_err(|_| eyre!("Channel closed"))?;
        response_rx
            .blocking_recv()
            .inspect(|response| log::trace!("Sending API response: {response:?}"))
            .map_err(|_| eyre!("Channel closed"))
    }
}

impl UapiClient {
    /// Wrap a [Read] + [Write] and spawn a thread to convert between the textual configuration
    /// protocol and [Request]/[Response].
    ///
    /// <https://www.wireguard.com/xplatform/#configuration-protocol>
    pub fn wrap_read_write<RW>(self, rw: RW)
    where
        for<'a> &'a RW: Read + Write,
        RW: Send + Sync + 'static,
    {
        std::thread::spawn(move || {
            let r = BufReader::new(&rw);

            let make_request = |s: &str| {
                let request = Request::from_str(s).wrap_err("Failed to parse command")?;

                let Some(response) = self.send_sync(request).ok() else {
                    bail!("Server hung up");
                };

                if let Err(e) = writeln!(&rw, "{response}") {
                    log::error!("Failed to write API response: {e}");
                }

                Ok(())
            };

            let mut lines = String::new();

            for line in r.lines() {
                let Ok(line) = line else {
                    if !lines.is_empty()
                        && let Err(e) = make_request(&lines)
                    {
                        log::error!("Failed to handle UAPI request: {e:#}");
                        return;
                    }
                    return;
                };

                // Final line of a command is empty, so if this one is not, we add it to the
                // `lines` buffer and wait for more.
                if !line.is_empty() {
                    lines.push_str(&line);
                    lines.push('\n');
                    continue;
                }

                if lines.is_empty() {
                    continue;
                }

                if let Err(e) = make_request(&lines) {
                    log::error!("Failed to handle UAPI request: {e:#}");
                    return;
                }

                lines.clear();
            }
        });
    }
}

impl UapiServer {
    pub fn new() -> (UapiClient, UapiServer) {
        let (tx, rx) = mpsc::channel(100);

        (UapiClient { tx }, UapiServer { rx })
    }

    /// Spawn a unix socket at `/var/run/wireguard/<name>.sock`. This socket speaks the official
    /// [configuration protocol](https://www.wireguard.com/xplatform/#configuration-protocol).
    ///
    /// Optionally, set the owner of the socket using `uid` and `gid`.
    #[cfg(unix)]
    pub fn default_unix_socket(
        name: &str,
        uid: Option<Uid>,
        gid: Option<Gid>,
    ) -> eyre::Result<Self> {
        use std::os::unix::net::UnixListener;

        let path = format!("{SOCK_DIR}/{name}.sock");

        create_sock_dir()?;

        let _ = std::fs::remove_file(&path); // Attempt to remove the socket if already exists

        // Bind a new socket to the path
        let api_listener =
            UnixListener::bind(&path).map_err(|e| eyre!("Failed to bind unix socket: {e}"))?;

        if uid.is_some() || gid.is_some() {
            if let Err(err) = nix::unistd::chown(std::path::Path::new(&path), uid, gid) {
                log::warn!("Failed to change owner of UDS: {err}");
            }
        }

        let (tx, rx) = UapiServer::new();

        std::thread::spawn(move || {
            loop {
                let Ok((stream, _)) = api_listener.accept() else {
                    break;
                };

                log::info!("New UAPI connection on unix socket");

                tx.clone().wrap_read_write(stream);
            }
        });

        Ok(rx)

        //self.cleanup_paths.push(path.clone());
    }

    /// Create an [`UapiServer`] from a reader+writer that speaks the official
    /// [configuration protocol](https://www.wireguard.com/xplatform/#configuration-protocol).
    pub fn from_read_write<RW>(rw: RW) -> Self
    where
        RW: Send + Sync + 'static,
        for<'a> &'a RW: Read + Write,
    {
        let (tx, rx) = Self::new();
        tx.wrap_read_write(rw);
        rx
    }

    /// Wait for a [`Request`]. The response should be sent on the provided [`oneshot`].
    pub(crate) async fn recv(&mut self) -> Option<(Request, oneshot::Sender<Response>)> {
        let (request, response_tx) = self.rx.recv().await?;

        Some((request, response_tx))
    }
}

impl Debug for UapiServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("UapiServer").finish()
    }
}

#[cfg(unix)]
fn create_sock_dir() -> eyre::Result<()> {
    match std::fs::create_dir(SOCK_DIR) {
        Ok(_) => {
            log::info!("Created socket directory at {SOCK_DIR}");
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            // Directory already exists, which is fine
        }
        Err(e) => {
            bail!("Failed to create socket directory {SOCK_DIR}: {e}");
        }
    }
    Ok(())
}

impl<T: DeviceTransports> DeviceState<T> {
    pub(super) async fn handle_api(device: Weak<RwLock<Self>>, mut api: UapiServer) {
        loop {
            let Some((request, respond)) = api.recv().await else {
                // The remote side is closed
                return;
            };

            let Some(device) = device.upgrade() else {
                return;
            };
            let response = match request {
                Request::Get(get) => {
                    let device_guard = device.read().await;
                    Response::Get(on_api_get(get, &device_guard).await)
                }
                Request::Set(set) => {
                    let mut device_guard = device.write().await;
                    let (response, reconfigure) = on_api_set(set, &mut device_guard).await;
                    drop(device_guard);

                    if reconfigure == Reconfigure::Yes {
                        match Connection::set_up(device.clone()).await {
                            Ok(con) => {
                                let mut device_guard = device.write().await;
                                device_guard.connection = Some(con);
                                Response::Set(response)
                            }
                            Err(err) => {
                                // TODO: error message
                                log::error!("Failed to set up stuff: {err}");
                                // TODO: response code
                                Response::Set(SetResponse { errno: EINVAL })
                            }
                        }
                    } else {
                        Response::Set(response)
                    }
                } //_ => EIO,
            };

            let _ = respond.send(response);

            // The protocol requires to return an error code as the response, or zero on success
            //channel.tx.send(format!("errno={}\n", status)).ok();
        }
    }

    // fn register_monitor(&self, _path: String) -> Result<(), Error> {
    //     // TODO: fix this
    //
    //     self.queue.new_periodic_event(
    //         Box::new(move |d, _| {
    //             // This is not a very nice hack to detect if the control socket was removed
    //             // and exiting nicely as a result. We check every 3 seconds in a loop if the
    //             // file was deleted by stating it.
    //             // The problem is that on linux inotify can be used quite beautifully to detect
    //             // deletion, and kqueue EVFILT_VNODE can be used for the same purpose, but that
    //             // will require introducing new events, for no measurable benefit.
    //             // TODO: Could this be an issue if we restart the service too quickly?
    //             let path = std::path::Path::new(&path);
    //             if !path.exists() {
    //                 d.trigger_exit();
    //                 return Action::Exit;
    //             }
    //
    //             Action::Continue
    //         }),
    //         std::time::Duration::from_millis(1000),
    //     )?;
    //
    //     Ok(())
    // }
}

/// Handle a [Get] request.
async fn on_api_get(_: Get, d: &DeviceState<impl DeviceTransports>) -> GetResponse {
    let mut peers = vec![];
    for (public_key, peer) in &d.peers {
        let peer = peer.lock().await;
        let (_, tx_bytes, rx_bytes, ..) = peer.tunnel.stats();
        let endpoint = peer.endpoint().addr;
        #[cfg(feature = "daita-uapi")]
        let daita_overhead = peer.daita.as_ref().map(|daita| daita.daita_overhead());

        let last_handshake_time = peer.time_since_last_handshake().and_then(|d| {
            SystemTime::now()
                .checked_sub(d)?
                .duration_since(SystemTime::UNIX_EPOCH)
                .ok()
        });

        peers.push(GetPeer {
            peer: Peer {
                public_key: KeyBytes(*public_key.as_bytes()),
                preshared_key: peer
                    .preshared_key
                    .map(|key| command::SetUnset::Set(KeyBytes(key))),
                endpoint,
                persistent_keepalive_interval: peer.persistent_keepalive(),
                allowed_ip: peer.allowed_ips().collect(),
                #[cfg(feature = "daita-uapi")]
                daita_settings: peer.daita_settings().cloned().map(SetUnset::Set),
            },
            last_handshake_time_sec: last_handshake_time.map(|t| t.as_secs()),
            last_handshake_time_nsec: last_handshake_time.map(|t| t.subsec_nanos()),
            rx_bytes: Some(rx_bytes as u64),
            tx_bytes: Some(tx_bytes as u64),
            #[cfg(feature = "daita-uapi")]
            tx_padding_bytes: daita_overhead.map(|p| p.tx_padding_bytes as u64),
            #[cfg(not(feature = "daita-uapi"))]
            tx_padding_bytes: None,
            #[cfg(feature = "daita-uapi")]
            tx_decoy_packet_bytes: daita_overhead
                .map(|p| p.tx_decoy_packet_bytes.load(atomic::Ordering::SeqCst) as u64),
            #[cfg(not(feature = "daita-uapi"))]
            tx_decoy_packet_bytes: None,
            #[cfg(feature = "daita-uapi")]
            rx_padding_bytes: daita_overhead.map(|p| p.rx_padding_bytes as u64),
            #[cfg(not(feature = "daita-uapi"))]
            rx_padding_bytes: None,
            #[cfg(feature = "daita-uapi")]
            rx_decoy_packet_bytes: daita_overhead.map(|p| p.rx_decoy_packet_bytes as u64),
            #[cfg(not(feature = "daita-uapi"))]
            rx_decoy_packet_bytes: None,
        });
    }

    GetResponse {
        private_key: d.key_pair.as_ref().map(|k| KeyBytes(k.0.to_bytes())),
        listen_port: Some(
            d.connection
                .as_ref()
                .and_then(|con| con.listen_port)
                .unwrap_or(0),
        ),
        fwmark: d.fwmark,
        peers,
        errno: 0,
    }
}

/// Handle a [Set] request.
async fn on_api_set(
    set: Set,
    device: &mut DeviceState<impl DeviceTransports>,
) -> (SetResponse, Reconfigure) {
    let Set {
        private_key,
        listen_port,
        fwmark,
        replace_peers,
        protocol_version,
        peers,
    } = set;

    if let Some(protocol_version) = protocol_version
        && protocol_version != "1"
    {
        log::warn!("Invalid API protocol version: {protocol_version}");
        return (SetResponse { errno: EINVAL }, Reconfigure::No);
    }

    let mut reconfigure: Reconfigure = Reconfigure::No;

    if replace_peers {
        device.clear_peers();
    }

    if let Some(private_key) = private_key {
        reconfigure |= device
            .set_key(x25519_dalek::StaticSecret::from(private_key.0))
            .await;
    }

    if let Some(listen_port) = listen_port {
        reconfigure |= device.set_port(listen_port);
    }

    if let Some(new_fwmark) = fwmark {
        #[cfg(target_os = "linux")]
        {
            let new_fwmark = match new_fwmark {
                command::SetUnset::Set(value) => Some(u32::from(value)),
                command::SetUnset::Unset => None,
            };
            if new_fwmark != device.fwmark {
                device.fwmark = new_fwmark;
                reconfigure = Reconfigure::Yes;
            }
        }

        // fwmark only applies on Linux
        // TODO: return error?
        #[cfg(not(target_os = "linux"))]
        let _ = new_fwmark;
    }

    for peer in peers {
        let SetPeer {
            peer:
                Peer {
                    public_key,
                    preshared_key,
                    endpoint,
                    persistent_keepalive_interval,
                    allowed_ip,
                    #[cfg(feature = "daita-uapi")]
                    daita_settings,
                },
            remove,
            update_only,
            replace_allowed_ips,
        } = peer;

        let public_key = x25519_dalek::PublicKey::from(public_key.0);

        if remove {
            // Completely remove a peer
            device.remove_peer(&public_key).await;
            continue;
        }

        if update_only && !device.peers.contains_key(&public_key) {
            continue;
        }

        let mut new_peer = match device.remove_peer(&public_key).await {
            None => {
                // New peer
                crate::device::Peer::new(public_key)
            }
            Some(old_peer) => {
                // Take existing peer
                let peer = old_peer.lock().await;

                crate::device::Peer {
                    public_key,
                    preshared_key: peer.preshared_key,
                    endpoint: peer.endpoint().addr,
                    keepalive: peer.persistent_keepalive(),
                    allowed_ips: if replace_allowed_ips {
                        vec![]
                    } else {
                        // Keep old allowed IPs if requested
                        peer.allowed_ips().collect()
                    },
                    #[cfg(feature = "daita")]
                    daita_settings: peer.daita_settings().cloned(),
                }
            }
        };

        if let Some(endpoint) = endpoint {
            new_peer.endpoint = Some(endpoint);
        }

        if let Some(keepalive) = persistent_keepalive_interval {
            new_peer.keepalive = Some(keepalive);
        }

        match preshared_key {
            Some(command::SetUnset::Set(psk)) => {
                new_peer.preshared_key = Some(psk.0);
            }
            Some(command::SetUnset::Unset) => {
                new_peer.preshared_key = None;
            }
            None => (),
        }

        #[cfg(feature = "daita-uapi")]
        match daita_settings {
            Some(SetUnset::Set(settings)) => {
                new_peer.daita_settings = Some(settings);
                reconfigure |= Reconfigure::Yes;
            }
            Some(SetUnset::Unset) => {
                new_peer.daita_settings = None;
                reconfigure |= Reconfigure::Yes;
            }
            None => (),
        }

        new_peer.allowed_ips.extend(allowed_ip);

        device.add_peer(new_peer);
    }

    // If there is no key pair, we cannot reconfigure the connection
    if device.key_pair.is_none() {
        reconfigure = Reconfigure::No;
    }

    (SetResponse { errno: 0 }, reconfigure)
}
