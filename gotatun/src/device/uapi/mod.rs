// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// This file incorporates work covered by the following copyright and
// permission notice:
//
//   Copyright (c) Mullvad VPN AB. All rights reserved.
//   Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
//
// SPDX-License-Identifier: MPL-2.0

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

/// Command types for the WireGuard userspace API.
pub mod command;
/// Application of WireGuard userspace API to a WireGuard device.
pub mod device;

use command::{Request, Response};
use eyre::{Context, bail, eyre};
#[cfg(unix)]
use nix::unistd::{Gid, Uid};
use std::fmt::Debug;
use std::io::{BufRead, BufReader, Read, Write};
use std::str::FromStr;
use tokio::sync::{mpsc, oneshot};

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
/// Use [`UapiClient::send`] or [`UapiClient::send_sync`] to configure the [`Device`] by adding
/// peers, etc.
///
/// [`Device`]: crate::device::Device
#[derive(Clone)]
pub struct UapiClient {
    tx: mpsc::Sender<(Request, oneshot::Sender<Response>)>,
}

impl UapiClient {
    /// Send a request to the device and wait for a response asynchronously.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the channel is closed.
    /// Returns a [`Response`] with `errno != 0` if the request fails.
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

    /// Send a request to the device and wait for a response synchronously (blocking).
    ///
    /// # Errors
    ///
    /// Returns `Err` if the channel is closed.
    /// Returns a [`Response`] with `errno != 0` if the request fails.
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
    /// Create a new UAPI client and server pair.
    ///
    /// The client can be used to send requests, and the server receives them.
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

    /// Wait for a [`Request`] from a client.
    ///
    /// The response should be sent back using the provided [`oneshot`] sender.
    ///
    /// Returns `None` when all clients have disconnected.
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
