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

//! WireGuard userspace socket.

use eyre::{bail, eyre};
use nix::unistd::{Gid, Uid};

use super::UapiServer;

const SOCK_DIR: &str = "/var/run/wireguard/";

/// Extension trait for [`UapiServer`].
///
/// Contains one method [`UapiSocket::default_unix_socket`] for creating a dedicated unix socket
/// for UAPI communication.
pub trait UapiSocket {
    /// Spawn a unix socket at `/var/run/wireguard/<name>.sock`. This socket speaks the official
    /// [configuration protocol](https://www.wireguard.com/xplatform/#configuration-protocol).
    ///
    /// Optionally, set the owner of the socket using `uid` and `gid`.
    fn default_unix_socket(name: &str, uid: Option<Uid>, gid: Option<Gid>) -> eyre::Result<Self>
    where
        Self: std::marker::Sized;
}

impl UapiSocket for UapiServer {
    fn default_unix_socket(name: &str, uid: Option<Uid>, gid: Option<Gid>) -> eyre::Result<Self> {
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
}

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
