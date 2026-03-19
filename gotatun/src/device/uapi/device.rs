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

//! TODO

use std::sync::Weak;
#[cfg(feature = "daita-uapi")]
use std::sync::atomic;
use std::time::SystemTime;

use nix::libc::EINVAL;
use tokio::sync::RwLock;

use crate::device::uapi::command::SetResponse;
#[cfg(feature = "daita-uapi")]
use crate::device::uapi::command::SetUnset;
use crate::device::{Connection, DeviceState, DeviceTransports, Reconfigure};
use crate::serialization::KeyBytes;

use super::command::{Get, GetPeer, GetResponse, Peer, Request, Response, Set, SetPeer};
use super::{UapiServer, command};

impl<T: DeviceTransports> DeviceState<T> {
    pub async fn handle_api(device: Weak<RwLock<Self>>, mut api: UapiServer) {
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
                preshared_key: peer.preshared_key.map(|key| SetUnset::Set(KeyBytes(key))),
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
