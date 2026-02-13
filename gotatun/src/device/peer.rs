// Copyright (c) 2026 Mullvad VPN AB. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use std::net::SocketAddr;

use ipnetwork::IpNetwork;
use x25519_dalek::PublicKey;

#[cfg(feature = "daita")]
use crate::device::daita::DaitaSettings;

/// Peer data. Used to construct and update peers in a [`Device`](crate::device::Device).
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct Peer {
    /// The peer's public key.
    pub public_key: PublicKey,
    /// The peer's endpoint address (IP and port).
    ///
    /// An incoming handshake from the peer will overwrite the endpoint to the source
    /// address of the handshake. If `None`, the peer is inactive until we receive a
    /// handshake from that peer.
    pub endpoint: Option<SocketAddr>,
    /// List of IP networks that are allowed to be routed through this peer.
    pub allowed_ips: Vec<IpNetwork>,
    // TODO: zeroize
    /// Optional preshared key for additional security.
    pub preshared_key: Option<[u8; 32]>,
    /// Persistent keepalive interval in seconds. Disabled if `None`.
    pub keepalive: Option<u16>,

    /// DAITA settings for this peer, if the DAITA feature is enabled.
    #[cfg(feature = "daita")]
    pub daita_settings: Option<DaitaSettings>,
}

impl Peer {
    /// Create a new peer with the given public key.
    ///
    /// All other fields are set to their default values.
    pub const fn new(public_key: PublicKey) -> Self {
        Self {
            public_key,
            endpoint: None,
            allowed_ips: Vec::new(),
            preshared_key: None,
            keepalive: None,
            #[cfg(feature = "daita")]
            daita_settings: None,
        }
    }

    /// Set the endpoint address for this peer.
    pub const fn with_endpoint(mut self, endpoint: SocketAddr) -> Self {
        self.endpoint = Some(endpoint);
        self
    }

    /// Add a single allowed IP network for this peer.
    pub fn with_allowed_ip(mut self, network: IpNetwork) -> Self {
        self.allowed_ips.push(network);
        self
    }

    /// Add multiple allowed IP networks for this peer.
    pub fn with_allowed_ips(mut self, networks: impl IntoIterator<Item = IpNetwork>) -> Self {
        self.allowed_ips.extend(networks);
        self
    }

    /// Set the preshared key for this peer.
    pub const fn with_preshared_key(mut self, preshared_key: [u8; 32]) -> Self {
        self.preshared_key = Some(preshared_key);
        self
    }

    /// Set the DAITA settings for this peer.
    #[cfg(feature = "daita")]
    pub fn with_daita(mut self, daita_settings: DaitaSettings) -> Self {
        self.daita_settings = Some(daita_settings);
        self
    }
}
