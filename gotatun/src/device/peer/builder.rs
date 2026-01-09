// Copyright (c) 2026 Mullvad VPN AB. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use std::net::SocketAddr;

use ipnetwork::IpNetwork;
use x25519_dalek::PublicKey;

use crate::device::daita::DaitaSettings;

// TODO: name
#[non_exhaustive]
pub struct PeerBuilder {
    pub public_key: PublicKey,
    pub endpoint: Option<SocketAddr>,
    pub allowed_ips: Vec<IpNetwork>,
    // TODO: zeroize
    pub preshared_key: Option<[u8; 32]>,
    pub keepalive: Option<u16>,

    // TODO
    pub(crate) daita_settings: Option<DaitaSettings>,
}

impl PeerBuilder {
    pub const fn new(public_key: PublicKey) -> Self {
        Self {
            public_key,
            endpoint: None,
            allowed_ips: Vec::new(),
            preshared_key: None,
            keepalive: None,
            daita_settings: None,
        }
    }

    pub const fn with_endpoint(mut self, endpoint: SocketAddr) -> Self {
        self.endpoint = Some(endpoint);
        self
    }

    pub fn with_allowed_ip(mut self, network: IpNetwork) -> Self {
        self.allowed_ips.push(network);
        self
    }

    pub fn with_allowed_ips(mut self, networks: impl IntoIterator<Item = IpNetwork>) -> Self {
        self.allowed_ips.extend(networks);
        self
    }

    pub const fn with_preshared_key(mut self, preshared_key: [u8; 32]) -> Self {
        self.preshared_key = Some(preshared_key);
        self
    }

    pub fn with_daita(mut self, daita_settings: DaitaSettings) -> Self {
        self.daita_settings = Some(daita_settings);
        self
    }
}
