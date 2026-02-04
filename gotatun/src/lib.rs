// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
//
// Modified by Mullvad VPN.
// Copyright (c) 2025 Mullvad VPN.
//
// SPDX-License-Identifier: BSD-3-Clause

//! A library implementation of [WireGuard](https://www.wireguard.com/).

// Warn on missing docs when running `cargo doc`
#![cfg_attr(doc, warn(missing_docs))]

#[cfg(feature = "device")]
/// WireGuard device implementation with support for peers, handshakes, and packet routing.
pub mod device;

/// Noise protocol implementation for WireGuard cryptographic handshakes and sessions.
pub mod noise;
/// Packet types and parsing for WireGuard and IP packets.
pub mod packet;
/// TUN device interface for reading and writing IP packets.
pub mod tun;
/// UDP socket interface for sending and receiving WireGuard packets.
pub mod udp;

mod task;

#[cfg(not(feature = "mock_instant"))]
pub(crate) mod sleepyinstant;

#[cfg(feature = "device")]
pub(crate) mod serialization;

/// Re-export of the x25519 types
pub mod x25519 {
    pub use x25519_dalek::{
        EphemeralSecret, PublicKey, ReusableSecret, SharedSecret, StaticSecret,
    };
}
