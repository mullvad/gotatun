// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
//
// Modified by Mullvad VPN.
// Copyright (c) 2025 Mullvad VPN.
//
// SPDX-License-Identifier: BSD-3-Clause

//! A library implementation of [WireGuard](https://www.wireguard.com/).

#[cfg(feature = "device")]
pub mod device;

pub mod noise;
pub mod packet;
pub mod tun;
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
