// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause
#![feature(allocator_api)]

//! Simple implementation of the client-side of the WireGuard protocol.
//!
//! <code>git clone https://github.com/cloudflare/boringtun.git</code>

#[cfg(feature = "device")]
pub mod device;

pub mod udp;

pub mod noise;
pub mod packet;
pub mod tun;

mod task;

#[cfg(not(feature = "mock-instant"))]
pub(crate) mod sleepyinstant;

#[cfg(feature = "device")]
pub(crate) mod serialization;

/// Re-export of the x25519 types
pub mod x25519 {
    pub use x25519_dalek::{
        EphemeralSecret, PublicKey, ReusableSecret, SharedSecret, StaticSecret,
    };
}
