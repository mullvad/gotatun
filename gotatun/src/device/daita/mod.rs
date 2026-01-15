// Copyright (c) 2025 Mullvad VPN AB. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Implementation of DAITA for GotaTun.
//!
//! DAITA (Defense Against AI-guided Traffic Analysis) is MullvadVPN's implementation of
//! an anti-fingerprinting protocol based on the [maybenot] crate.

mod actions;
mod events;
mod hooks;
mod types;

use std::num::NonZeroUsize;

pub use hooks::DaitaHooks;
pub use maybenot;
pub use maybenot::Error;
pub use maybenot::Machine;

#[derive(Debug, Clone)]
pub struct DaitaSettings {
    /// The maybenot machines to use.
    pub maybenot_machines: Vec<Machine>,
    /// Maximum fraction of bandwidth that may be used for padding packets.
    pub max_padding_frac: f64,
    /// Maximum fraction of bandwidth that may be used for blocking packets.
    pub max_blocking_frac: f64,
    /// Maximum number of packets that may be blocked at any time.
    pub max_blocked_packets: NonZeroUsize,
    /// Minimum number of free slots in the blocking queue to continue blocking.
    pub min_blocking_capacity: usize,
}

impl Default for DaitaSettings {
    fn default() -> Self {
        Self {
            maybenot_machines: vec![],
            max_padding_frac: 0.0,
            max_blocking_frac: 0.0,
            max_blocked_packets: const { NonZeroUsize::new(1024).unwrap() },
            min_blocking_capacity: 50,
        }
    }
}
