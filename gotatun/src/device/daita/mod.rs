// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// This file incorporates work covered by the following copyright and
// permission notice:
//
//   Copyright (c) Mullvad VPN AB. All rights reserved.
//
// SPDX-License-Identifier: MPL-2.0

//! Implementation of DAITA for GotaTun.
//!
//! DAITA (Defense Against AI-guided Traffic Analysis) is an implementation of
//! an AI-fingerprinting defense scheme by Mullvad VPN based on the [maybenot] framework.

mod actions;
mod events;
mod hooks;
mod types;

use std::num::NonZeroUsize;

pub(crate) use hooks::DaitaHooks;
pub use maybenot;
pub use maybenot::Error;
pub use maybenot::Machine;

/// Configuration settings for DAITA (Defense Against AI-guided Traffic Analysis).
#[derive(Debug, Clone)]
pub struct DaitaSettings {
    /// The maybenot machines to use.
    pub maybenot_machines: Vec<Machine>,
    /// Maximum fraction of bandwidth that may be used for decoy packets.
    pub max_decoy_frac: f64,
    /// Maximum fraction of bandwidth that may be used for delayed packets.
    pub max_delay_frac: f64,
    /// Maximum number of packets that may be delayed at any time.
    pub max_delayed_packets: NonZeroUsize,
    /// Minimum number of free slots in the delay queue before the delay state is aborted.
    pub min_delay_capacity: usize,
}

impl Default for DaitaSettings {
    fn default() -> Self {
        Self {
            maybenot_machines: vec![],
            max_decoy_frac: 0.0,
            max_delay_frac: 0.0,
            max_delayed_packets: const { NonZeroUsize::new(1024).unwrap() },
            min_delay_capacity: 50,
        }
    }
}
