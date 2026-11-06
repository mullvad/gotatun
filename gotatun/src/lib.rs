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

//! A library implementation of [WireGuard](https://www.wireguard.com/).

// Warn on missing docs when running `cargo doc`
#![cfg_attr(doc, warn(missing_docs))]
// Enables this nightly only feature for the documentation build on docs.rs.
// To test this locally, build the docs with:
// `RUSTDOCFLAGS="--cfg docsrs" cargo +nightly doc --all-features`
#![cfg_attr(docsrs, feature(doc_cfg))]

#[cfg(feature = "device")]
pub mod device;
pub mod noise;
pub mod tun;
pub mod udp;

mod task;

#[cfg(not(feature = "mock_instant"))]
pub mod sleepyinstant;

/// The monotonic clock that the tunnel timers are measured against, and that
/// [`noise::Tunn::next_timer_deadline`] returns deadlines on.
///
/// This is [`sleepyinstant::Instant`], which — unlike [`std::time::Instant`] — keeps running
/// while the system is suspended. With the `mock_instant` feature it is instead
/// `mock_instant`'s controllable clock, so that tests can drive the timers.
#[cfg(not(feature = "mock_instant"))]
pub use sleepyinstant::Instant;

/// The monotonic clock that the tunnel timers are measured against, and that
/// [`noise::Tunn::next_timer_deadline`] returns deadlines on.
///
/// The `mock_instant` feature replaces the real clock with `mock_instant`'s controllable one,
/// so that tests can drive the timers.
#[cfg(feature = "mock_instant")]
pub use mock_instant::thread_local::Instant;

#[cfg(feature = "device")]
pub(crate) mod serialization;

/// Re-export `gotatun-packet` types
pub use gotatun_packet as packet;

/// Re-export of the x25519 types
pub use gotatun_crypto::x25519;
