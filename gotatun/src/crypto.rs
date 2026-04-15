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

//! ChaCha20-Poly1305 AEAD backend, selected at compile time by the
//! `aws-lc-rs` and `ring` Cargo features. `aws-lc-rs` is the default
//! and takes precedence when both are enabled. At least one feature
//! must be enabled.
//!
//! Enabling both backends compiles and links `ring` for nothing.
//! Disable default features if you plan on using ring.

#[cfg(not(any(feature = "ring", feature = "aws-lc-rs")))]
compile_error!(
    "gotatun requires at least one of the `ring` or `aws-lc-rs` Cargo features to be enabled"
);

#[cfg(feature = "aws-lc-rs")]
pub use aws_lc_rs::{aead, error};

#[cfg(all(feature = "ring", not(feature = "aws-lc-rs")))]
pub use ring::{aead, error};
