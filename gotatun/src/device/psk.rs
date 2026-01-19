// Copyright (c) 2026 Mullvad VPN AB. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Pre-shared Symmetric Key used for the extremely paranoid.
//!
//! See section 5.2 of the [whitepaper](https://www.wireguard.com/papers/wireguard.pdf).

use zeroize::Zeroize;

/// A 256-bit symmetric encryption key for an additional layer of symmetric encryption between peers.
//
// # TODO: Mark as sensitive? Do not implement Debug?
#[derive(Clone, Debug)]
pub struct Psk(pub [u8; 32]);

impl Psk {
    /// Create a new [`Psk`].
    pub const fn new(key: [u8; 32]) -> Self {
        Self(key)
    }
}

impl Drop for Psk {
    /// Wipe memory backing PSK on drop.
    fn drop(&mut self) {
        self.0.zeroize();
    }
}
