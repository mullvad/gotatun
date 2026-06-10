// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
//   Copyright (c) Mullvad VPN AB. All rights reserved.
//
// SPDX-License-Identifier: MPL-2.0

//! X25519 key agreement wrappers that make it impossible to accidentally use a
//! non-contributory (all-zero) Diffie-Hellman result.
//!
//! The contributory check is the only way to construct a [`SharedSecret`], and
//! a [`SharedSecret`] is the only thing in this module that exposes secret
//! bytes. Because the wrapped `x25519_dalek` types are private to this module,
//! code outside it cannot reach dalek's unchecked `diffie_hellman` nor read a
//! raw shared secret. The check is therefore not merely easy to remember, it is
//! impossible to bypass.
//!
//! A non-contributory result is produced by a low-order peer public key. The
//! Noise spec treats rejecting it as optional (§12.1), but the Linux kernel
//! WireGuard implementation does so as a fail-fast hardening measure
//! (`mix_dh`/`curve25519`); this matches its behavior.

use crate::noise::errors::WireGuardError;
use crate::x25519;

/// A long-term static secret key. Wraps the dalek key so the only key agreement
/// it offers is the checked [`StaticSecret::dh`].
pub(crate) struct StaticSecret(x25519::StaticSecret);

impl StaticSecret {
    /// The public key corresponding to this secret key.
    pub(crate) fn public_key(&self) -> x25519::PublicKey {
        x25519::PublicKey::from(&self.0)
    }

    /// Performs the key agreement against `peer`.
    ///
    /// # Errors
    ///
    /// Returns [`WireGuardError::InvalidSharedSecret`] if the result is
    /// non-contributory (all-zero), indicating a low-order `peer` key.
    pub(crate) fn dh(&self, peer: &x25519::PublicKey) -> Result<SharedSecret, WireGuardError> {
        SharedSecret::checked(self.0.diffie_hellman(peer))
    }
}

impl From<x25519::StaticSecret> for StaticSecret {
    fn from(secret: x25519::StaticSecret) -> Self {
        Self(secret)
    }
}

/// A per-handshake ephemeral secret key. Wraps `ReusableSecret` rather than
/// dalek's `EphemeralSecret`, because the latter is consumed by value on a
/// single agreement, while a handshake performs two agreements with the same
/// ephemeral key.
pub(crate) struct EphemeralSecret(x25519::ReusableSecret);

impl EphemeralSecret {
    /// Generates a fresh ephemeral secret key.
    pub(crate) fn random() -> Self {
        Self(x25519::ReusableSecret::random_from_rng(rand_core::OsRng))
    }

    /// The public key corresponding to this secret key.
    pub(crate) fn public_key(&self) -> x25519::PublicKey {
        x25519::PublicKey::from(&self.0)
    }

    /// Performs the key agreement against `peer`.
    ///
    /// # Errors
    ///
    /// Returns [`WireGuardError::InvalidSharedSecret`] if the result is
    /// non-contributory (all-zero), indicating a low-order `peer` key.
    pub(crate) fn dh(&self, peer: &x25519::PublicKey) -> Result<SharedSecret, WireGuardError> {
        SharedSecret::checked(self.0.diffie_hellman(peer))
    }
}

/// A shared secret that has passed the non-contributory check.
///
/// The only constructor is the private [`SharedSecret::checked`], reachable
/// solely through [`StaticSecret::dh`] / [`EphemeralSecret::dh`], so merely
/// holding a value of this type is proof the check passed. Its bytes leave the
/// module only as the `&[u8; 32]` returned by [`SharedSecret::as_bytes`].
pub(crate) struct SharedSecret(x25519::SharedSecret);

impl SharedSecret {
    /// Wraps a raw shared secret, rejecting a non-contributory (all-zero) one.
    fn checked(shared: x25519::SharedSecret) -> Result<Self, WireGuardError> {
        if shared.was_contributory() {
            Ok(Self(shared))
        } else {
            Err(WireGuardError::InvalidSharedSecret)
        }
    }

    /// The shared secret bytes, safe to mix into the KDF.
    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }
}
