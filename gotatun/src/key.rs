// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
//   Copyright (c) Mullvad VPN AB. All rights reserved.
//
// SPDX-License-Identifier: MPL-2.0

//! WireGuard peer keys validated at the type level.

use std::borrow::Borrow;

use crate::x25519;

/// A peer's static public key, validated as *contributory*.
///
/// A low-order Curve25519 point produces an all-zero (non-contributory)
/// Diffie-Hellman result for every scalar, making the derived key predictable to
/// an eavesdropper. The WireGuard spec does not require rejecting these points,
/// but we do so as a hardening measure, matching the Linux kernel WireGuard
/// implementation.
///
/// Every constructor ([`PeerPublicKey::new`] and the equivalent
/// [`TryFrom`] impl) rejects such points, so holding a `PeerPublicKey` is proof
/// the key passed this check. This lets the handshake code treat the peer static
/// key as infallible rather than re-checking it on every handshake.
///
/// # Examples
///
/// ```
/// use gotatun::{InvalidPeerKey, PeerPublicKey};
/// use gotatun::x25519;
///
/// let secret = x25519::StaticSecret::from([0x42; 32]);
/// let public_key = x25519::PublicKey::from(&secret);
/// let peer_public_key = PeerPublicKey::new(public_key)?;
/// # Ok::<(), InvalidPeerKey>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PeerPublicKey(x25519::PublicKey);

impl PeerPublicKey {
    /// Validates `public_key` as contributory and wraps it.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidPeerKey`] if `public_key` is a low-order
    /// (non-contributory) Curve25519 point.
    pub fn new(public_key: x25519::PublicKey) -> Result<Self, InvalidPeerKey> {
        // An arbitrary fixed scalar. Whether `scalar * point` is the all-zero
        // (non-contributory) value depends only on `point`, not the scalar, so
        // any fixed non-low-order scalar reveals every low-order point. This is
        // a complete check: it also rejects low-order points on the curve's
        // twist, not just the canonical curve points.
        const PROBE_SCALAR: [u8; 32] = [1u8; 32];

        let probe = x25519::StaticSecret::from(PROBE_SCALAR);
        if probe.diffie_hellman(&public_key).was_contributory() {
            Ok(Self(public_key))
        } else {
            Err(InvalidPeerKey)
        }
    }

    /// The wrapped [`x25519::PublicKey`].
    pub fn as_public_key(&self) -> &x25519::PublicKey {
        &self.0
    }
}

impl From<PeerPublicKey> for x25519::PublicKey {
    fn from(peer_public_key: PeerPublicKey) -> Self {
        peer_public_key.0
    }
}

// A `PeerPublicKey` hashes and compares identically to its inner
// `x25519::PublicKey` (the derived `Hash`/`Eq` just delegate to the single
// field), so it can be used as a map key while still being looked up by a plain
// `x25519::PublicKey`, e.g. one reconstructed from a received handshake.
impl Borrow<x25519::PublicKey> for PeerPublicKey {
    fn borrow(&self) -> &x25519::PublicKey {
        &self.0
    }
}

impl TryFrom<x25519::PublicKey> for PeerPublicKey {
    type Error = InvalidPeerKey;

    /// Equivalent to [`PeerPublicKey::new`].
    ///
    /// # Errors
    ///
    /// Returns [`InvalidPeerKey`] if `public_key` is a low-order
    /// (non-contributory) Curve25519 point.
    fn try_from(public_key: x25519::PublicKey) -> Result<Self, InvalidPeerKey> {
        Self::new(public_key)
    }
}

/// A peer public key was a low-order (non-contributory) Curve25519 point.
///
/// See [`PeerPublicKey`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
#[error("peer public key is a low-order (non-contributory) Curve25519 point")]
pub struct InvalidPeerKey;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::noise::handshake::low_order_keys;

    /// A genuine, randomly generated public key is accepted.
    #[test]
    fn accepts_contributory_key() {
        let public_key =
            x25519::PublicKey::from(&x25519::StaticSecret::random_from_rng(rand_core::OsRng));
        assert!(PeerPublicKey::new(public_key).is_ok());
    }

    /// Every known low-order point is rejected at construction.
    #[test]
    fn rejects_low_order_keys() {
        for low_order in low_order_keys() {
            let public_key = x25519::PublicKey::from(low_order);
            assert_eq!(
                PeerPublicKey::new(public_key),
                Err(InvalidPeerKey),
                "point {low_order:02x?}: expected rejection"
            );
        }
    }
}
