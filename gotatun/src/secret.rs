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

use std::fmt;
use std::sync::Arc;

use zeroize::{Zeroize, Zeroizing};

/// 32-byte key storage that zeroizes its allocation on drop.
///
/// See [`zeroize`] for caveats.
#[derive(Clone)]
pub(crate) struct SecretBytes32(Arc<Zeroizing<[u8; 32]>>);

impl SecretBytes32 {
    pub(crate) fn take_from(bytes: &mut [u8; 32]) -> Self {
        let secret = Self::copy_from(bytes);
        bytes.zeroize();
        secret
    }

    pub(crate) fn copy_from(bytes: &[u8; 32]) -> Self {
        let mut secret = Self::zeroed();
        Arc::get_mut(&mut secret.0)
            .expect("new secret is not shared")
            .copy_from_slice(bytes);
        secret
    }

    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_ref()
    }

    fn zeroed() -> Self {
        Self(Arc::new(Zeroizing::new([0u8; 32])))
    }
}

/// WireGuard preshared key material.
#[derive(Clone)]
pub struct PresharedKey(SecretBytes32);

impl PresharedKey {
    /// Create a [`PresharedKey`] by copying a byte array.
    ///
    /// This clears the function's local input after importing it, but arrays
    /// are [`Copy`]. Any copy retained by the caller is unaffected. Use
    /// [`Self::take_from`] to clear a mutable source array while importing it.
    pub fn new(mut bytes: [u8; 32]) -> Self {
        Self::take_from(&mut bytes)
    }

    /// Create a [`PresharedKey`] by copying and zeriozing a byte array.
    ///
    /// The provided buffer will be zeroized.
    /// The zeroizing covers the supplied array, but not copies retained
    /// elsewhere or compiler-generated temporaries.
    pub fn take_from(bytes: &mut [u8; 32]) -> Self {
        Self(SecretBytes32::take_from(bytes))
    }

    /// Create a [`PresharedKey`] by copying a byte array.
    ///
    /// Prefer [`PresharedKey::take_from`], as that will attempt to zeroize the
    /// source buffer. Since these bytes are secret material, they should only
    /// be exposed at an explicit import/export or cryptographic boundary.
    pub fn copy_from(bytes: &[u8; 32]) -> Self {
        Self(SecretBytes32::copy_from(bytes))
    }

    /// Borrow the PSK bytes for cryptographic use.
    ///
    /// The returned bytes are secret material. Do not store, log, or copy them
    /// unless crossing an explicit export or cryptographic boundary.
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }
}

impl fmt::Debug for PresharedKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("PresharedKey").field(&"<redacted>").finish()
    }
}

impl From<[u8; 32]> for PresharedKey {
    fn from(mut bytes: [u8; 32]) -> Self {
        Self::take_from(&mut bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::PresharedKey;

    #[test]
    fn debug_redacts_preshared_key() {
        let key = PresharedKey::new([165; 32]);
        let debug = format!("{key:?}");

        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("165"), "PSK Debug must not print raw bytes");
    }
}
