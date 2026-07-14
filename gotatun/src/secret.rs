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

use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Fixed-size secret storage kept behind a stable heap allocation, so moving
/// an owner moves only the pointer rather than copying the key bytes. The outer
/// drop clears eagerly and `Zeroizing` remains the final drop guard.
pub(crate) struct SecretBytes32(Box<Zeroizing<[u8; 32]>>);

impl SecretBytes32 {
    pub(crate) fn from_bytes_ref(bytes: &[u8; 32]) -> Self {
        let mut secret = Self::zeroed();
        secret.0.as_mut().copy_from_slice(bytes);
        secret
    }

    pub(crate) fn take_from(bytes: &mut [u8; 32]) -> Self {
        let secret = Self::from_bytes_ref(bytes);
        bytes.zeroize();
        secret
    }

    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_ref()
    }

    fn zeroed() -> Self {
        Self(Box::new(Zeroizing::new([0u8; 32])))
    }

    fn zeroize(&mut self) {
        self.0.as_mut().zeroize();
    }
}

impl Clone for SecretBytes32 {
    fn clone(&self) -> Self {
        Self::from_bytes_ref(self.as_bytes())
    }
}

impl Drop for SecretBytes32 {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for SecretBytes32 {}

/// WireGuard preshared key material.
///
/// This type owns PSK bytes as secret material: it is non-`Copy`, redacts
/// `Debug`, and zeroizes its backing storage on drop. Raw byte arrays should
/// only be used at explicit import/export boundaries or borrowed for crypto.
/// Cloning creates an independent zeroizing allocation; replacing or dropping
/// one value does not revoke any clones. Caller-owned buffers, compiler-created
/// temporaries, registers, and allocator history are outside this guarantee.
pub struct PresharedKey(SecretBytes32);

impl PresharedKey {
    /// Copy raw PSK bytes into a secret-owning value.
    ///
    /// This clears the function's local input after importing it, but arrays
    /// are [`Copy`]. Any copy retained by the caller is unaffected. Use
    /// [`Self::take_from`] to clear a mutable source array while importing it.
    pub fn new(mut bytes: [u8; 32]) -> Self {
        Self::take_from(&mut bytes)
    }

    /// Import raw PSK bytes and zeroize the source array.
    ///
    /// This covers the supplied array, but not copies retained elsewhere or
    /// compiler-generated temporaries.
    pub fn take_from(bytes: &mut [u8; 32]) -> Self {
        Self(SecretBytes32::take_from(bytes))
    }

    /// Copy borrowed raw PSK bytes into a secret-owning value.
    ///
    /// The source is not cleared. The borrowed bytes are secret material and
    /// should only be exposed at an explicit import/export or cryptographic
    /// boundary.
    pub fn from_bytes_ref(bytes: &[u8; 32]) -> Self {
        Self(SecretBytes32::from_bytes_ref(bytes))
    }

    /// Borrow the PSK bytes for cryptographic use.
    ///
    /// The returned bytes are secret material. Do not store, log, or copy them
    /// unless crossing an explicit export or cryptographic boundary.
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }
}

impl Clone for PresharedKey {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl fmt::Debug for PresharedKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("PresharedKey").field(&"<redacted>").finish()
    }
}

impl ZeroizeOnDrop for PresharedKey {}

impl From<[u8; 32]> for PresharedKey {
    fn from(mut bytes: [u8; 32]) -> Self {
        Self::take_from(&mut bytes)
    }
}

#[cfg(test)]
mod tests {
    use zeroize::ZeroizeOnDrop;

    use super::PresharedKey;

    fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}

    #[test]
    fn implements_zeroize_on_drop() {
        assert_zeroize_on_drop::<PresharedKey>();
    }

    #[test]
    fn take_from_clears_source() {
        let mut source = [0xA5; 32];
        let key = PresharedKey::take_from(&mut source);

        assert_eq!(source, [0; 32]);
        assert_eq!(key.as_bytes(), &[0xA5; 32]);
    }

    #[test]
    fn clone_uses_independent_storage() {
        let key = PresharedKey::new([0xA5; 32]);
        let clone = key.clone();

        assert_eq!(clone.as_bytes(), key.as_bytes());
        assert_ne!(clone.as_bytes().as_ptr(), key.as_bytes().as_ptr());
    }

    #[test]
    fn debug_redacts_preshared_key() {
        let key = PresharedKey::new([0xA5; 32]);
        let debug = format!("{key:?}");

        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("165"), "PSK Debug must not print raw bytes");
    }
}
