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
