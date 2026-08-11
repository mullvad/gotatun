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

use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD},
};

pub struct KeyBytes(pub [u8; 32]);

impl std::str::FromStr for KeyBytes {
    type Err = &'static str;

    /// Can parse a secret key from a hex or base64 encoded string.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut internal = [0u8; 32];

        match s.len() {
            64 => {
                // Try to parse as hex
                for i in 0..32 {
                    internal[i] = u8::from_str_radix(&s[i * 2..=i * 2 + 1], 16)
                        .map_err(|_| "Illegal character in key")?;
                }
            }
            43 | 44 => {
                // Try to parse as base64
                let decoded_key = if s.len() == 43 {
                    STANDARD_NO_PAD.decode(s)
                } else {
                    STANDARD.decode(s)
                }
                .map_err(|_| "Illegal character in key")?;

                if decoded_key.len() != internal.len() {
                    return Err("Illegal character in key");
                }
                internal.copy_from_slice(&decoded_key);
            }
            _ => return Err("Illegal key size"),
        }

        Ok(KeyBytes(internal))
    }
}

impl std::fmt::Debug for KeyBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("KeyBytes").field(&..).finish()
    }
}

impl From<[u8; 32]> for KeyBytes {
    fn from(bytes: [u8; 32]) -> Self {
        KeyBytes(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::KeyBytes;

    const KEY: [u8; 32] = [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
        25, 26, 27, 28, 29, 30, 31,
    ];

    #[test]
    fn parse_padded_and_unpadded_base64_keys() {
        for encoded in [
            "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
            "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
        ] {
            assert_eq!(encoded.parse::<KeyBytes>().unwrap().0, KEY);
        }
    }

    #[test]
    fn reject_invalid_base64_keys() {
        for invalid in ["!".repeat(43), "!".repeat(44), "A".repeat(44)] {
            assert!(invalid.parse::<KeyBytes>().is_err());
        }
    }
}
