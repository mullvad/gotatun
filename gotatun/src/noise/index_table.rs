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

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use rand::rngs::SysRng;

/// A table of unique session IDs.
///
/// All peers share a single `IndexTable` to ensure no two sessions use the same index.
/// Indices are random `u32`s and freed automatically when the returned [`Index`] is dropped.
#[derive(Clone)]
pub struct IndexTable<Rng = SysRng>(Arc<Mutex<(Rng, HashSet<u32>)>>);

/// A 32-bit index that locally represents the other peer, analogous to IPsec’s “SPI”.
///
/// A session index is derived from [`IndexTable::new_index`], and the session index is
/// automatically freed from its [`IndexTable`] on drop.
///
/// See section 5.4 of the [whitepaper](https://www.wireguard.com/papers/wireguard.pdf).
pub struct Index<Rng = SysRng> {
    value: u32,
    table: IndexTable<Rng>,
}

impl<Rng> IndexTable<Rng>
where
    Rng: rand::TryRng,
{
    /// Generate a random `u32` not already in the table.
    ///
    /// The returned [`Index`] keeps the entry reserved; dropping it frees the slot.
    pub fn new_index(&self) -> Index<Rng> {
        let mut g = self.0.lock().unwrap();
        // Find a free index by guessing. See the rationale here:
        // https://github.com/torvalds/linux/blob/e81dd54f62c753dd423d1a9b62481a1c599fb975/drivers/net/wireguard/peerlookup.c#L95-L117
        // Even if the table contained 2^31 entries, you'd usually only need 1-2 attempts.
        loop {
            let idx = Self::next_id(&mut g.0);
            if g.1.insert(idx) {
                return Index {
                    value: idx,
                    table: Self(Arc::clone(&self.0)),
                };
            }
        }
    }

    /// Naively generate the next session ID. This index is not guaranteed to be locally unique.
    pub(crate) fn next_id(rng: &mut Rng) -> u32 {
        rng.try_next_u32().unwrap()
    }

    /// Create a new [`IndexTable`] using the given [`RngCore`].
    pub fn from_rng(rng: Rng) -> Self {
        IndexTable(Arc::new(Mutex::new((rng, HashSet::new()))))
    }

    /// Check if an index is already in the table.
    pub fn in_use(&self, value: u32) -> bool {
        let g = self.0.lock().unwrap();
        g.1.contains(&value)
    }
}

impl IndexTable<SysRng> {
    /// Create a new [`IndexTable`] seeded using [`SysRng`].
    pub fn from_os_rng() -> Self {
        let rng = SysRng;
        IndexTable::from_rng(rng)
    }
}

impl<Rng> IndexTable<Rng> {
    /// Remove an index from the table, making it available for reuse.
    fn free_index(&self, index: u32) {
        let mut g = self.0.lock().unwrap();
        g.1.remove(&index);
    }
}

impl Index {
    /// The raw `u32` index value.
    pub fn value(&self) -> u32 {
        self.value
    }
}

impl<Rng> Drop for Index<Rng> {
    fn drop(&mut self) {
        self.table.free_index(self.value);
    }
}

impl std::fmt::Debug for Index {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.value.fmt(f)
    }
}

impl std::fmt::Display for Index {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.value.fmt(f)
    }
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;

    use rand::TryRng;

    use super::*;

    #[derive(Default)]
    struct ModCounter {
        dividend: u32,
        divisor: u32,
    }

    impl TryRng for ModCounter {
        type Error = Infallible;

        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            let v = self.dividend % self.divisor;
            self.dividend += 1;
            Ok(v)
        }

        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            unimplemented!()
        }

        fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
            unimplemented!()
        }
    }

    /// Test that indices are freed when dropped.
    #[test]
    fn test_reuse_on_drop() {
        let table = IndexTable::from_rng(ModCounter {
            dividend: 0,
            divisor: 3,
        });

        let a = table.new_index();
        let b = table.new_index();
        let c = table.new_index();

        assert_eq!(a.value, 0);
        assert_eq!(b.value, 1);
        assert_eq!(c.value, 2);

        // 1 should be the only free value
        let recycled = b.value;
        drop(b);
        for _ in 0..10 {
            assert_eq!(table.new_index().value, recycled);
        }
    }
}
