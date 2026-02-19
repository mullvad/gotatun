// Copyright (c) 2026 Mullvad VPN AB. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};

/// A table of unique session IDs.
///
/// All peers share a single `IndexTable` to ensure no two sessions use the same index.
/// Indices are random `u32`s and freed automatically when the returned [`Index`] is dropped.
#[derive(Clone)]
pub struct IndexTable<Rng = StdRng>(Arc<Mutex<(Rng, HashSet<u32>)>>);

/// A 32-bit index that locally represents the other peer, analogous to IPsec’s “SPI”.
///
/// A session index is derived from [`IndexTable::new_index`], and the session index is
/// automatically freed from its [`IndexTable`] on drop.
///
/// See section 5.4 of the [whitepaper](https://www.wireguard.com/papers/wireguard.pdf).
pub struct Index<Rng = StdRng> {
    value: u32,
    table: IndexTable<Rng>,
}

impl<Rng> IndexTable<Rng>
where
    Rng: RngCore,
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
            let idx = g.0.next_u32();
            if g.1.insert(idx) {
                return Index {
                    value: idx,
                    table: Self(Arc::clone(&self.0)),
                };
            }
        }
    }

    /// Create a new [`IndexTable`] using the given [`RngCore`].
    pub fn from_rng(rng: Rng) -> Self {
        IndexTable(Arc::new(Mutex::new((rng, HashSet::new()))))
    }
}

impl<Rng> IndexTable<Rng>
where
    Rng: SeedableRng + RngCore,
{
    /// Create a new [`IndexTable`] seeded using `OsRng`.
    pub fn from_os_rng() -> Self {
        Self::from_rng(Rng::from_os_rng())
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
