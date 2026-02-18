// Copyright (c) 2026 Mullvad VPN AB. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use rand::rngs::{OsRng, StdRng};
use rand::{RngCore, SeedableRng, TryRngCore};

/// A table of unique session IDs.
///
/// All peers share a single `IndexTable` to ensure no two sessions use the same index.
/// Indices are random `u32`s and freed automatically when the returned [`Index`] is dropped.
#[derive(Clone)]
pub struct IndexTable(Arc<Mutex<(StdRng, HashSet<u32>)>>);

/// An allocated session index that is automatically freed from its [`IndexTable`] on drop.
pub struct Index {
    value: u32,
    table: IndexTable,
}

impl Index {
    /// The raw `u32` index value.
    pub fn value(&self) -> u32 {
        self.value
    }
}

impl Drop for Index {
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

impl IndexTable {
    /// Generate a random `u32` not already in the table.
    ///
    /// The returned [`Index`] keeps the entry reserved; dropping it frees the slot.
    pub fn new_index(&self) -> Index {
        let mut g = self.0.lock().unwrap();
        // Find a free index by guessing. See the rationale here:
        // https://github.com/torvalds/linux/blob/e81dd54f62c753dd423d1a9b62481a1c599fb975/drivers/net/wireguard/peerlookup.c#L95-L117
        // Even if the table contained 2^31 entries, you'd usually only need 1-2 attempts.
        loop {
            let idx = g.0.next_u32();
            if g.1.insert(idx) {
                return Index {
                    value: idx,
                    table: self.clone(),
                };
            }
        }
    }

    /// Create a new [`IndexTable`] using the given seed.
    pub fn from_seed(seed: [u8; 32]) -> Self {
        IndexTable(Arc::new(Mutex::new((
            StdRng::from_seed(seed),
            HashSet::new(),
        ))))
    }

    /// Create a new [`IndexTable`] seeded using [`OsRng`].
    pub fn from_os_rng() -> Self {
        let mut seed = [0u8; 32];
        // `StdRng::from_os_rng` also unwraps, so we can trust that this won't fail
        OsRng.try_fill_bytes(&mut seed).unwrap();
        Self::from_seed(seed)
    }

    /// Remove an index from the table, making it available for reuse.
    fn free_index(&self, index: u32) {
        let mut g = self.0.lock().unwrap();
        g.1.remove(&index);
    }
}
