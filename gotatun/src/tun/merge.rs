// Copyright (c) 2025 Mullvad VPN AB. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Merges two [`IpRecv`] sources into one.
//!
//! See [`MergingIpRecv`].

use std::io;

use either::Either;

use crate::packet::{Ip, Packet, PacketBufPool};
use crate::tun::{IpRecv, MtuWatcher};

/// Merges packets from two [`IpRecv`] sources using [`tokio::select!`].
///
/// The first source's MTU is used as the merged MTU.
pub struct MergingIpRecv<A: IpRecv, B: IpRecv> {
    a: A,
    b: B,
    pool: PacketBufPool,
}

impl<A: IpRecv, B: IpRecv> MergingIpRecv<A, B> {
    /// Create a new `MergingIpRecv` that merges packets from `a` and `b`.
    ///
    /// `pool` is used as the packet buffer pool when receiving from `b`.
    pub fn new(a: A, b: B, pool: PacketBufPool) -> Self {
        Self { a, b, pool }
    }
}

impl<A: IpRecv, B: IpRecv> IpRecv for MergingIpRecv<A, B> {
    async fn recv<'a>(
        &'a mut self,
        pool: &mut PacketBufPool,
    ) -> io::Result<impl Iterator<Item = Packet<Ip>> + Send + 'a> {
        // Destructure to help the borrow checker see disjoint field borrows.
        let Self { a, b, pool: pool_b } = self;
        tokio::select! {
            result = a.recv(pool) => result.map(Either::Left),
            result = b.recv(pool_b) => result.map(Either::Right),
        }
    }

    fn mtu(&self) -> MtuWatcher {
        // TODO
        self.a.mtu()
    }
}
