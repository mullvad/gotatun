// Copyright (c) 2025 Mullvad VPN AB. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use bytes::BytesMut;

use crate::packet::Packet;

/// Used to send a previously allocated [`BytesMut`] back to [`PacketBufPool`] when its dropped.
pub type ReturnToPool = crossbeam_channel::Sender<BytesMut>;
type GetFromPool = crossbeam_channel::Receiver<BytesMut>;

/// A pool of packet buffers.
#[derive(Clone)]
pub struct PacketBufPool<const N: usize = 4096> {
    rx: GetFromPool,
    _tx: ReturnToPool,
}

impl<const N: usize> PacketBufPool<N> {
    /// Create a new [`PacketBufPool`] with space for at least `capacity` packets,
    /// each allocated with a capacity of `N` bytes.
    pub fn new(capacity: usize) -> Self {
        let (_tx, rx) = crossbeam_channel::bounded(capacity);

        //let mut contiguous_buf = BytesMut::zeroed(N * capacity);
        // pre-allocate buffers
        for _ in 0..capacity {
            //_tx.send(contiguous_buf.split_to(N))
            _tx.send(BytesMut::zeroed(N))
                .expect("chan has space for 'capacity' bufs");
        }
        //debug_assert!(contiguous_buf.is_empty());

        PacketBufPool { rx, _tx }
    }

    /// Get the configured capacity of this pool.
    pub fn capacity(&self) -> usize {
        self.rx.capacity().expect("channel is bounded")
    }

    /// Try to re-use a [`Packet`] from the pool.
    fn re_use(&self) -> Option<Packet<[u8]>> {
        let mut buf = self.rx.try_recv().ok()?;
        //debug_assert!(buf.capacity() == N);
        //assert!(buf.capacity() == N);
        buf.resize(N, 0);
        //unsafe { buf.set_len(N) };

        Some(Packet::new_from_pool(self._tx.clone(), buf))
    }

    /// Get a new [`Packet`] from the pool.
    ///
    /// This will try to re-use an already allocated packet if possible.
    /// If the pool is empty, a new packet will be allocated. This packet
    /// will not be returned to the pool when dropped.
    pub fn get(&self) -> Packet<[u8]> {
        if let Some(packet) = self.re_use() {
            return packet;
        }

        log::trace!("Pool is empty, allocating new packet");
        Packet::from_bytes(BytesMut::zeroed(N))
    }
}

#[cfg(test)]
mod tests {
    use std::{hint::black_box, thread};

    use super::PacketBufPool;

    /// Test pre-allocation semantics of [PacketBufPool].
    #[test]
    fn pool_prealloc() {
        const N: usize = 1024;
        let buffer_count = 10;
        let pool = PacketBufPool::<N>::new(10);

        let mut packets = vec![];

        for _ in 0..buffer_count {
            let packet = pool.re_use().expect("10 buffers was pre-allocated");
            assert_eq!(packet.buf().len(), N);
            packets.push(packet); // save packets so they don't get re-used
        }

        assert!(
            pool.re_use().is_none(),
            "pool is empty and a new packet must be allocated"
        );
    }

    /// Test buffer recycle semantics of [PacketBufPool].
    #[test]
    fn pool_buffer_recycle() {
        let pool = PacketBufPool::<4096>::new(1);

        for i in 0..10 {
            // Get a packet and record its address.
            let mut packet1 = black_box(pool.get());
            let packet1_addr = packet1.buf().as_ptr();

            // Mutate the packet for good measure
            let data = format!("Hello there. x{i}\nGeneral Kenobi! You are a bold one.");
            let data = data.as_bytes();
            packet1.truncate(data.len());
            packet1.copy_from_slice(data);

            // Drop the packet, allowing it to be re-used.
            // Do it on another thread for good measure.
            thread::spawn(move || drop(packet1)).join().unwrap();

            // Get another packet. This should be the same as packet1.
            let packet2 = black_box(pool.get());
            let packet2_addr = packet2.buf().as_ptr();

            // Get a third packet.
            // Since we're still holding packet2, this will result in an allocation.
            let packet3 = black_box(pool.get());
            let packet3_addr = packet3.buf().as_ptr();

            assert!(
                packet2.starts_with(data),
                "old data should remain in the recycled buffer",
            );

            assert!(
                !packet3.starts_with(data),
                "old data should not exist in the new buffer",
            );

            assert_eq!(packet1_addr, packet2_addr);
            assert_ne!(packet1_addr, packet3_addr);

            drop((packet2, packet3));
        }
    }
}
