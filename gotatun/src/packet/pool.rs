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

use bytes::BytesMut;
use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
};

use crate::packet::Packet;

/// A pool of packet buffers.
#[derive(Clone)]
pub struct PacketBufPool<const N: usize = 4096> {
    queue: Arc<Mutex<VecDeque<BytesMut>>>,
    capacity: usize,
}

impl<const N: usize> PacketBufPool<N> {
    /// Create a new [`PacketBufPool`] with space for at least `capacity` packets,
    /// each allocated with a capacity of `N` bytes.
    pub fn new(capacity: usize) -> Self {
        let mut queue = VecDeque::with_capacity(capacity);

        // pre-allocate buffers
        for _ in 0..capacity {
            queue.push_back(BytesMut::zeroed(N).split_to(0));
        }

        PacketBufPool {
            queue: Arc::new(Mutex::new(queue)),
            capacity,
        }
    }

    /// Create an empty [`PacketBufPool`] with space for at least `capacity` returned buffers.
    #[cfg(feature = "device")]
    pub(crate) fn new_lazy(capacity: usize) -> Self {
        Self {
            queue: Arc::new(Mutex::new(VecDeque::with_capacity(capacity))),
            capacity,
        }
    }

    /// Get the configured capacity of this pool.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Try to re-use a [`Packet`] from the pool.
    fn re_use(&self) -> Option<Packet<[u8]>> {
        while let Some(mut pointer_to_start_of_allocation) =
            { self.queue.lock().unwrap().pop_front() }
        {
            debug_assert_eq!(pointer_to_start_of_allocation.len(), 0);
            if pointer_to_start_of_allocation.try_reclaim(N) {
                let mut buf = pointer_to_start_of_allocation.split_off(0);

                debug_assert!(buf.capacity() >= N);

                // SAFETY:
                // - buf was split from the BytesMut allocated below.
                // - buf has not been mutated, and still points to the original allocation.
                // - try_reclaim succeeded, so the capacity is at least `N`.
                // - the allocation was created using `BytesMut::zeroed`, so the bytes are
                //   initialized.
                unsafe { buf.set_len(N) };

                let return_to_pool = ReturnToPool {
                    pointer_to_start_of_allocation: Some(pointer_to_start_of_allocation),
                    queue: self.queue.clone(),
                };

                return Some(Packet::new_from_pool(return_to_pool, buf));
            } else {
                // Backing buffer is still in use. Someone probably called split_* on it.
                continue;
            }
        }

        None
    }

    /// Get a new [`Packet`] from the pool.
    ///
    /// This will try to re-use an already allocated packet if possible, or allocate one otherwise.
    pub fn get(&self) -> Packet<[u8]> {
        if let Some(packet) = self.re_use() {
            return packet;
        }

        let mut buf = BytesMut::zeroed(N);
        let pointer_to_start_of_allocation = buf.split_to(0);

        debug_assert_eq!(pointer_to_start_of_allocation.len(), 0);
        debug_assert_eq!(buf.len(), N);

        let return_to_pool = ReturnToPool {
            pointer_to_start_of_allocation: Some(pointer_to_start_of_allocation),
            queue: self.queue.clone(),
        };

        Packet::new_from_pool(return_to_pool, buf)
    }
}

/// This sends a previously allocated [`BytesMut`] back to [`PacketBufPool`] when its dropped.
pub struct ReturnToPool {
    /// This is a pointer to the allocation allocated by [`PacketBufPool::get`].
    /// By making sure we never modify this (by calling reserve, etc), we can efficiently re-use
    /// this allocation later.
    ///
    /// INVARIANT:
    /// - Points to the start of an `N`-sized allocation.
    // Note: Option is faster than mem::take
    pointer_to_start_of_allocation: Option<BytesMut>,
    queue: Arc<Mutex<VecDeque<BytesMut>>>,
}

impl Drop for ReturnToPool {
    fn drop(&mut self) {
        let p = self.pointer_to_start_of_allocation.take().unwrap();
        let mut queue_g = self.queue.lock().unwrap();
        if queue_g.len() < queue_g.capacity() {
            // Add the packet back to the pool unless we're at capacity
            queue_g.push_back(p);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{hint::black_box, thread};

    #[cfg(feature = "device")]
    use std::sync::{Arc, Barrier};

    use super::PacketBufPool;

    /// Growing a packet's buffer beyond the pool's `N` (e.g. via `extend_from_slice`)
    /// reallocates the data away from the shared allocation. Tests that the pool stays healthy
    /// The original `N`-sized buffer is recycled via the start pointer and the pool keeps
    /// handing out usable buffers.
    #[test]
    fn packet_grow_beyond_capacity() {
        const N: usize = 4096;
        let pool = PacketBufPool::<N>::new(1);

        // Record the address of the pool's single pre-allocated buffer.
        let buffer_ptr = {
            let packet = pool.get();
            let ptr = packet.as_ptr();
            drop(packet);
            ptr
        };

        for _ in 0..10 {
            // The pool must hand back the original N buffer - recycled after the
            // previous iteration grew (and so detached) its data - not a fresh one.
            let mut packet = pool.get();
            assert_eq!(
                packet.as_ptr(),
                buffer_ptr,
                "the original N buffer must be recycled into the pool after a grow"
            );
            assert_eq!(packet.len(), N);

            // Grow well past N; this reallocates the data onto a fresh, larger buffer,
            // detaching it from the pooled allocation.
            packet.buf_mut().clear();
            packet.buf_mut().extend_from_slice(&vec![0x55u8; N * 4]);
            assert_eq!(packet.len(), N * 4);
            assert_ne!(packet.as_ptr(), buffer_ptr, "growing must reallocate");
        }
    }

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

    /// Test demand-driven allocation and recycle semantics of [PacketBufPool].
    #[cfg(feature = "device")]
    #[test]
    fn pool_lazy_allocation_and_recycle() {
        const N: usize = 1024;
        let pool = PacketBufPool::<N>::new_lazy(1);

        assert!(pool.re_use().is_none(), "lazy pool must start empty");

        let packet = pool.get();
        let buffer_ptr = packet.as_ptr();
        assert_eq!(packet.len(), N);
        assert!(packet.iter().all(|byte| *byte == 0));
        drop(packet);

        let recycled = pool.re_use().expect("returned buffer must be retained");
        assert_eq!(recycled.as_ptr(), buffer_ptr);
    }

    /// Test that concurrent allocations do not grow lazy pool retention beyond its capacity.
    #[cfg(feature = "device")]
    #[test]
    fn lazy_pool_retention_is_bounded() {
        const CAPACITY: usize = 4;
        const CONCURRENT_PACKETS: usize = CAPACITY * 2;

        let pool = PacketBufPool::<1024>::new_lazy(CAPACITY);
        let barrier = Arc::new(Barrier::new(CONCURRENT_PACKETS));

        thread::scope(|scope| {
            for _ in 0..CONCURRENT_PACKETS {
                let pool = pool.clone();
                let barrier = Arc::clone(&barrier);
                scope.spawn(move || {
                    let packet = pool.get();
                    barrier.wait();
                    drop(packet);
                });
            }
        });

        assert_eq!(pool.queue.lock().unwrap().len(), CAPACITY);
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
