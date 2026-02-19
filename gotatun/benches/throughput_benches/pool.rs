// Copyright (c) 2025 Mullvad VPN AB. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use criterion::{BenchmarkId, Criterion};
use rand::rngs::StdRng;
use rand::{SeedableRng, seq::SliceRandom};
use std::hint::black_box;
use std::sync::{Arc, Barrier};
use std::time::{Duration, Instant};

const CAPACITY: usize = 4000;

/// Benchmark concurrent holds: acquire `num_concurrent` packets at a time, keeping them all
/// live simultaneously, then drop them together. This prevents the pool from reusing the same
/// buffer slot on every iteration and exercises real concurrent holds.
pub fn bench_pool(c: &mut Criterion) {
    let pool = gotatun::packet::PacketBufPool::<4096>::new(CAPACITY);

    let mut group = c.benchmark_group("pool_concurrent");
    for &num_concurrent in &[1, 10, 100, 1000] {
        group.throughput(criterion::Throughput::Elements(CAPACITY as u64));
        group.bench_function(BenchmarkId::from_parameter(num_concurrent), |b| {
            let mut packets = Vec::with_capacity(num_concurrent);
            b.iter(|| {
                for _ in 0..(CAPACITY / num_concurrent) {
                    packets.extend((0..num_concurrent).map(|_| pool.get()));
                    // drain drops all packets (returning them to the pool) and resets len to 0,
                    // leaving the Vec's allocation intact for the next batch.
                    black_box(packets.drain(..));
                }
            })
        });
    }
    group.finish();
}

/// Same as `bench_pool`, but packets within each batch are dropped in a pre-shuffled order
/// rather than all at once. This models real usage where buffers are returned to the pool out
/// of acquisition order (e.g. packets processed or forwarded at different rates).
/// The drop order is fixed (same seed) so results are reproducible.
pub fn bench_pool_reordered(c: &mut Criterion) {
    let pool = gotatun::packet::PacketBufPool::<4096>::new(CAPACITY);

    let mut group = c.benchmark_group("pool_reordered");
    for &num_concurrent in &[1, 10, 100, 1000] {
        group.throughput(criterion::Throughput::Elements(CAPACITY as u64));

        // Pre-compute the shuffled drop order outside b.iter() so the RNG cost
        // is not included in the measurement.
        let mut rng = StdRng::seed_from_u64(42);
        let mut shuffled_indices: Vec<usize> = (0..num_concurrent).collect();
        shuffled_indices.shuffle(&mut rng);

        group.bench_function(BenchmarkId::from_parameter(num_concurrent), |b| {
            let mut packets = Vec::with_capacity(num_concurrent);
            b.iter(|| {
                for _ in 0..(CAPACITY / num_concurrent) {
                    // Wrap each packet in Option so we can drop them individually
                    // via take() rather than all at once when the Vec is dropped.
                    packets.extend((0..num_concurrent).map(|_| Some(pool.get())));
                    for &i in &shuffled_indices {
                        black_box(packets[i].take());
                    }
                    // All slots are already None; clear() just resets len to 0
                    // without any drop cost, leaving the allocation intact.
                    packets.clear();
                }
            })
        });
    }
    group.finish();
}

/// Benchmark the pool when multiple OS threads concurrently get and return packets.
/// This exercises Mutex contention on the shared VecDeque, matching production usage
/// where handle_incoming (x2), handle_outgoing, and DAITA all share the same pool.
pub fn bench_pool_multithreaded(c: &mut Criterion) {
    let mut group = c.benchmark_group("pool_multithreaded");
    for &num_threads in &[2, 4, 8] {
        let pool = gotatun::packet::PacketBufPool::<4096>::new(CAPACITY);
        let per_thread = CAPACITY / num_threads;
        group.throughput(criterion::Throughput::Elements(CAPACITY as u64));
        group.bench_function(BenchmarkId::from_parameter(num_threads), |b| {
            b.iter_custom(|iters| {
                // Pre-spawn threads so thread creation isn't included in the measurement.
                // Two barriers synchronize each iteration: the main thread releases all
                // workers at once and then waits for them all to finish.
                let start_barrier = Arc::new(Barrier::new(num_threads + 1));
                let end_barrier = Arc::new(Barrier::new(num_threads + 1));

                let handles: Vec<_> = (0..num_threads)
                    .map(|_| {
                        let pool = pool.clone();
                        let start = start_barrier.clone();
                        let end = end_barrier.clone();
                        std::thread::spawn(move || {
                            let mut packets = Vec::with_capacity(per_thread);
                            for _ in 0..iters {
                                start.wait();
                                packets.extend((0..per_thread).map(|_| pool.get()));
                                black_box(packets.drain(..));
                                end.wait();
                            }
                        })
                    })
                    .collect();

                let mut total = Duration::ZERO;
                for _ in 0..iters {
                    start_barrier.wait(); // release all workers simultaneously
                    let t = Instant::now();
                    end_barrier.wait(); // wait until all workers have finished
                    total += t.elapsed();
                }

                for h in handles {
                    h.join().unwrap();
                }
                total
            })
        });
    }
    group.finish();
}

/// Benchmark the full get-write-drop cycle, modelling the UDP/TUN recv path:
///   pool.get() → copy payload into buffer → truncate → drop
/// Parameterised by packet size to show how write cost scales and whether the
/// pool's pre-warmed allocation reduces page-fault overhead vs a cold BytesMut.
pub fn bench_pool_write(c: &mut Criterion) {
    let pool = gotatun::packet::PacketBufPool::<4096>::new(CAPACITY);

    let mut group = c.benchmark_group("pool_write");
    for &packet_size in &[64usize, 512, 1500, 4096] {
        let data = vec![0u8; packet_size];
        group.throughput(criterion::Throughput::Bytes(
            (CAPACITY * packet_size) as u64,
        ));
        group.bench_function(BenchmarkId::from_parameter(packet_size), |b| {
            let mut packets = Vec::with_capacity(CAPACITY);
            b.iter(|| {
                for _ in 0..CAPACITY {
                    let mut pkt = pool.get();
                    // Simulate writing received network data into the pre-allocated buffer.
                    pkt[..packet_size].copy_from_slice(&data);
                    pkt.truncate(packet_size);
                    packets.push(pkt);
                }
                black_box(packets.drain(..));
            })
        });
    }
    group.finish();
}

/// Benchmark pool.get() when the pool is always empty (capacity = 0).
/// ReturnToPool::drop checks `queue.len() < queue.capacity()`, which is `0 < 0`
/// when the VecDeque was created with capacity 0, so buffers are never re-enqueued.
/// Every call therefore falls through to a fresh BytesMut::zeroed allocation,
/// giving a cost baseline to compare against the warm-pool benchmarks.
pub fn bench_pool_cold(c: &mut Criterion) {
    let pool = gotatun::packet::PacketBufPool::<4096>::new(0);

    let mut group = c.benchmark_group("pool_cold");
    group.throughput(criterion::Throughput::Elements(CAPACITY as u64));
    group.bench_function("always_allocate", |b| {
        let mut packets = Vec::with_capacity(CAPACITY);
        b.iter(|| {
            packets.extend((0..CAPACITY).map(|_| pool.get()));
            black_box(packets.drain(..));
        })
    });
    group.finish();
}
