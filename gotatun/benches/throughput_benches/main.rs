// Copyright (c) 2025 Mullvad VPN AB. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use bytes::BytesMut;
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use gotatun::packet::{IpNextProtocol, Ipv4, Ipv4Header, Packet};
use gotatun::tun::channel::Ipv4Fragments;
use rand::rngs::StdRng;
use rand::{SeedableRng, seq::SliceRandom};
use std::hint::black_box;
use std::net::Ipv4Addr;
use std::sync::{Arc, Barrier};
use std::time::{Duration, Instant};
use zerocopy::FromBytes;

fn bench_pool(c: &mut Criterion) {
    const CAPACITY: usize = 4000;
    let pool = gotatun::packet::PacketBufPool::<4096>::new(CAPACITY);

    // Parameterized by how many packets are held alive simultaneously.
    // Each batch acquires `num_concurrent` packets into a Vec (keeping them all live),
    // then drops them all together at the end of the batch. This prevents the pool from
    // reusing the same buffer slot on every iteration and exercises real concurrent holds.
    let mut group = c.benchmark_group("pool_concurrent");
    for &num_concurrent in &[1, 10, 100, 1000] {
        group.throughput(criterion::Throughput::Elements(CAPACITY as u64));
        group.bench_function(BenchmarkId::from_parameter(num_concurrent), |b| {
            let mut packets = Vec::with_capacity(num_concurrent);
            b.iter(|| {
                for _ in 0..(CAPACITY / num_concurrent) {
                    // Hold `num_concurrent` packets simultaneously so the pool can't
                    // reuse any of them until the whole batch is dropped at once.
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

fn bench_pool_reordered(c: &mut Criterion) {
    const CAPACITY: usize = 4000;
    let pool = gotatun::packet::PacketBufPool::<4096>::new(CAPACITY);

    // Same as pool_concurrent, but packets within each batch are dropped in a pre-shuffled
    // order rather than all at once. This models real usage where buffers are returned to
    // the pool out of acquisition order (e.g. packets processed or forwarded at different
    // rates). The drop order is fixed (same seed) so results are reproducible.
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
fn bench_pool_multithreaded(c: &mut Criterion) {
    const CAPACITY: usize = 4000;

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
fn bench_pool_write(c: &mut Criterion) {
    const CAPACITY: usize = 4000;
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
fn bench_pool_cold(c: &mut Criterion) {
    const CAPACITY: usize = 4000;
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

fn fragment_ipv4_packet(identification: u16, payload: &[u8], mtu: usize) -> Vec<Packet<Ipv4>> {
    let ipv4_header_len = 20;
    let max_payload_per_fragment = ((mtu - ipv4_header_len) / 8) * 8; // must be multiple of 8
    let payload_chunks = payload.chunks_exact(max_payload_per_fragment);
    let last_payload = payload_chunks.remainder();
    assert!(!last_payload.is_empty());
    let last_fragment = make_single_fragment(
        identification,
        ((payload.len() - last_payload.len()) / 8) as u16,
        false,
        last_payload,
    );
    payload_chunks
        .zip(0..)
        .map(|(payload, i)| {
            make_single_fragment(
                identification,
                (i * max_payload_per_fragment / 8) as u16,
                true,
                payload,
            )
        })
        .chain(std::iter::once(last_fragment))
        .collect()
}

fn make_single_fragment(
    identification: u16,
    offset: u16,
    more_fragments: bool,
    payload: &[u8],
) -> Packet<Ipv4> {
    let mut buf = BytesMut::zeroed(Ipv4Header::LEN + payload.len()); // TODO: Use PacketBufPool?
    let ipv4 = Ipv4::<[u8]>::mut_from_bytes(&mut buf).unwrap();
    let source_ip = Ipv4Addr::new(10, 0, 0, 1);
    let destination_ip = Ipv4Addr::new(10, 0, 0, 2);
    ipv4.header = Ipv4Header::new(source_ip, destination_ip, IpNextProtocol::Udp, payload);
    ipv4.header.identification = identification.into();
    let mut flags = gotatun::packet::Ipv4FlagsFragmentOffset::new();
    flags.set_more_fragments(more_fragments);
    flags.set_fragment_offset(offset);
    ipv4.header.flags_and_fragment_offset = flags;
    ipv4.payload.copy_from_slice(payload);

    Packet::from_bytes(buf)
        .try_into_ipvx()
        .unwrap()
        .unwrap_left()
}

fn bench_assemble_ipv4_fragment(c: &mut Criterion) {
    let mut fragments = Ipv4Fragments::default();

    let id = 42;
    let mtu = 1500;
    let mut group = c.benchmark_group("assemble_ipv4_fragment");
    for &payload_len in &[2000, 4000, 10000] {
        let payload = vec![0u8; payload_len];
        let frags = fragment_ipv4_packet(id, &payload, mtu);
        group.throughput(criterion::Throughput::Bytes(payload_len as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(payload_len),
            &frags,
            |b, frags| {
                b.iter(|| {
                    for frag in frags {
                        black_box(
                            fragments.assemble_ipv4_fragment(black_box(Packet::copy_from(frag))),
                        );
                    }
                    assert_eq!(fragments.incomplete_packet_count(), 0);
                })
            },
        );
    }
    group.finish();
}

fn bench_assemble_ipv4_fragment_reverse_order(c: &mut Criterion) {
    let mut fragments = Ipv4Fragments::default();

    let id = 42;
    let mtu = 1500;
    let mut group = c.benchmark_group("assemble_ipv4_fragment_reverse_order");
    for &payload_len in &[2000, 4000, 10000] {
        let payload = vec![0u8; payload_len];
        let mut frags = fragment_ipv4_packet(id, &payload, mtu);
        frags.reverse();
        group.throughput(criterion::Throughput::Bytes(payload_len as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(payload_len),
            &frags,
            |b, frags| {
                b.iter(|| {
                    for frag in frags {
                        black_box(
                            fragments.assemble_ipv4_fragment(black_box(Packet::copy_from(frag))),
                        );
                    }
                    assert_eq!(fragments.incomplete_packet_count(), 0);
                })
            },
        );
    }
    group.finish();
}

fn bench_assemble_ipv4_fragment_interleaved(c: &mut Criterion) {
    let mut fragments = Ipv4Fragments::default();

    let mtu = 1500;
    let mut group = c.benchmark_group("assemble_ipv4_fragment_interleaved");
    for (n_packets, payload_len) in [(4, 10000), (16, 4000), (64, 2000)] {
        group.throughput(criterion::Throughput::Bytes(
            (n_packets * payload_len) as u64,
        ));
        let mut all_frags = Vec::new();
        for i in 0..n_packets {
            let id = 1000 + i as u16;
            let payload = vec![i as u8; payload_len];
            let mut frags = fragment_ipv4_packet(id, &payload, mtu);
            all_frags.append(&mut frags);
        }
        // Shuffle with a fixed seed for reproducibility
        let mut rng = StdRng::seed_from_u64(42);
        all_frags.shuffle(&mut rng);
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{n_packets}x{payload_len}")),
            &all_frags,
            |b, all_frags| {
                b.iter(|| {
                    for frag in all_frags {
                        black_box(
                            fragments.assemble_ipv4_fragment(black_box(Packet::copy_from(frag))),
                        );
                    }
                    assert_eq!(fragments.incomplete_packet_count(), 0);
                })
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_assemble_ipv4_fragment,
    bench_assemble_ipv4_fragment_reverse_order,
    bench_assemble_ipv4_fragment_interleaved,
    bench_pool,
    bench_pool_reordered,
    bench_pool_multithreaded,
    bench_pool_write,
    bench_pool_cold
);
criterion_main!(benches);
