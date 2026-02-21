// Copyright (c) 2025 Mullvad VPN AB. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use criterion::{criterion_group, criterion_main};

mod fragmentation;
mod pool;

criterion_group!(
    benches,
    fragmentation::bench_assemble_ipv4_fragment,
    fragmentation::bench_assemble_ipv4_fragment_reverse_order,
    fragmentation::bench_assemble_ipv4_fragment_interleaved,
    pool::bench_pool,
    pool::bench_pool_reordered,
    pool::bench_pool_multithreaded,
    pool::bench_pool_write,
    pool::bench_pool_cold,
);
criterion_main!(benches);
