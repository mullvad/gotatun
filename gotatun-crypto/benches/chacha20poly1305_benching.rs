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
//! Benchmarks the configured GotaTun AEAD backend (`ring` or `aws-lc-rs`,
//! both wrapping a hardware-accelerated C implementation) against the
//! pure-Rust [`chacha20poly1305`] crate on the same workload, to track the
//! gap between our production backend and a portable software fallback.

use aead::{AeadInPlace, KeyInit};
#[cfg(feature = "aws-lc-rs")]
use aws_lc_rs::aead::{Aad, CHACHA20_POLY1305, LessSafeKey, Nonce, UnboundKey};
use criterion::{BenchmarkId, Criterion, Throughput};
use rand::{TryRngCore, rngs::OsRng};
#[cfg(all(feature = "ring", not(feature = "aws-lc-rs")))]
use ring::aead::{Aad, CHACHA20_POLY1305, LessSafeKey, Nonce, UnboundKey};

/// Name of the configured GotaTun AEAD backend, used as the benchmark id.
/// Mirrors the precedence used by the `gotatun::crypto` module.
#[cfg(feature = "aws-lc-rs")]
const BACKEND_NAME: &str = "aws_lc_rs";
#[cfg(all(feature = "ring", not(feature = "aws-lc-rs")))]
const BACKEND_NAME: &str = "ring";

/// Name of the pure-Rust comparison AEAD implementation.
const PURE_RUST_NAME: &str = "chacha20poly1305_crate";

/// Encrypt `buf` in place using the GotaTun-configured AEAD backend
/// (`ring` or `aws-lc-rs`).
fn chacha20poly1305_backend(key_bytes: &[u8], buf: &mut [u8]) {
    let len = buf.len();
    let n = len - 16;

    let key = LessSafeKey::new(UnboundKey::new(&CHACHA20_POLY1305, key_bytes).unwrap());

    let tag = key
        .seal_in_place_separate_tag(
            Nonce::assume_unique_for_key([0u8; 12]),
            Aad::from(&[]),
            &mut buf[..n],
        )
        .unwrap();

    buf[n..].copy_from_slice(tag.as_ref())
}

/// Encrypt `buf` in place using the pure-Rust [`chacha20poly1305`] crate,
/// for side-by-side comparison with the configured backend above.
fn chacha20poly1305_pure_rust(key_bytes: &[u8], buf: &mut [u8]) {
    let len = buf.len();
    let n = len - 16;

    let aead = chacha20poly1305::ChaCha20Poly1305::new_from_slice(key_bytes).unwrap();
    let nonce = chacha20poly1305::Nonce::default();

    let tag = aead
        .encrypt_in_place_detached(&nonce, &[], &mut buf[..n])
        .unwrap();

    buf[n..].copy_from_slice(tag.as_ref());
}

pub fn bench_chacha20poly1305(c: &mut Criterion) {
    let mut group = c.benchmark_group("chacha20poly1305");

    group.sample_size(1000);

    for size in [128, 192, 1400, 8192] {
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(BenchmarkId::new(BACKEND_NAME, size), &size, |b, i| {
            let mut key = [0; 32];
            let mut buf = vec![0; i + 16];

            let mut rng = OsRng;

            rng.try_fill_bytes(&mut key).unwrap();
            rng.try_fill_bytes(&mut buf).unwrap();

            b.iter(|| chacha20poly1305_backend(&key, &mut buf));
        });

        group.bench_with_input(BenchmarkId::new(PURE_RUST_NAME, size), &size, |b, i| {
            let mut key = [0; 32];
            let mut buf = vec![0; i + 16];

            let mut rng = OsRng;

            rng.try_fill_bytes(&mut key).unwrap();
            rng.try_fill_bytes(&mut buf).unwrap();

            b.iter(|| chacha20poly1305_pure_rust(&key, &mut buf));
        });
    }

    group.finish();
}
