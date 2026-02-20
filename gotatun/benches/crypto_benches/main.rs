use blake2s_benching::{bench_blake2s_hash, bench_blake2s_hmac, bench_blake2s_keyed};

mod blake2s_benching;

criterion::criterion_group!(
    crypto_benches,
    bench_blake2s_hash,
    bench_blake2s_hmac,
    bench_blake2s_keyed,
);
criterion::criterion_main!(crypto_benches);
