use std::{
    net::{Ipv4Addr, SocketAddr},
    time::Duration,
};

use boringtun::{
    device::{
        DeviceConfig, DeviceHandle,
        api::{
            ApiServer,
            command::{Set, SetPeer},
        },
        peer::AllowedIP,
    },
    udp::UdpSocketFactory,
};
use criterion::{BenchmarkId, Criterion};
use mock_ip::{MockIpRecv, MockIpSend, NullIpRecv, NullIpSend};
use tokio::{runtime, time::timeout};
use tracing::level_filters::LevelFilter;
use x25519_dalek::{PublicKey, StaticSecret};

mod mock_ip;

criterion::criterion_group!(throughput_benches, throughput);
criterion::criterion_main!(throughput_benches);

pub fn throughput(c: &mut Criterion) {
    //console_subscriber::init();
    tracing_subscriber::fmt()
        .pretty()
        .with_max_level(LevelFilter::ERROR)
        .init();

    let mut group = c.benchmark_group("packet_throughput");
    for packet_batch_size in [1, 16, 64, 256, 1024, 8192] {
        for payload_size in [10, 1000] {
            group.throughput(criterion::Throughput::Bytes(
                (packet_batch_size * payload_size) as u64,
            ));

            group.sampling_mode(criterion::SamplingMode::Flat);

            let runtime = runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .unwrap();

            let (api_client_a, api_server_a) = ApiServer::new();
            let (api_client_b, api_server_b) = ApiServer::new();

            let a_tun_rx = MockIpRecv::new(payload_size);
            let a_tun_tx = NullIpSend {};

            let b_tun_rx = NullIpRecv {};
            let mut b_tun_tx = MockIpSend::new();

            let device_a =
                runtime.block_on(
                    DeviceHandle::<(UdpSocketFactory, NullIpSend, MockIpRecv)>::new(
                        UdpSocketFactory,
                        a_tun_tx,
                        a_tun_rx.clone(),
                        DeviceConfig {
                            api: Some(api_server_a),
                        },
                    ),
                );

            let device_b =
                runtime.block_on(
                    DeviceHandle::<(UdpSocketFactory, MockIpSend, NullIpRecv)>::new(
                        UdpSocketFactory,
                        b_tun_tx.clone(),
                        b_tun_rx,
                        DeviceConfig {
                            api: Some(api_server_b),
                        },
                    ),
                );

            let private_key_a = StaticSecret::random();
            let private_key_b = StaticSecret::random();
            let public_key_a = PublicKey::from(&private_key_a);
            let public_key_b = PublicKey::from(&private_key_b);

            let endpoint_a = SocketAddr::from((Ipv4Addr::LOCALHOST, 53001));
            let endpoint_b = SocketAddr::from((Ipv4Addr::LOCALHOST, 53002));

            let mut peer_a = SetPeer::new(public_key_a.to_bytes());
            peer_a.peer.allowed_ip = vec![AllowedIP {
                addr: Ipv4Addr::UNSPECIFIED.into(),
                cidr: 0,
            }];
            api_client_b
                .send_sync(
                    Set::builder()
                        .listen_port(endpoint_b.port())
                        .private_key(private_key_b.to_bytes())
                        .build()
                        .peer(peer_a),
                )
                .expect("configure device B");

            let mut peer_b = SetPeer::new(public_key_b.to_bytes()).with_endpoint(endpoint_b);
            peer_b.peer.allowed_ip = vec![AllowedIP {
                addr: Ipv4Addr::UNSPECIFIED.into(),
                cidr: 0,
            }];
            api_client_a
                .send_sync(
                    Set::builder()
                        .listen_port(endpoint_a.port())
                        .private_key(private_key_a.to_bytes())
                        .build()
                        .peer(peer_b),
                )
                .expect("configure device A");

            runtime.block_on(async {
                a_tun_rx.add_packets(1);
                b_tun_tx.wait_for(1).await;
            });

            group.bench_with_input(
                BenchmarkId::new(
                    "packet_throughput_foo",
                    format!("{packet_batch_size}x{payload_size}"),
                ),
                &packet_batch_size,
                |b, &packet_batch_size| {
                    b.iter(|| {
                        runtime.block_on(async {
                            a_tun_rx.add_packets(packet_batch_size);
                            if timeout(
                                Duration::from_secs(60),
                                b_tun_tx.wait_for(packet_batch_size),
                            )
                            .await
                            .is_err()
                            {
                                panic!("no data is being received, something is wrong!");
                            }
                        })
                    });
                },
            );

            runtime.block_on(async move {
                device_a.stop().await;
                device_b.stop().await;
            });
        }
    }
}
