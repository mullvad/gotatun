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
    },
    udp::UdpSocketFactory,
};
use criterion::Criterion;
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
        .with_max_level(LevelFilter::TRACE)
        .init();

    let runtime = runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    let (api_client_a, api_server_a) = ApiServer::new();
    let (api_client_b, api_server_b) = ApiServer::new();

    let a_tun_rx = MockIpRecv::new();
    let a_tun_tx = NullIpSend {};

    let b_tun_rx = NullIpRecv {};
    let mut b_tun_tx = MockIpSend::new();

    let device_a = runtime.block_on(
        DeviceHandle::<(UdpSocketFactory, NullIpSend, MockIpRecv)>::new(
            UdpSocketFactory,
            a_tun_tx,
            a_tun_rx,
            DeviceConfig {
                api: Some(api_server_a),
            },
        ),
    );

    let device_b = runtime.block_on(
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

    let peer_a = SetPeer::new(public_key_a.to_bytes());
    api_client_b
        .send_sync(
            Set::builder()
                .listen_port(endpoint_b.port())
                .private_key(private_key_b.to_bytes())
                .build()
                .peer(peer_a),
        )
        .expect("configure device B");

    let peer_b = SetPeer::new(public_key_b.to_bytes()).with_endpoint(endpoint_b);
    api_client_a
        .send_sync(
            Set::builder()
                .listen_port(endpoint_a.port())
                .private_key(private_key_a.to_bytes())
                .build()
                .peer(peer_b),
        )
        .expect("configure device A");

    c.bench_function("throughput", |b| {
        b.iter(|| {
            // receive 100 packets
            runtime.block_on(async {
                if timeout(Duration::from_secs(6000), b_tun_tx.wait_for(100))
                    .await
                    .is_err()
                {
                    panic!("no data is being received, something is wrong!");
                }
            })
        });
        // TODO:
    });

    runtime.block_on(async move {
        device_a.stop().await;
        device_b.stop().await;
    });
}
