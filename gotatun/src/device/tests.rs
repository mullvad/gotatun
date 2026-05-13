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

use std::net::{Ipv4Addr, Ipv6Addr};
use std::{future::ready, time::Duration};

use futures::{StreamExt, future::pending};
use mock::MockEavesdropper;
use rand::{SeedableRng, rngs::StdRng};
use tokio::{join, select, time::sleep};
use zerocopy::IntoBytes;

use ipnetwork::{IpNetwork, Ipv4Network};
use tokio::sync::mpsc;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::device::{DeviceBuilder, Peer};
use crate::packet::PacketBufPool;
use crate::tun::{
    IpRecv, IpSend,
    nat::{NatIpRecv, NatIpSend},
    router::{TunRxRouter, TunTxRouter},
};
use crate::udp::channel::{UdpChannelFactory, UdpChannelV4, UdpChannelV6};

use crate::noise::index_table::IndexTable;

pub mod mock;

/// Assert that the expected number of packets is sent.
/// We expect there to be [`packet_count`] data packets, one handshake init,
/// one handshake resp, and one keepalive.
#[tokio::test]
#[test_log::test]
async fn number_of_packets() {
    test_device_pair(async |eve| {
        let expected_count = packet_count() + 2 + 1;
        let ipv4_count = eve.ipv4().count().await;
        assert_eq!(ipv4_count, expected_count);
    })
    .await
}

/// Assert that IPv6 is not used.
#[tokio::test]
#[test_log::test]
async fn ipv6_isnt_used() {
    test_device_pair(async |eve| {
        let ipv6_count = eve.ipv6().count().await;
        assert_eq!(dbg!(ipv6_count), 0);
    })
    .await
}

/// Assert that exactly one handshake is performed.
/// This test does not run for long enough to trigger a second handshake.
#[tokio::test]
#[test_log::test]
async fn one_handshake() {
    test_device_pair(async |eve| {
        let handshake_inits = async {
            assert_eq!(eve.wg_handshake_init().count().await, 1);
        };
        let handshake_resps = async {
            assert_eq!(eve.wg_handshake_resp().count().await, 1);
        };
        join! { handshake_inits, handshake_resps };
    })
    .await
}

// TODO: is this according to spec?
/// Assert that exactly one keepalive is sent.
/// The keepalive should be sent after the handshake is completed.
#[tokio::test]
#[test_log::test]
async fn one_keepalive() {
    test_device_pair(async |eve| {
        let keepalive_count = eve
            .wg_data()
            .filter(|wg_data| ready(wg_data.is_keepalive()))
            .count()
            .await;

        assert_eq!(keepalive_count, 1);
    })
    .await
}

/// Assert that all WgData packets lenghts are a multiple of 16.
#[tokio::test]
#[test_log::test]
async fn wg_data_length_is_x16() {
    test_device_pair(async |eve| {
        let wg_data_count = eve
            .wg_data()
            .map(|wg| {
                let payload_len = wg.encrypted_encapsulated_packet().len();
                assert!(
                    payload_len.is_multiple_of(16),
                    "wireguard data length must be a multiple of 16, but was {payload_len}"
                );
            })
            .count()
            .await;

        assert!(dbg!(wg_data_count) >= packet_count());
    })
    .await
}

/// Test that indices work as expected.
#[tokio::test]
#[test_log::test]
async fn test_indices() {
    // Compute the expected first index from each seeded RNG.
    let expected_alice_idx =
        IndexTable::next_id(&mut StdRng::seed_from_u64(mock::ALICE_INDEX_SEED));
    let expected_bob_idx = IndexTable::next_id(&mut StdRng::seed_from_u64(mock::BOB_INDEX_SEED));

    test_device_pair(async |eve| {
        let check_init = eve.wg_handshake_init().for_each(async |p| {
            assert_eq!(p.sender_idx.get(), expected_alice_idx);
        });
        let check_alice_data = eve.wg_data().for_each(async |p| {
            // Every data packet is sent to Bob
            assert_eq!(p.header.receiver_idx, expected_bob_idx);
        });
        let check_resp = eve.wg_handshake_resp().for_each(async |p| {
            assert_eq!(p.sender_idx.get(), expected_bob_idx);
        });
        join!(check_init, check_resp, check_alice_data);
    })
    .await;
}

/// Test that device handles roaming (changes to endpoint) for data packets.
#[tokio::test]
#[test_log::test]
async fn test_endpoint_roaming() {
    let (mut alice, mut bob, eve) = mock::device_pair().await;
    let packet = mock::packet(b"Hello!");

    let mut ping_pong = async |alice_ip| {
        *alice.source_ipv4_override.lock().await = Some(alice_ip);

        alice.app_tx.send(packet.clone()).await;
        assert_eq!(bob.app_rx.recv().await.as_bytes(), packet.as_bytes());

        let peers = bob.device.peers().await;
        assert_eq!(peers.len(), 1);
        let stats = &peers[0];

        // Bob's device's peer should point to Alice's last known endpoint
        assert_eq!(
            stats.peer.endpoint.map(|addr| addr.ip()),
            Some(alice_ip.into()),
        );

        // Bob's sent packets should use the new endpoint
        let ip_stream = eve.ip();
        tokio::pin!(ip_stream);

        let next_packet = async {
            tokio::time::timeout(Duration::from_secs(5), ip_stream.next())
                .await
                .expect("did not see sent packet")
        };

        let (_, sniffed_packet) = join! {
            bob.app_tx.send(packet.clone()),
            next_packet,
        };
        alice.app_rx.recv().await;

        assert_eq!(
            sniffed_packet.and_then(|ip| ip.destination()),
            Some(alice_ip.into())
        );
    };

    // Simulate roaming by changing Alice's source IP
    ping_pong("1.2.3.4".parse().unwrap()).await;
    ping_pong("1.3.3.7".parse().unwrap()).await;
    ping_pong("1.2.3.4".parse().unwrap()).await;
}

/// Test that [`TunRxRouter`] routes packets to alt or default receiver
/// based on whether their destination IP matches the configured network.
#[tokio::test]
#[test_log::test]
async fn test_tun_router() {
    let (source, app_tx, _app_rx) = mock::mock_tun();
    let inner_allowed_ip: IpNetwork = "10.100.0.0/24".parse().unwrap();

    let mut router = TunRxRouter::new(source);
    let mut default_recv = router.add_default_route(10);
    let mut alt_recv = router.add_route(inner_allowed_ip, 10);

    let mut pool = PacketBufPool::new(10);

    tokio::spawn(router.run(pool.clone()));

    let src: Ipv4Addr = "10.64.0.2".parse().unwrap();
    let inner_dst: Ipv4Addr = "10.100.0.1".parse().unwrap();
    let other_dst: Ipv4Addr = "8.8.8.8".parse().unwrap();

    // Packet destined for inner allowed IP -> alt_recv
    app_tx
        .send(mock::packet_with_addrs(src, inner_dst, b"hello inner"))
        .await;
    let received = alt_recv.recv(&mut pool).await.unwrap().next().unwrap();
    assert_eq!(received.destination(), Some(inner_dst.into()));
    assert_eq!(received.payload(), Some(b"hello inner".as_slice()));

    // Packet destined for other IP -> default_recv
    app_tx
        .send(mock::packet_with_addrs(src, other_dst, b"hello default"))
        .await;
    let received = default_recv.recv(&mut pool).await.unwrap().next().unwrap();
    assert_eq!(received.destination(), Some(other_dst.into()));
    assert_eq!(received.payload(), Some(b"hello default".as_slice()));
}

/// Demonstrate that a malicious outer-tunnel peer can spoof packets that
/// *appear* to come from inside the inner tunnel — and that wiring
/// [`TunTxRouter`] with `inner_allowed_ips` blocks the spoof.
///
/// Scenario: the outer WG decapsulates a packet whose source IP is inside the
/// inner tunnel's allowed-IP range, but whose UDP source-socket does *not*
/// match the inner WG endpoint. Pre-fix, the [`TunTxRouter`] would route this
/// straight to the local TUN - letting the outer peer impersonate any host
/// behind the inner tunnel. With the fix, it is dropped.
#[tokio::test]
#[test_log::test]
async fn tun_tx_router_blocks_spoofed_inner_source() {
    use std::net::SocketAddr;

    use crate::packet::{Ip, Packet};
    use ipnetwork::IpNetwork;

    // A tiny `IpSend` that records every packet it receives.
    #[derive(Clone)]
    struct RecordingIpSend(mpsc::Sender<Packet<Ip>>);
    impl IpSend for RecordingIpSend {
        async fn send(&mut self, packet: Packet<Ip>) -> std::io::Result<()> {
            self.0.send(packet).await.unwrap();
            Ok(())
        }
    }

    let inner_allowed: IpNetwork = "10.100.0.0/24".parse().unwrap();
    let inner_tun_endpoint: SocketAddr = "203.0.113.1:51820".parse().unwrap();

    // The forged packet: src is *inside* the inner allowed range. Legitimately,
    // a packet with this src can only reach the local stack via the inner WG
    // device (which decrypts it, then NATs the dest). If it shows up at the
    // outer device's IpSend, the outer peer must have minted it.
    let forged_src: Ipv4Addr = "10.100.0.5".parse().unwrap();
    let local_dst: Ipv4Addr = "10.0.0.1".parse().unwrap();
    let forged = || mock::packet_with_addrs(forged_src, local_dst, b"spoofed reply");

    // --- Without the filter: the hijack works. ---
    {
        let (inner_tx, mut inner_rx) = mpsc::channel(8);
        let (outer_tx, mut outer_rx) = mpsc::channel(8);
        let mut router = TunTxRouter::new(
            RecordingIpSend(inner_tx),
            RecordingIpSend(outer_tx),
            inner_tun_endpoint,
            &[], // no filter — the pre-fix behavior
        );
        router.send(forged()).await.unwrap();
        assert!(
            outer_rx.try_recv().is_ok(),
            "without inner_allowed_ips, the outer peer's spoofed packet \
             reaches the local TUN — this is the hijack"
        );
        assert!(inner_rx.try_recv().is_err());
    }

    // --- With the filter: the hijack is blocked. ---
    {
        let (inner_tx, mut inner_rx) = mpsc::channel(8);
        let (outer_tx, mut outer_rx) = mpsc::channel(8);
        let mut router = TunTxRouter::new(
            RecordingIpSend(inner_tx),
            RecordingIpSend(outer_tx),
            inner_tun_endpoint,
            &[inner_allowed],
        );
        router.send(forged()).await.unwrap();
        assert!(
            outer_rx.try_recv().is_err(),
            "spoofed packet with src inside inner_allowed_ips must NOT reach the TUN"
        );
        assert!(
            inner_rx.try_recv().is_err(),
            "spoofed packet must also not be forwarded to the inner WG"
        );

        // Sanity: a packet with an unrelated source (a legitimate direct
        // outer-tunnel response) still reaches the outer TUN.
        let legit_src: Ipv4Addr = "8.8.8.8".parse().unwrap();
        router
            .send(mock::packet_with_addrs(
                legit_src,
                local_dst,
                b"legit response",
            ))
            .await
            .unwrap();
        let received = outer_rx.try_recv().expect("legit traffic must pass");
        assert_eq!(received.source(), Some(legit_src.into()));
    }
}

/// Test [`NatIpRecv`] and [`NatIpSend`]
///
/// - Outgoing: app sends src=outer_tun_ip -> Bob receives src=inner_tun_ip
/// - Incoming: Bob sends dst=inner_tun_ip -> app receives dst=outer_tun_ip
#[tokio::test]
#[test_log::test]
async fn test_tunnel_nat() {
    let outer_tun_ip: Ipv4Addr = "10.64.0.2".parse().unwrap();
    let inner_tun_ip: Ipv4Addr = "172.16.0.1".parse().unwrap();
    let some_addr: Ipv4Addr = "10.100.0.5".parse().unwrap();

    async fn forward<T>(mut eve_rx: mpsc::Receiver<T>, eve_tx: mpsc::Sender<T>) {
        loop {
            let Some(packet) = eve_rx.recv().await else {
                break;
            };
            if eve_tx.send(packet).await.is_err() {
                break;
            }
        }
    }

    let (alice_mock_tun, alice_app_tx, mut alice_app_rx) = mock::mock_tun();
    let (bob_mock_tun, bob_app_tx, mut bob_app_rx) = mock::mock_tun();

    let port = 51820u16;
    let endpoint_alice = Ipv4Addr::new(10, 0, 0, 1);
    let endpoint_bob = Ipv4Addr::new(10, 0, 0, 2);

    const CHANNEL_CAPACITY: usize = 10;
    let (alice_v4, alice_eve_v4) = UdpChannelV4::new_pair(CHANNEL_CAPACITY);
    let (bob_v4, bob_eve_v4) = UdpChannelV4::new_pair(CHANNEL_CAPACITY);
    let (alice_v6, alice_eve_v6) = UdpChannelV6::new_pair(CHANNEL_CAPACITY);
    let (bob_v6, bob_eve_v6) = UdpChannelV6::new_pair(CHANNEL_CAPACITY);

    // Relay alice <-> bob (IPv4)
    tokio::spawn(forward(alice_eve_v4.rx, bob_eve_v4.tx));
    tokio::spawn(forward(bob_eve_v4.rx, alice_eve_v4.tx));

    // Relay alice <-> bob (IPv6)
    tokio::spawn(forward(alice_eve_v6.rx, bob_eve_v6.tx));
    tokio::spawn(forward(bob_eve_v6.rx, alice_eve_v6.tx));

    let udp_alice =
        UdpChannelFactory::new(endpoint_alice, alice_v4, Ipv6Addr::UNSPECIFIED, alice_v6);
    let udp_bob = UdpChannelFactory::new(endpoint_bob, bob_v4, Ipv6Addr::UNSPECIFIED, bob_v6);

    let privkey_alice = StaticSecret::random();
    let privkey_bob = StaticSecret::random();
    let pubkey_alice = PublicKey::from(&privkey_alice);
    let pubkey_bob = PublicKey::from(&privkey_bob);

    let allow_all: IpNetwork = Ipv4Network::new(Ipv4Addr::UNSPECIFIED, 0).unwrap().into();

    let peer_alice = Peer::new(pubkey_alice)
        .with_endpoint((endpoint_alice, port).into())
        .with_allowed_ip(allow_all);
    let peer_bob = Peer::new(pubkey_bob)
        .with_endpoint((endpoint_bob, port).into())
        .with_allowed_ip(allow_all);

    // Alice uses NAT adapters:
    //   NatIpRecv: rewrites outgoing src  outer_tun_ip -> inner_tun_ip
    //   NatIpSend: rewrites incoming dst  inner_tun_ip -> outer_tun_ip
    let alice_rx = NatIpRecv::new(alice_mock_tun.clone(), outer_tun_ip, inner_tun_ip);
    let alice_tx = NatIpSend::new(alice_mock_tun, inner_tun_ip, outer_tun_ip);

    let _alice = DeviceBuilder::new()
        .with_private_key(privkey_alice)
        .with_ip_pair(alice_tx, alice_rx)
        .with_udp(udp_alice)
        .with_listen_port(port)
        .with_peer(peer_bob)
        .build()
        .await
        .expect("create alice device");

    let _bob = DeviceBuilder::new()
        .with_private_key(privkey_bob)
        .with_ip(bob_mock_tun)
        .with_udp(udp_bob)
        .with_listen_port(port)
        .with_peer(peer_alice)
        .build()
        .await
        .expect("create bob device");

    // Outgoing: Alice app sends src=outer_tun_ip;
    // NatIpRecv rewrites src -> inner_tun_ip before encrypting.
    // Bob should receive src=inner_tun_ip.
    alice_app_tx
        .send(mock::packet_with_addrs(outer_tun_ip, some_addr, b"hello"))
        .await;
    let received = bob_app_rx.recv().await;
    assert_eq!(received.source(), Some(inner_tun_ip.into()));
    assert_eq!(received.payload(), Some(b"hello".as_slice()));

    // Incoming: Bob app sends dst=inner_tun_ip;
    // NatIpSend rewrites dst -> outer_tun_ip before writing to TUN.
    // Alice should receive dst=outer_tun_ip.
    bob_app_tx
        .send(mock::packet_with_addrs(some_addr, inner_tun_ip, b"reply"))
        .await;
    let received = alice_app_rx.recv().await;
    assert_eq!(received.destination(), Some(outer_tun_ip.into()));
    assert_eq!(received.payload(), Some(b"reply".as_slice()));
}

/// The number of packets we send through the tunnel
fn packet_count() -> usize {
    mock::packets_of_every_size().len()
}

/// Helper method to test that packets can be sent from one [`Device`] to another.
/// Use `eavesdrop` to sniff wireguard packets and assert things about the connection.
async fn test_device_pair(eavesdrop: impl AsyncFnOnce(MockEavesdropper) + Send) {
    let (mut alice, mut bob, eve) = mock::device_pair().await;

    // Create a future to eavesdrop on alice and bob.
    let eavesdrop = async {
        select! {
            _ = eavesdrop(eve) => {}
            _ = sleep(Duration::from_secs(1)) => panic!("eavesdrop timeout"),
        }
    };

    // Create a future to drive alice and bob.
    let drive_connection = async move {
        let packets_to_send = mock::packets_of_every_size();
        let packets_to_recv = packets_to_send.clone();

        // Send a bunch of packets from alice to bob.
        let send_packets = async {
            for packet in packets_to_send {
                alice.app_tx.send(packet).await;
            }
            pending().await
        };

        // Receive expected packets to bob from alice.
        let wait_for_packets = async {
            for expected_packet in packets_to_recv {
                let p = bob.app_rx.recv().await;
                assert_eq!(p.as_bytes(), expected_packet.as_bytes());
            }
        };

        select! {
            _ = wait_for_packets => {},
            _ = send_packets => unreachable!(),
            _ = alice.app_rx.recv() => panic!("no data is sent from bob to alice"),
            _ = sleep(Duration::from_secs(1)) => panic!("timeout"),
        }

        // Shut down alice and bob after `wait_for_packets`
        drop((alice, bob));
    };

    // Drive the connection, and eavesdrop it at the same time.
    join! {
        drive_connection,
        eavesdrop
    };
}
