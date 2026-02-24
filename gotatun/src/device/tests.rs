use std::{future::ready, time::Duration};

use futures::{StreamExt, future::pending};
use mock::MockEavesdropper;
use rand::{SeedableRng, rngs::StdRng};
use tokio::{join, select, time::sleep};
use zerocopy::IntoBytes;

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
