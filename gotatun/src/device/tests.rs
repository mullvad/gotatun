use std::{future::ready, time::Duration};

use futures::StreamExt;
use mock::MockEavesdropper;
use tokio::{join, select, time::sleep};
use zerocopy::IntoBytes;

pub mod mock;

/// How many packets we send through the tunnel
const N: usize = 100;

/// Assert that the expected number of packets is sent.
// We expect there to be N WgData packets, one handshake init, one handshake resp, and one keepalive.
#[tokio::test]
#[test_log::test]
async fn number_of_packets() {
    test_device_pair(async |eve| {
        let expected_count = N + 2 + 1;
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

        assert!(dbg!(wg_data_count) >= N);
    })
    .await
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
        let mut next_packet_to_send = mock::packet_generator();
        let mut next_packet_to_recv = next_packet_to_send.clone();

        // Send a bunch of packets from alice to bob.
        let spam_packets = async {
            loop {
                alice.app_tx.send(next_packet_to_send()).await;
            }
        };

        // Receive exactly N packets to bob from alice.
        let wait_for_n_packets = async {
            for _ in 0..N {
                let p = bob.app_rx.recv().await;
                assert_eq!(p.as_bytes(), next_packet_to_recv().as_bytes());
            }
        };

        select! {
            _ = wait_for_n_packets => {},
            _ = spam_packets => unreachable!(),
            _ = alice.app_rx.recv() => panic!("no data is sent from bob to alice"),
            _ = sleep(Duration::from_secs(1)) => panic!("timeout"),
        }

        // Shut down alice and bob after `wait_for_n_packets`
        drop((alice, bob));
    };

    // Drive the connection, and eavesdrop it at the same time.
    join! {
        drive_connection,
        eavesdrop
    };
}
