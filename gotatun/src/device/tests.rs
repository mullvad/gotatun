use std::time::Duration;

use tokio::{select, time::sleep};
use zerocopy::IntoBytes;

pub mod mock;

/// Test that packets can be sent from one [`Device`] to another and that they arrive intact and in order.
#[tokio::test]
#[test_log::test]
async fn test_send_packets() {
    let [mut alice, mut bob] = mock::device_pair().await;

    let mut next_packet_to_send = mock::packet_generator();
    let mut next_packet_to_recv = next_packet_to_send.clone();

    let spam_packets = async {
        loop {
            alice.app_tx.send(next_packet_to_send()).await;
            // log::trace!("Alice sent a packet!");
        }
    };

    let wait_for_x_packets = async {
        for _ in 0..100 {
            let p = bob.app_rx.recv().await;
            assert_eq!(p.as_bytes(), next_packet_to_recv().as_bytes());
        }
    };

    select! {
        _ = wait_for_x_packets => {},
        _ = spam_packets => unreachable!(),
        _ = alice.app_rx.recv() => panic!("no data is sent from bob to alice"),
        _ = sleep(Duration::from_secs(1)) => panic!("timeout"),
    }
}
