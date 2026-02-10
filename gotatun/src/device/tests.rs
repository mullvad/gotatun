use tokio::select;
use zerocopy::IntoBytes;

pub mod mock;

macro_rules! timeout {
    ($n:literal sec) => {
        async {
            tokio::time::sleep(std::time::Duration::from_secs($n)).await;
            panic!("timeout");
        }
    };
}

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
        _ = alice.app_rx.recv() => panic!(),
        _ = timeout!(1 sec) => {}
    }
}
