#![cfg(test)]

use std::{future::ready, net::Ipv4Addr, sync::Arc, time::Duration};

use crate::{
    device::peer::{AllowedIP, Peer},
    noise::{Tunn, TunnResult},
    packet::{Ip, Packet, Wg, WgKind},
};

use aead::OsRng;
use futures::{FutureExt, SinkExt, Stream, StreamExt, channel::mpsc::SendError, select};
use rand_core::RngCore;
use tokio::{
    sync::{Mutex, OwnedMutexGuard},
    time::sleep,
};
use zerocopy::IntoBytes;

fn create_two_tuns() -> [Tunn; 2] {
    let my_secret_key = x25519_dalek::StaticSecret::random_from_rng(OsRng);
    let my_public_key = x25519_dalek::PublicKey::from(&my_secret_key);
    let my_idx = OsRng.next_u32();

    let their_secret_key = x25519_dalek::StaticSecret::random_from_rng(OsRng);
    let their_public_key = x25519_dalek::PublicKey::from(&their_secret_key);
    let their_idx = OsRng.next_u32();

    let my_tun = Tunn::new(my_secret_key, their_public_key, None, None, my_idx, None);

    let their_tun = Tunn::new(their_secret_key, my_public_key, None, None, their_idx, None);

    [my_tun, their_tun]
}

fn create_two_peers() -> [Peer; 2] {
    let tuns = create_two_tuns();

    let mut i = 0;
    tuns.map(|tun| {
        i += 1;
        Peer::new(
            tun,
            i,
            None,
            &[AllowedIP {
                addr: Ipv4Addr::UNSPECIFIED.into(),
                cidr: 0,
            }],
            None,
        )
    })
}

#[tokio::test]
async fn pipelines() {
    let [peer1, peer2] = create_two_peers().map(Mutex::new).map(Arc::new);
    let mock_ip1 = async_stream::stream! {
        loop {
            yield mock_read_ip().await;
        }
    };

    let mock_ip2 = async_stream::stream! {
         loop {
            yield mock_read_ip().await;
        }

    };

    let (p1_tx, p2_rx) = futures::channel::mpsc::channel(10);
    let (p2_tx, p1_rx) = futures::channel::mpsc::channel(10);

    let p1_out = handle_outgoing(mock_ip1, peer1.clone())
        .inspect(|packet| println!("peer 1->2 {:?}", packet.as_ref().unwrap().packet_type));
    let p2_out = handle_outgoing(mock_ip2, peer2.clone())
        .inspect(|packet| println!("peer 2->1 {:?}", packet.as_ref().unwrap().packet_type));

    // try commenting me out!
    let p1_rx = p1_rx.map(deobfuscate);
    let p2_rx = p2_rx.map(deobfuscate);
    let p1_tx = p1_tx.with(obfuscate);
    let p2_tx = p2_tx.with(obfuscate);

    let p1_out = p1_out.forward(p1_tx.clone());
    let p2_out = p2_out.forward(p2_tx.clone());

    let p2_inc = handle_incoming(p2_rx, peer2).for_each(|result| {
        let mut p2_tx = p2_tx.clone();
        async move {
            let packet: Packet<Ip> = match result {
                TunnResult::Done => return,
                TunnResult::Err(err) => {
                    println!("{err:?}");
                    return;
                }
                TunnResult::WriteToNetwork(packet) => {
                    println!("peer 2->1, writetonetwork {:?}", packet.packet_type);
                    p2_tx.send(packet).await.unwrap();
                    return;
                }
                TunnResult::WriteToTunnelV4(packet) => packet.into(),
                TunnResult::WriteToTunnelV6(packet) => packet.into(),
            };
            println!(
                "Peer two got an IP packet! {:?}",
                str::from_utf8(&packet.as_bytes()[packet.as_bytes().len() - 20..])
                    .unwrap_or("non-utf8")
            );
        }
    });

    let p1_inc = handle_incoming(p1_rx, peer1).for_each(|result| {
        let mut p1_tx = p1_tx.clone();
        async move {
            let packet: Packet<Ip> = match result {
                TunnResult::Done => return,
                TunnResult::Err(err) => {
                    println!("{err:?}");
                    return;
                }
                TunnResult::WriteToNetwork(packet) => {
                    println!("peer 1->2, writetonetwork {:?}", packet.packet_type);
                    p1_tx.send(packet).await.unwrap();
                    return;
                }
                TunnResult::WriteToTunnelV4(packet) => packet.into(),
                TunnResult::WriteToTunnelV6(packet) => packet.into(),
            };
            println!(
                "Peer one got an IP packet! {:?}",
                str::from_utf8(&packet.as_bytes()[packet.as_bytes().len() - 20..])
                    .unwrap_or("non-utf8")
            );
        }
    });

    select! {
        _ = p1_inc.fuse() => {}
        _ = p2_inc.fuse() => {}
        _ = p1_out.fuse() => {}
        _ = p2_out.fuse() => {}
        _ = sleep(Duration::from_secs(5)).fuse() => panic!("timeout"),
    }

    panic!("exited")
}

fn handle_outgoing<E: 'static>(
    stream: impl Stream<Item = Packet<Ip>> + Send + 'static,
    peer1: Arc<Mutex<Peer>>, // TODO: make mock peer
) -> impl Stream<Item = Result<Packet<Wg>, E>> + Send + 'static {
    stream
        .then(move |p| {
            let peer1 = peer1.clone();
            async { (p, peer1.lock_owned().await) }
        })
        .filter_map(encapsulate)
        .map(Ok)
}

fn handle_incoming(
    stream: impl Stream<Item = Packet<Wg>> + Send + 'static,
    peer: Arc<Mutex<Peer>>, // TODO: make mock peer
) -> impl Stream<Item = TunnResult> + Send + 'static {
    stream
        .then(move |p| {
            let peer = peer.clone();
            async { (p, peer.lock_owned().await) }
        })
        .then(parse_wg)
        .then(decapsulate)
}

async fn mock_read_ip() -> Packet<Ip> {
    tokio::time::sleep(Duration::from_secs(0)).await;
    const EXAMPLE_IPV4_ICMP: &[u8] = &[
        0x45, 0x83, 0x0, 0x54, 0xa3, 0x13, 0x40, 0x0, 0x40, 0x1, 0xc6, 0x26, 0xa, 0x8c, 0xc2, 0xdd,
        0x1, 0x2, 0x3, 0x4, 0x8, 0x0, 0x51, 0x13, 0x0, 0x2b, 0x0, 0x1, 0xb1, 0x5c, 0x87, 0x68, 0x0,
        0x0, 0x0, 0x0, 0xa8, 0x28, 0x7, 0x0, 0x0, 0x0, 0x0, 0x0, 0x10, 0x11, 0x12, 0x13, 0x14,
        0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23,
        0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32,
        0x33, 0x34, 0x35, 0x36, 0x37,
    ];

    Packet::copy_from(EXAMPLE_IPV4_ICMP).try_into_ip().unwrap()
}

async fn encapsulate(
    (packet, mut peer): (Packet<Ip>, OwnedMutexGuard<Peer>),
) -> Option<Packet<Wg>> {
    peer.tunnel.handle_outgoing_packet(packet.into_bytes())
}

async fn parse_wg(
    (packet, peer): (Packet<Wg>, OwnedMutexGuard<Peer>),
) -> (WgKind, OwnedMutexGuard<Peer>) {
    println!("peer {} got {:?}", peer.index(), packet.packet_type);
    let packet = packet.into_kind().unwrap();
    (packet, peer)
}

async fn decapsulate((packet, mut peer): (WgKind, OwnedMutexGuard<Peer>)) -> TunnResult {
    let packet = peer.tunnel.handle_incoming_packet(packet);
    packet
}

fn obfuscate(packet: Packet<Wg>) -> impl Future<Output = Result<Packet, SendError>> + Clone {
    let mut packet = packet.into_bytes();
    for b in &mut *packet {
        *b ^= 0xff;
    }
    ready(Ok(packet))
}

fn deobfuscate(mut packet: Packet) -> Packet<Wg> {
    for b in &mut *packet {
        *b ^= 0xff;
    }
    packet.try_into_wg().unwrap()
}
