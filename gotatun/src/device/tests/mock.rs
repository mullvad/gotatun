// Copyright (c) 2026 Mullvad VPN AB. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use std::{
    io,
    net::{Ipv4Addr, Ipv6Addr},
    sync::Arc,
};

use ipnetwork::Ipv4Network;
use rand::random;
use tokio::sync::{
    Mutex,
    mpsc::{self, Receiver, Sender},
};
use x25519_dalek::{PublicKey, StaticSecret};
use zerocopy::IntoBytes;

use crate::{
    device::{Device, DeviceBuilder, Peer},
    packet::{Ip, IpNextProtocol, Ipv4Header, Packet, PacketBufPool},
    tun::{IpRecv, IpSend, MtuWatcher},
    udp::channel::{UdpChannelFactory, new_udp_udp_channel},
};

pub async fn device_pair() -> [MockDevice; 2] {
    let (mock_tun_a, mock_app_tx_a, mock_app_rx_a) = mock_tun();
    let (mock_tun_b, mock_app_tx_b, mock_app_rx_b) = mock_tun();

    let port = 51820u16;
    let endpoint_a = Ipv4Addr::new(10, 0, 0, 1);
    let endpoint_b = Ipv4Addr::new(10, 0, 0, 2);

    let [udp_a, udp_b] = new_udp_udp_channel(
        100,
        endpoint_a,
        Ipv6Addr::UNSPECIFIED, // TODO
        endpoint_b,
        Ipv6Addr::UNSPECIFIED, // TODO
    );

    let privkey_a = StaticSecret::random();
    let privkey_b = StaticSecret::random();

    let pubkey_a = PublicKey::from(&privkey_a);
    let pubkey_b = PublicKey::from(&privkey_b);

    let peer_a = Peer::new(pubkey_a)
        .with_endpoint((endpoint_a, port).into())
        .with_allowed_ip(Ipv4Network::new(Ipv4Addr::UNSPECIFIED, 0).unwrap().into());

    let peer_b = Peer::new(pubkey_b)
        .with_endpoint((endpoint_b, port).into())
        .with_allowed_ip(Ipv4Network::new(Ipv4Addr::UNSPECIFIED, 0).unwrap().into());

    let device_a = DeviceBuilder::new()
        .with_private_key(privkey_a)
        .with_ip(mock_tun_a.clone())
        .with_udp(udp_a)
        .with_listen_port(port) // TODO: is this necessary?
        .with_peer(peer_b)
        .build()
        .await
        .expect("create mock device");

    let device_b = DeviceBuilder::new()
        .with_private_key(privkey_b)
        .with_ip(mock_tun_b.clone())
        .with_udp(udp_b)
        .with_listen_port(port) // TODO: is this necessary?
        .with_peer(peer_a)
        .build()
        .await
        .expect("create mock device");

    let device_a = MockDevice {
        device: device_a,
        app_tx: mock_app_tx_a,
        app_rx: mock_app_rx_a,
    };

    let device_b = MockDevice {
        device: device_b,
        app_tx: mock_app_tx_b,
        app_rx: mock_app_rx_b,
    };

    [device_a, device_b]
}

pub fn mock_tun() -> (MockTun, MockAppTx, MockAppRx) {
    let (app_to_tun_tx, app_to_tun_rx) = mpsc::channel(1);
    let (tun_to_app_tx, tun_to_app_rx) = mpsc::channel(1);

    let tun = MockTun {
        app_to_tun_rx: Arc::new(Mutex::new(app_to_tun_rx)),
        tun_to_app_tx,
    };

    let app_tx = MockAppTx { tx: app_to_tun_tx };
    let app_rx = MockAppRx { rx: tun_to_app_rx };

    (tun, app_tx, app_rx)
}

/// Create a mocked barely passable IPv4 packet containing `payload`.
pub fn packet(payload: impl AsRef<[u8]>) -> Packet<Ip> {
    let payload = payload.as_ref();
    let packet = Ipv4Header::new(
        Ipv4Addr::new(192, 168, 0, 1),
        Ipv4Addr::new(192, 168, 0, 2),
        IpNextProtocol::Pup,
        payload,
    );

    let mut packet = Packet::copy_from(packet.as_bytes());
    packet.buf_mut().extend_from_slice(payload);
    packet.try_into_ip().unwrap()
}

/// Create an `FnMut` that returns a new unique packet every time it's called.
pub fn packet_generator() -> impl FnMut() -> Packet<Ip> + Clone {
    let random: u64 = random();
    let mut n = 0;
    move || {
        n += 1;
        packet(format!("Hello there! {random} {n}"))
    }
}

pub struct MockDevice {
    #[expect(dead_code)]
    pub device: Device<(UdpChannelFactory, MockTun, MockTun)>,
    pub app_tx: MockAppTx,
    pub app_rx: MockAppRx,
}

#[derive(Clone)]
pub struct MockTun {
    tun_to_app_tx: Sender<Packet<Ip>>,
    app_to_tun_rx: Arc<Mutex<Receiver<Packet<Ip>>>>,
    // on_send: Arc<Mutex<Option<Box<dyn FnMut(Packet<Ip>) -> io::Result<()> + Send>>>>,
}

#[derive(Clone)]
pub struct MockAppTx {
    tx: Sender<Packet<Ip>>,
}

pub struct MockAppRx {
    rx: Receiver<Packet<Ip>>,
}

impl MockAppTx {
    /// Send a packet over the TUN from the conceptual user application.
    pub async fn send(&self, packet: Packet<Ip>) {
        self.tx.send(packet).await.unwrap();
    }
}

impl MockAppRx {
    /// Recv a packet from the TUN to the conceptual user application.
    pub async fn recv(&mut self) -> Packet<Ip> {
        self.rx.recv().await.unwrap()
    }
}

impl IpSend for MockTun {
    async fn send(&mut self, packet: Packet<Ip>) -> io::Result<()> {
        self.tun_to_app_tx.send(packet).await.unwrap();
        Ok(())
    }
}

impl IpRecv for MockTun {
    async fn recv<'a>(
        &'a mut self,
        _pool: &mut PacketBufPool,
    ) -> io::Result<impl Iterator<Item = Packet<Ip>> + Send + 'a> {
        let packet = self
            .app_to_tun_rx
            .try_lock()
            .expect("may not call `recv` concurrently")
            .recv()
            .await
            .ok_or(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "no more packets: channel closed",
            ))?;
        Ok([packet].into_iter())
    }

    fn mtu(&self) -> MtuWatcher {
        MtuWatcher::new(1360)
    }
}
