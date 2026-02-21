// Copyright (c) 2026 Mullvad VPN AB. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use std::{
    io,
    net::{Ipv4Addr, Ipv6Addr},
    sync::Arc,
};

use duplicate::duplicate;
use either::for_both;
use futures::{Stream, StreamExt};
use ipnetwork::Ipv4Network;
use rand::random;
use tokio::sync::{
    Mutex, broadcast,
    mpsc::{self, Receiver, Sender},
};
use tokio_stream::wrappers::BroadcastStream;
use x25519_dalek::{PublicKey, StaticSecret};
use zerocopy::IntoBytes;

use crate::{
    device::{Device, DeviceBuilder, Peer},
    packet::{
        Ip, IpNextProtocol, Ipv4, Ipv4Header, Ipv6, Packet, PacketBufPool, Udp, WgData,
        WgHandshakeInit, WgHandshakeResp, WgKind,
    },
    tun::{IpRecv, IpSend, MtuWatcher},
    udp::channel::{UdpChannelFactory, UdpChannelV4, UdpChannelV6},
};

pub const TUN_MTU: u16 = 1360;

pub async fn device_pair() -> (MockDevice, MockDevice, MockEavesdropper) {
    let (mock_tun_a, mock_app_tx_a, mock_app_rx_a) = mock_tun();
    let (mock_tun_b, mock_app_tx_b, mock_app_rx_b) = mock_tun();

    let port: u16 = 51820;
    let endpoint_a = Ipv4Addr::new(10, 0, 0, 1);
    let endpoint_b = Ipv4Addr::new(10, 0, 0, 2);

    let channel_capacity = 10;
    let (alice_v4, mut alice_eve_v4) = UdpChannelV4::new_pair(channel_capacity);
    let (bob_v4, mut bob_eve_v4) = UdpChannelV4::new_pair(channel_capacity);

    let (alice_v6, mut alice_eve_v6) = UdpChannelV6::new_pair(channel_capacity);
    let (bob_v6, mut bob_eve_v6) = UdpChannelV6::new_pair(channel_capacity);
    let (eve_tx, eve_rx) = broadcast::channel(1000);
    let eve = MockEavesdropper { rx: eve_rx };

    duplicate! {
        [
            from to;
            [alice_eve_v4] [bob_eve_v4];
            [alice_eve_v6] [bob_eve_v6];
            [bob_eve_v4] [alice_eve_v4];
            [bob_eve_v6] [alice_eve_v6];
        ]
        {
            let eve_tx = eve_tx.clone();
            tokio::spawn(async move {
                loop {
                    let Some(packet) = from.rx.recv().await else {
                        break
                    };

                    let _ = eve_tx.send(Packet::copy_from(&*packet).into());

                    if to.tx.send(packet).await.is_err() {
                        break;
                    }
                }
            });
        }
    };

    let udp_alice = UdpChannelFactory::new(endpoint_a, alice_v4, Ipv6Addr::UNSPECIFIED, alice_v6);
    let udp_bob = UdpChannelFactory::new(endpoint_b, bob_v4, Ipv6Addr::UNSPECIFIED, bob_v6);

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
        .with_udp(udp_alice)
        .with_listen_port(port) // TODO: is this necessary?
        .with_peer(peer_b)
        .build()
        .await
        .expect("create mock device");

    let device_b = DeviceBuilder::new()
        .with_private_key(privkey_b)
        .with_ip(mock_tun_b.clone())
        .with_udp(udp_bob)
        .with_listen_port(port) // TODO: is this necessary?
        .with_peer(peer_a)
        .build()
        .await
        .expect("create mock device");

    let alice = MockDevice {
        device: device_a,
        app_tx: mock_app_tx_a,
        app_rx: mock_app_rx_a,
    };

    let bob = MockDevice {
        device: device_b,
        app_tx: mock_app_tx_b,
        app_rx: mock_app_rx_b,
    };

    (alice, bob, eve)
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
    packet.extend_from_slice(payload);
    packet.try_into_ip().unwrap()
}

/// Create an `Iterator` that returns one packet for every possible payload size (with respect to [`TUN_MTU`]).
pub fn packets_of_every_size() -> impl ExactSizeIterator<Item = Packet<Ip>> + Clone {
    let tun_mtu = usize::from(TUN_MTU);

    // Include some randomness for good measure.
    let random: u64 = random();

    // Don't exceed max payload size
    let max_payload = tun_mtu - Ipv4Header::LEN;

    (0..max_payload + 1).map(move |len| {
        // Generate some nonsense payload
        let mut payload = vec![b'!'; tun_mtu];
        let message = format!("{random} Hello there!");
        let message = message.as_bytes();
        let message_len = message.len().min(len);
        payload[..message_len].copy_from_slice(&message[..message_len]);

        // Wrap it in an IP packet
        packet(&payload[..len])
    })
}

pub struct MockDevice {
    #[expect(dead_code)]
    pub device: Device<(UdpChannelFactory, MockTun, MockTun)>,
    pub app_tx: MockAppTx,
    pub app_rx: MockAppRx,
}

pub struct MockEavesdropper {
    rx: broadcast::Receiver<Packet<Ip>>,
}

impl MockEavesdropper {
    /// Get a stream of all sniffed IP packets.
    ///
    /// The stream will close after the WireGuard devices has shut down, and the last packet sent.
    pub fn ip(&self) -> impl Stream<Item = Packet<Ip>> + use<> {
        let rx = self.rx.resubscribe();
        BroadcastStream::new(rx).filter_map(async |result| result.ok())
    }

    /// Get as stream of all sniffed IPv4 packets. [Read more](Self::ip)
    pub fn ipv4(&self) -> impl Stream<Item = Packet<Ipv4<Udp>>> + use<> {
        self.ip()
            .filter_map(async |ip| ip.try_into_ipvx().unwrap().left())
            .map(|ipv4| ipv4.try_into_udp().unwrap())
    }

    /// Get as stream of all sniffed IPv6 packets. [Read more](Self::ip)
    pub fn ipv6(&self) -> impl Stream<Item = Packet<Ipv6<Udp>>> + use<> {
        self.ip()
            .filter_map(async |ip| ip.try_into_ipvx().unwrap().right())
            .map(|ipv6| ipv6.try_into_udp().unwrap())
    }

    /// Get as stream of all sniffed UDP packets. [Read more](Self::ip)
    pub fn udp(&self) -> impl Stream<Item = Packet<Udp>> + use<> {
        self.ip()
            .map(|ip| ip.try_into_ipvx().unwrap())
            .map(|ipvx| for_both!(ipvx, ipvx => ipvx.try_into_udp().unwrap().into_payload()))
    }

    /// Get as stream of all sniffed WireGuard packets. [Read more](Self::ip)
    pub fn wg(&self) -> impl Stream<Item = WgKind> + use<> {
        self.udp()
            .map(|udp| udp.into_payload().try_into_wg().unwrap())
    }

    /// Get as stream of all sniffed [`WgData`] packets. [Read more](Self::ip)
    pub fn wg_data(&self) -> impl Stream<Item = Packet<WgData>> + use<> {
        self.wg().filter_map(async |wg| match wg {
            WgKind::Data(data) => Some(data),
            _ => None,
        })
    }

    /// Get as stream of all sniffed [`WgHandshakeInit`] packets. [Read more](Self::ip)
    pub fn wg_handshake_init(&self) -> impl Stream<Item = Packet<WgHandshakeInit>> + use<> {
        self.wg().filter_map(async |wg| match wg {
            WgKind::HandshakeInit(data) => Some(data),
            _ => None,
        })
    }

    /// Get as stream of all sniffed [`WgHandshakeResp`] packets. [Read more](Self::ip)
    pub fn wg_handshake_resp(&self) -> impl Stream<Item = Packet<WgHandshakeResp>> + use<> {
        self.wg().filter_map(async |wg| match wg {
            WgKind::HandshakeResp(data) => Some(data),
            _ => None,
        })
    }
}

#[derive(Clone)]
pub struct MockTun {
    tun_to_app_tx: Sender<Packet<Ip>>,
    app_to_tun_rx: Arc<Mutex<Receiver<Packet<Ip>>>>,
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
            .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "channel closed"))?;
        Ok(std::iter::once(packet))
    }

    fn mtu(&self) -> MtuWatcher {
        MtuWatcher::new(TUN_MTU)
    }
}
