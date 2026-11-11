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

//! A device on real UDP sockets keeps answering after it has sent to a peer whose port has
//! closed.
//!
//! The ICMP port unreachable that comes back is reported on Windows as `WSAECONNRESET` on
//! the device socket's next receive. It must not end reception for the whole device.
//! See <https://github.com/mullvad/gotatun/issues/226>.

use std::net::Ipv4Addr;
use std::time::Duration;

use ipnetwork::Ipv4Network;
use tokio::time::timeout;
use x25519_dalek::{PublicKey, StaticSecret};

use super::mock::{self, MockAppRx, MockAppTx, MockTun};
use crate::device::{Device, DeviceBuilder, Peer};
use crate::udp::socket::UdpSocketFactory;

type SocketDevice = Device<(UdpSocketFactory, MockTun, MockTun)>;

/// Guards each step against hanging. A handshake initiation is retried after 5 seconds, so
/// this allows for one lost initiation on a slow runner.
const TIMEOUT: Duration = Duration::from_secs(12);

/// A device with a real UDP socket on a free port, and a mock TUN.
struct TestDevice {
    device: SocketDevice,
    app_tx: MockAppTx,
    _app_rx: MockAppRx,
    port: u16,
}

impl TestDevice {
    async fn new(private_key: StaticSecret, peer: Peer) -> Self {
        let (tun, app_tx, app_rx) = mock::mock_tun();
        let device = DeviceBuilder::new()
            .with_private_key(private_key)
            .with_ip(tun)
            .with_default_udp()
            .with_listen_port(0)
            .with_peer(peer)
            .build()
            .await
            .expect("create device");
        let port = device.read(async |d| d.listen_port()).await;
        Self {
            device,
            app_tx,
            _app_rx: app_rx,
            port,
        }
    }

    async fn tx_bytes(&self) -> usize {
        let peers = self.device.read(async |d| d.peers().await).await;
        peers[0].stats.tx_bytes
    }
}

/// A server keeps answering new handshakes after sending to clients that have gone away.
#[tokio::test]
#[test_log::test]
async fn device_answers_after_port_unreachable() {
    let server_key = StaticSecret::random();
    let server_public = PublicKey::from(&server_key);
    let client_key = StaticSecret::random();

    // `mock::packet` is addressed to 192.168.0.2.
    let client_on_server = Peer::new(PublicKey::from(&client_key)).with_allowed_ip(
        Ipv4Network::new(Ipv4Addr::new(192, 168, 0, 2), 32)
            .unwrap()
            .into(),
    );
    let mut server = TestDevice::new(server_key, client_on_server).await;

    let new_client = async |server_port: u16| {
        let server_on_client = Peer::new(server_public)
            .with_endpoint((Ipv4Addr::LOCALHOST, server_port).into())
            .with_allowed_ip(Ipv4Network::new(Ipv4Addr::UNSPECIFIED, 0).unwrap().into());
        TestDevice::new(client_key.clone(), server_on_client).await
    };

    for round in 0..3 {
        // A client connects, then goes away, and its port closes.
        let client = new_client(server.port).await;
        timeout(TIMEOUT, client.device.force_handshake(&server_public))
            .await
            .unwrap_or_else(|_| panic!("round {round}: the server never answered the handshake"))
            .unwrap();
        let client_port = client.port;
        client.device.stop().await;
        drop(
            std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, client_port))
                .expect("the client's port must have closed"),
        );

        // The server still has a session with the client, so a packet for the client goes
        // to its old port, and an ICMP port unreachable comes back.
        let tx_bytes = server.tx_bytes().await;
        server
            .app_tx
            .send(mock::packet("for a client that has gone"))
            .await;
        timeout(TIMEOUT, async {
            while server.tx_bytes().await == tx_bytes {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the server must send the packet to the client's old port");
    }

    // A new client with the same key, on a new port, must still get an answer.
    let client = new_client(server.port).await;
    timeout(TIMEOUT, client.device.force_handshake(&server_public))
        .await
        .expect("the server stopped answering after a port unreachable report")
        .unwrap();

    assert!(
        timeout(Duration::ZERO, server.device.wait()).await.is_err(),
        "the server must not have stopped with an error"
    );

    client.device.stop().await;
    server.device.stop().await;
}
