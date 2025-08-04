use std::{future::pending, io, iter, net::Ipv4Addr, ops::Deref as _, sync::Arc};

use boringtun::{
    packet::{Ip, IpNextProtocol, Ipv4, Ipv4Header, Packet, PacketBufPool, Udp, UdpHeader},
    tun::{IpRecv, IpSend},
};
use tokio::sync::Semaphore;
use zerocopy::{FromBytes, IntoBytes};

/// An [IpSend] that will only allow a packet to be sent if [MockIpSend::wait_for] is called.
#[derive(Clone)]
pub struct MockIpSend {
    /// Number of packets that has been sent on this [IpSend].
    pub packets_sent: Arc<Semaphore>,
}

/// An [IpRecv] that always returns the same packet.
#[derive(Clone)]
pub struct MockIpRecv {
    /// This controls how many packets are received.
    ///
    /// Calling [MockIpRecv::recv] will decrement this semaphore.
    /// Calling [MockIpRecv::add_packets] will increment it.
    pub receive_packets: Arc<Semaphore>,

    mock_packet: Arc<Packet<Ipv4<Udp<[u8]>>>>,
}

/// An [IpRecv] that does nothing.
#[derive(Clone)]
pub struct NullIpSend {}

/// An [IpRecv] that returns nothing.
pub struct NullIpRecv {}

impl IpSend for MockIpSend {
    async fn send(&self, packet: Packet<Ip>) -> io::Result<()> {
        self.packets_sent.add_permits(1);

        let _ = packet;

        Ok(())
    }
}

impl IpRecv for MockIpRecv {
    async fn recv<'a>(
        &'a mut self,
        pool: &mut PacketBufPool,
    ) -> io::Result<impl Iterator<Item = Packet<Ip>> + Send + 'a> {
        self.receive_packets.acquire().await.unwrap().forget();

        let mut packet = pool.get();
        let mock_packet_bytes = self.mock_packet.deref().as_bytes();
        packet.truncate(mock_packet_bytes.len());
        packet.copy_from_slice(mock_packet_bytes);

        let packet = packet.try_into_ip().unwrap();

        Ok(iter::once(packet))
    }
}

impl IpSend for NullIpSend {
    async fn send(&self, packet: Packet<Ip>) -> io::Result<()> {
        let _ = packet;
        Ok(())
    }
}

impl IpRecv for NullIpRecv {
    async fn recv<'a>(
        &'a mut self,
        _pool: &mut PacketBufPool,
    ) -> io::Result<impl Iterator<Item = Packet<Ip>> + Send + 'a> {
        Ok(iter::once(pending().await))
    }
}

impl MockIpSend {
    pub fn new() -> Self {
        Self {
            packets_sent: Arc::new(Semaphore::new(0)),
        }
    }

    /// Wait until `count` packets have been sent.
    pub async fn wait_for(&mut self, count: usize) {
        self.packets_sent
            .acquire_many(count as u32)
            .await
            .unwrap()
            .forget();
    }
}

impl MockIpRecv {
    pub fn new(payload_len: usize) -> Self {
        let payload = b"Hello there! General Kenobi, you are a bold one. ";

        let udp_len = (UdpHeader::LEN + payload_len) as u16;
        let headers = Ipv4 {
            header: Ipv4Header::new_for_length(
                Ipv4Addr::new(1, 2, 3, 4),
                Ipv4Addr::new(4, 3, 2, 1),
                IpNextProtocol::Udp,
                udp_len,
            ),
            payload: Udp {
                header: UdpHeader {
                    source_port: 1234.into(),
                    destination_port: 4321.into(),
                    length: udp_len.into(),
                    checksum: 0.into(), // not relevant for benchmarking
                },
                payload: (),
            },
        };

        let mut packet = headers.as_bytes().to_vec();
        packet.extend(
            iter::repeat(payload.into_iter())
                .flatten()
                .take(payload_len),
        );

        let packet = Ipv4::<Udp<[u8]>>::ref_from_bytes(&packet[..]).unwrap();

        let mock_packet = Arc::new(Packet::copy_from(packet));

        Self {
            mock_packet,
            receive_packets: Arc::new(Semaphore::new(0)),
        }
    }

    /// Trigger `count` number of packets to be received on this [IpRecv].
    ///
    /// Think of this as "sending" a packet to a TUN device, the packet will be "received" by
    /// the wireguard client.
    pub fn add_packets(&self, count: usize) {
        self.receive_packets.add_permits(count);
    }
}
