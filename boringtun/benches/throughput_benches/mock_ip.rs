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
    pub received: Arc<Semaphore>,
    pub allow_receive: Arc<Semaphore>,
}

/// An [IpRecv] that always returns the same packet.
pub struct MockIpRecv {
    pub mock_packet: Packet<Ipv4<Udp<[u8]>>>,
}

/// An [IpRecv] that does nothing.
#[derive(Clone)]
pub struct NullIpSend {}

/// An [IpRecv] that returns nothing.
pub struct NullIpRecv {}

impl IpSend for MockIpSend {
    async fn send(&self, packet: Packet<Ip>) -> io::Result<()> {
        self.allow_receive.acquire().await.unwrap().forget();
        self.received.add_permits(1);

        let _ = packet;

        Ok(())
    }
}

impl IpRecv for MockIpRecv {
    async fn recv<'a>(
        &'a mut self,
        pool: &mut PacketBufPool,
    ) -> io::Result<impl Iterator<Item = Packet<Ip>> + Send + 'a> {
        let mut packet = pool.get();
        let mock_packet_bytes = self.mock_packet.deref().as_bytes();
        packet.truncate(mock_packet_bytes.len());
        packet.copy_from_slice(mock_packet_bytes);

        let packet = packet.try_into_ip().unwrap();

        //log::debug!("mock_ip_recv");

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
            received: Arc::new(Semaphore::new(0)),
            allow_receive: Arc::new(Semaphore::new(0)),
        }
    }
    /// Wait until `count` packets have been sent.
    pub async fn wait_for(&mut self, count: usize) {
        self.allow_receive.add_permits(count);
        self.received
            .acquire_many(count as u32)
            .await
            .unwrap()
            .forget();
    }
}

impl MockIpRecv {
    pub fn new() -> Self {
        let payload = *b"hello there!";
        let udp_len = (UdpHeader::LEN + payload.len()) as u16;
        let packet = Ipv4 {
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
                payload,
            },
        };

        let packet = Ipv4::<Udp<[u8]>>::ref_from_bytes(packet.as_bytes()).unwrap();

        let mock_packet = Packet::copy_from(packet);

        Self { mock_packet }
    }
}
