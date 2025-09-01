/// Implementations of [IpSend] and [IpRecv] for the [::tun] crate.
use super::*;
use std::sync::Arc;

#[cfg(any(target_os = "linux", target_os = "android"))]
mod tso;
use bytes::BytesMut;
#[cfg(any(target_os = "linux", target_os = "android"))]
pub use tso::try_enable_tso;
use zerocopy::IntoBytes;

#[allow(dead_code)] // TODO
#[cfg(any(target_os = "linux", target_os = "android"))]
mod virtio;

// TODO
const VNET_HDR: bool = true;

impl IpSend for Arc<::tun::AsyncDevice> {
    async fn send(&mut self, packet: Packet<Ip>) -> io::Result<()> {
        let mut packet = packet.into_bytes();

        if VNET_HDR {
            let header = virtio::VirtioNetHeader {
                flags: virtio::Flags::new(),
                gso_type: virtio::GsoType::VIRTIO_NET_HDR_GSO_NONE,
                hdr_len: 0,
                gso_size: 0,
                csum_start: 0,
                csum_offset: 0,
            };
            let mut buf = BytesMut::new();
            buf.extend_from_slice(header.as_bytes());
            buf.extend_from_slice(packet.as_bytes());
            *packet.buf_mut() = buf;
        }

        ::tun::AsyncDevice::send(self, &packet.into_bytes()).await?;
        Ok(())
    }
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
impl IpRecv for Arc<::tun::AsyncDevice> {
    async fn recv<'a>(
        &'a mut self,
        pool: &mut PacketBufPool,
    ) -> io::Result<impl Iterator<Item = Packet<Ip>> + 'a> {
        let mut packet = pool.get();
        let n = ::tun::AsyncDevice::recv(self.as_ref(), &mut packet).await?;
        packet.truncate(n);

        packet
            .try_into_ip()
            .map_err(|e| io::Error::other(e.to_string()))
            .map(std::iter::once)
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
impl IpRecv for Arc<::tun::AsyncDevice> {
    async fn recv<'a>(
        &'a mut self,
        pool: &mut PacketBufPool,
    ) -> io::Result<impl Iterator<Item = Packet<Ip>> + 'a> {
        use bytes::BytesMut;
        use either::Either;
        use zerocopy::FromBytes;

        use crate::tun::tun_async_device::virtio::VirtioNetHeader;

        // FIXME: pool buffers have a cap of 4096, but we need more
        //let mut packet = pool.get();
        let _ = pool;

        let mut buf = BytesMut::zeroed(usize::from(u16::MAX));
        let n = ::tun::AsyncDevice::recv(self.as_ref(), &mut buf).await?;
        buf.truncate(n);

        let vnet_hdr = buf.split_to(size_of::<VirtioNetHeader>());
        let vnet_hdr = *VirtioNetHeader::ref_from_bytes(&vnet_hdr).unwrap();

        let packet = Packet::from_bytes(buf)
            .try_into_ipvx()
            .map_err(|e| io::Error::other(e.to_string()))?;

        // TODO
        let mtu = 1200;

        // TODO: if segmentation and checksum offload is disabled,
        // we could take a more efficient branch where we do not need to check
        // packet length, and whether it's an IP/TCP packet.
        match packet {
            Either::Left(ipv4_packet) => {
                tso::new_tso_iter_ipv4(ipv4_packet, usize::from(vnet_hdr.gso_size))
            }
            Either::Right(ipv6_packet) => {
                tso::new_tso_iter_ipv6(ipv6_packet, usize::from(vnet_hdr.gso_size))
            }
        }
    }
}
