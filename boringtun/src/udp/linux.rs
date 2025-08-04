use nix::sys::socket::{MsgFlags, MultiHeaders, SockaddrIn, SockaddrStorage};
#[cfg(target_os = "linux")]
use nix::sys::socket::{setsockopt, sockopt};
use std::{
    io::{self, IoSlice, IoSliceMut},
    net::SocketAddr,
    os::fd::AsRawFd,
};
use tokio::io::Interest;

use crate::{
    packet::Packet,
    udp::{UdpRecv, UdpSend},
};

use super::UdpTransport;

const MAX_PACKET_COUNT: usize = 100;

#[derive(Default)]
pub struct SendmmsgBuf {
    targets: Vec<Option<SockaddrStorage>>,
}

impl UdpSend for super::UdpSocket {
    type SendManyBuf = SendmmsgBuf;

    async fn send_to(&self, packet: Packet, target: SocketAddr) -> io::Result<()> {
        //log::debug!("send_to {target}");
        tokio::net::UdpSocket::send_to(&self.inner, &packet, target).await?;
        Ok(())
    }

    async fn send_many_to(
        &self,
        buf: &mut SendmmsgBuf,
        packets: &mut Vec<(Packet, SocketAddr)>,
    ) -> io::Result<()> {
        let n = packets.len();
        debug_assert!(n <= MAX_PACKET_COUNT);

        let fd = self.inner.as_raw_fd();

        buf.targets.clear();
        packets
            .iter()
            //.inspect(|(_, target)| log::debug!("send_many_to {target}"))
            .map(|(_packet, target)| Some(SockaddrStorage::from(*target)))
            .for_each(|target| buf.targets.push(target));

        // This allocation can't be put in the struct because of lifetimes.
        // So we allocate it on the stack instead.
        let mut packets_buf = [[IoSlice::new(&[])]; MAX_PACKET_COUNT];
        packets
            .iter()
            .map(|(packet, _target)| [IoSlice::new(&packet[..])])
            .enumerate()
            // packets.len() is no greater than MAX_PACKET_COUNT
            .for_each(|(i, packet)| packets_buf[i] = packet);
        let pkts = &packets_buf[..n];

        self.inner
            .async_io(Interest::WRITABLE, || {
                let mut multiheaders = MultiHeaders::preallocate(pkts.len(), None);
                nix::sys::socket::sendmmsg(
                    fd,
                    &mut multiheaders,
                    pkts,
                    &buf.targets[..],
                    [],
                    MsgFlags::MSG_DONTWAIT,
                )?;

                Ok(())
            })
            .await?;

        packets.clear();

        Ok(())
    }

    fn max_number_of_packets_to_send(&self) -> usize {
        MAX_PACKET_COUNT
    }
}

pub struct RecvManyBuf {
    headers: MultiHeaders<SockaddrIn>,
    lengths: Vec<usize>,
}

// SAFETY: MultiHeaders contains pointers, but we only ever mutate data in [Self::recv_many_from].
// This should be fine.
unsafe impl Send for RecvManyBuf {}

impl Default for RecvManyBuf {
    fn default() -> Self {
        Self {
            headers: MultiHeaders::<SockaddrIn>::preallocate(MAX_PACKET_COUNT, None),
            lengths: vec![],
        }
    }
}

impl UdpRecv for super::UdpSocket {
    type RecvManyBuf = RecvManyBuf;

    fn max_number_of_packets_to_recv(&self) -> usize {
        MAX_PACKET_COUNT
    }

    async fn recv_from(&mut self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        tokio::net::UdpSocket::recv_from(&self.inner, buf).await
    }

    async fn recv_many_from(
        &mut self,
        recv_many_bufs: &mut Self::RecvManyBuf,
        bufs: &mut [Packet],
        source_addrs: &mut [Option<SocketAddr>],
    ) -> io::Result<usize> {
        debug_assert_eq!(bufs.len(), source_addrs.len());

        let fd = self.inner.as_raw_fd();

        let num_bufs = self
            .inner
            .async_io(Interest::READABLE, move || {
                let headers = &mut recv_many_bufs.headers;

                let mut io_slices: [[IoSliceMut; 1]; MAX_PACKET_COUNT] =
                    std::array::from_fn(|_| [IoSliceMut::new(&mut [])]);

                let num_packets = bufs.len();
                bufs.iter_mut()
                    .enumerate()
                    .for_each(|(i, packet)| io_slices[i] = [IoSliceMut::new(&mut packet[..])]);

                let results = nix::sys::socket::recvmmsg(
                    fd,
                    headers,
                    &mut io_slices[..num_packets],
                    MsgFlags::MSG_DONTWAIT,
                    None,
                )?;

                recv_many_bufs
                    .lengths
                    .extend(
                        results
                            .zip(source_addrs.iter_mut())
                            .map(|(result, out_addr)| {
                                *out_addr = result.address.map(|addr| addr.into());
                                result.bytes
                            }),
                    );

                let num_bufs = recv_many_bufs.lengths.len();

                for (buf, length) in bufs.iter_mut().zip(recv_many_bufs.lengths.drain(..)) {
                    buf.truncate(length);
                }

                Ok(num_bufs)
            })
            .await?;

        Ok(num_bufs)
    }
}

impl UdpTransport for super::UdpSocket {
    fn local_addr(&self) -> io::Result<Option<SocketAddr>> {
        super::UdpSocket::local_addr(self).map(Some)
    }

    #[cfg(target_os = "linux")]
    fn set_fwmark(&self, mark: u32) -> io::Result<()> {
        setsockopt(&self.inner, sockopt::Mark, &mark)?;
        Ok(())
    }
}
