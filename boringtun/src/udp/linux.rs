use nix::sys::socket::{ControlMessage, MsgFlags, MultiHeaders, SockaddrIn, SockaddrStorage};
#[cfg(target_os = "linux")]
use nix::sys::socket::{setsockopt, sockopt};
use std::{
    io::{self, IoSlice, IoSliceMut},
    net::{IpAddr, SocketAddr},
    os::fd::AsRawFd,
};
use tokio::io::Interest;

use crate::{
    packet::{Ipv4Header, Packet, Udp},
    udp::{UdpRecv, UdpSend, generic_send_many_to},
};

use super::UdpTransport;

const MAX_PACKET_RECV_COUNT: usize = 100;

// At most 64 segments can be sent at a time (https://man7.org/linux/man-pages/man7/udp.7.html)
const MAX_PACKET_SEND_COUNT: usize = 64;

// Maximum length of data passed to `sendmsg` and friends. Exceeding it results in EMSGSIZE.
const MAX_IPV4_PAYLOAD_LEN: usize = Udp::MAX_PAYLOAD_LEN - Ipv4Header::LEN;
const MAX_IPV6_PAYLOAD_LEN: usize = Udp::MAX_PAYLOAD_LEN;

#[derive(Default)]
pub struct SendmmsgBuf {}

impl UdpSend for super::UdpSocket {
    type SendManyBuf = SendmmsgBuf;

    async fn send_to(&self, packet: Packet, target: SocketAddr) -> io::Result<()> {
        tokio::net::UdpSocket::send_to(&self.inner, &packet, target).await?;
        Ok(())
    }

    async fn send_many_to(
        &self,
        _buf: &mut SendmmsgBuf,
        packets_vec: &mut Vec<(Packet, SocketAddr)>,
    ) -> io::Result<()> {
        if !self.gso {
            return generic_send_many_to(self, packets_vec).await;
        }

        let fd = self.inner.as_raw_fd();

        debug_assert!(packets_vec.len() <= MAX_PACKET_SEND_COUNT);

        let mut packets = &packets_vec[..];
        let mut io_slices = [IoSlice::new(&[]); MAX_PACKET_SEND_COUNT];

        let mut result = Ok(());

        while let Some(gso) = udp_gso_coalesce(packets, &mut io_slices) {
            packets = &packets[gso.io_slices.len()..];

            // don't throw result immediately, instead try to send all packets before returning.
            // this may result in some errors getting overwritten.
            result = self
                .inner
                .async_io(Interest::WRITABLE, || {
                    nix::sys::socket::sendmsg(
                        fd,
                        gso.io_slices,
                        &[ControlMessage::UdpGsoSegments(&gso.segment_len)],
                        MsgFlags::MSG_DONTWAIT,
                        Some(&SockaddrStorage::from(gso.addr)),
                    )?;

                    Ok(())
                })
                .await
                .inspect_err(|e| {
                    if cfg!(debug_assertions) {
                        log::warn!("sendmsg: {e}");
                    }
                });
        }

        packets_vec.clear();

        result
    }

    fn max_number_of_packets_to_send(&self) -> usize {
        MAX_PACKET_SEND_COUNT
    }
}

struct GsoCoalesce<'a> {
    segment_len: u16,
    addr: SocketAddr,
    io_slices: &'a [IoSlice<'a>],
}

/// Coalesce UDP payloads into an array of [IoSlice].
fn udp_gso_coalesce<'slice, 'packet: 'slice>(
    packets: &'packet [(Packet, SocketAddr)],
    io_slices: &'slice mut [IoSlice<'packet>; MAX_PACKET_SEND_COUNT],
) -> Option<GsoCoalesce<'slice>> {
    let ((first_packet, first_addr), packets) = packets.split_first()?;
    let segment_len = first_packet.len();

    io_slices[0] = IoSlice::new(&first_packet[..]);

    let max_total_len = match first_addr.ip() {
        IpAddr::V4(..) => MAX_IPV4_PAYLOAD_LEN,
        IpAddr::V6(..) => MAX_IPV6_PAYLOAD_LEN,
    };

    let mut count = 1;
    let mut total_len = segment_len;
    for ((packet, target), io_slice) in packets.iter().zip(&mut io_slices[1..]) {
        // consume packets as long as they have the same addr and fit in segment_len
        if target != first_addr || packet.len() > segment_len {
            break;
        }

        // don't exceed linux hard length limit
        if total_len + packet.len() > max_total_len {
            break;
        }

        *io_slice = IoSlice::new(&packet[..]);
        count += 1;
        total_len += packet.len();

        // if the packet is shorter than segment_len, let it be the last element.
        if packet.len() < segment_len {
            break;
        }
    }

    let segment_len = u16::try_from(segment_len).expect("UDP payload length is u16");

    Some(GsoCoalesce {
        segment_len,
        addr: *first_addr,
        io_slices: &io_slices[..count],
    })
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
            headers: MultiHeaders::<SockaddrIn>::preallocate(MAX_PACKET_RECV_COUNT, None),
            lengths: vec![],
        }
    }
}

impl UdpRecv for super::UdpSocket {
    type RecvManyBuf = RecvManyBuf;

    fn max_number_of_packets_to_recv(&self) -> usize {
        MAX_PACKET_RECV_COUNT
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

                let mut io_slices: [[IoSliceMut; 1]; MAX_PACKET_RECV_COUNT] =
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
