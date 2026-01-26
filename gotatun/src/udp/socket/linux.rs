// Copyright (c) 2025 Mullvad VPN AB. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use nix::sys::socket::{MsgFlags, MultiHeaders, SockaddrStorage};
#[cfg(target_os = "linux")]
use nix::sys::socket::{setsockopt, sockopt};
use std::{
    io::{self, IoSlice},
    net::SocketAddr,
    os::fd::AsRawFd,
};
use tokio::io::Interest;

use crate::{
    packet::Packet,
    udp::{UdpSend, check_send_max_number_of_packets, socket::UdpSocket},
};

/// Max number of packets/messages for sendmmsg/recvmmsg
const MAX_PACKET_COUNT: usize = 100;

#[derive(Default)]
pub struct SendmmsgBuf {
    targets: Vec<Option<SockaddrStorage>>,
}

impl UdpSend for super::UdpSocket {
    type SendManyBuf = SendmmsgBuf;

    async fn send_to(&self, packet: Packet, target: SocketAddr) -> io::Result<()> {
        tokio::net::UdpSocket::send_to(&self.inner, &packet, target).await?;
        Ok(())
    }

    async fn send_many_to(
        &self,
        buf: &mut SendmmsgBuf,
        packets: &mut Vec<(Packet, SocketAddr)>,
    ) -> io::Result<()> {
        check_send_max_number_of_packets(MAX_PACKET_COUNT, packets)?;

        let fd = self.inner.as_raw_fd();

        buf.targets.clear();

        // This allocation can't be put in the struct because of lifetimes.
        // So we allocate it on the stack instead.
        let mut packets_buf = [[IoSlice::new(&[])]; MAX_PACKET_COUNT];
        for ((packet, target), packets_buf) in packets.iter().zip(&mut packets_buf) {
            buf.targets.push(Some(SockaddrStorage::from(*target)));
            *packets_buf = [IoSlice::new(&packet[..])];
        }

        let len = buf.targets.len();
        let pkts = &packets_buf[..len];
        let mut packet_buf_start = 0;
        while packet_buf_start < len {
            let result = self
                .inner
                .async_io(Interest::WRITABLE, || {
                    let mut multiheaders =
                        MultiHeaders::preallocate(pkts[packet_buf_start..].len(), None);
                    let multiresult = nix::sys::socket::sendmmsg(
                        fd,
                        &mut multiheaders,
                        &pkts[packet_buf_start..],
                        &buf.targets[packet_buf_start..],
                        [],
                        MsgFlags::MSG_DONTWAIT,
                    )?;
                    let n = multiresult.count();
                    Ok(n)
                })
                .await;
            let n = result?;
            packet_buf_start += n;
        }
        assert!(packet_buf_start == len, "all packets should be sent");
        packets.clear();

        Ok(())
    }

    fn max_number_of_packets_to_send(&self) -> usize {
        MAX_PACKET_COUNT
    }

    fn local_addr(&self) -> io::Result<Option<SocketAddr>> {
        UdpSocket::local_addr(self).map(Some)
    }

    #[cfg(target_os = "linux")]
    fn set_fwmark(&self, mark: u32) -> io::Result<()> {
        setsockopt(&self.inner, sockopt::Mark, &mark)?;
        Ok(())
    }
}

#[cfg(target_os = "linux")]
mod gro {
    /// Number of segments per message received
    const MAX_SEGMENTS: usize = 64;
    /// Size of a single UDP packet with multiple segments
    // TODO: Fix constant
    const MAX_GRO_SIZE: usize = MAX_SEGMENTS * 4096;

    use super::MAX_PACKET_COUNT;
    use crate::packet::{Packet, PacketBufPool};
    use crate::udp::{UdpRecv, socket::UdpSocket};
    use bytes::BytesMut;
    use nix::cmsg_space;
    use nix::sys::socket::{ControlMessageOwned, MsgFlags, MultiHeaders, SockaddrIn};
    use std::io::{self, IoSliceMut};
    use std::net::SocketAddr;
    use std::os::fd::AsRawFd;
    use tokio::io::Interest;

    pub struct RecvManyBuf {
        pub(crate) gro_bufs: Box<[BytesMut; MAX_PACKET_COUNT]>,
    }

    // SAFETY: MultiHeaders contains pointers, but we only ever mutate data in [Self::recv_many_from].
    // This should be fine.
    unsafe impl Send for RecvManyBuf {}

    impl Default for RecvManyBuf {
        fn default() -> Self {
            let mut gro_buf = BytesMut::zeroed(MAX_PACKET_COUNT * MAX_GRO_SIZE);
            let gro_bufs = [(); MAX_PACKET_COUNT];
            let gro_bufs = gro_bufs.map(|()| gro_buf.split_to(MAX_GRO_SIZE));
            let gro_bufs = Box::new(gro_bufs);

            Self { gro_bufs }
        }
    }

    impl UdpRecv for UdpSocket {
        type RecvManyBuf = RecvManyBuf;

        async fn recv_from(
            &mut self,
            pool: &mut PacketBufPool,
        ) -> io::Result<(Packet, SocketAddr)> {
            let mut buf = pool.get();
            let (n, src) = self.inner.recv_from(&mut buf).await?;
            buf.truncate(n);
            Ok((buf, src))
        }

        async fn recv_many_from(
            &mut self,
            recv_many_bufs: &mut Self::RecvManyBuf,
            pool: &mut PacketBufPool,
            packets: &mut Vec<(Packet, SocketAddr)>,
        ) -> io::Result<()> {
            let fd = self.inner.as_raw_fd();

            self.inner
                .async_io(Interest::READABLE, move || {
                    // TODO: the CMSG space cannot be reused, so we must allocate new headers each time
                    // [ControlMessageOwned::UdpGroSegments(i32)] contains the size of all smaller packets/segments
                    let headers = &mut MultiHeaders::<SockaddrIn>::preallocate(
                        MAX_PACKET_COUNT,
                        Some(cmsg_space!(i32)),
                    );

                    let mut io_slices: [[IoSliceMut; 1]; MAX_PACKET_COUNT] =
                        std::array::from_fn(|_| [IoSliceMut::new(&mut [])]);

                    for (i, buf) in recv_many_bufs.gro_bufs.iter_mut().enumerate() {
                        io_slices[i] = [IoSliceMut::new(&mut buf[..])];
                    }

                    let results = nix::sys::socket::recvmmsg(
                        fd,
                        headers,
                        &mut io_slices[..MAX_PACKET_COUNT],
                        MsgFlags::MSG_DONTWAIT,
                        None,
                    )?;

                    for result in results {
                        let iov = result.iovs().next().expect("we create exactly one IoSlice");

                        let Some(source_addr) = result.address.map(|addr| addr.into()) else {
                            if cfg!(debug_assertions) {
                                log::debug!("recvmmsg returned packet without source");
                            }
                            continue;
                        };

                        // TODO: is this true? Under what circumstance can the cmsg buffer overflow?
                        let mut cmsgs = result.cmsgs().expect("we have allocated enough memory");

                        let gro_size = cmsgs
                            .find_map(|cmsg| match cmsg {
                                ControlMessageOwned::UdpGroSegments(gro_size) => Some(gro_size),
                                _ => None,
                            })
                            .and_then(|gro_size| usize::try_from(gro_size).ok())
                            .filter(|&gro_size| gro_size > 0);

                        // Generic Receive Offload
                        if let Some(gro_size) = gro_size {
                            // Divide packet into GRO-sized segments and copy them into Packet bufs
                            for gro_segment in iov.chunks(gro_size) {
                                let mut buf = pool.get();
                                // TODO: consider splitting the iov backing buffer into multiple
                                // BytesMut to avoid copying the data here.
                                buf[..gro_segment.len()].copy_from_slice(gro_segment);
                                buf.truncate(gro_segment.len());

                                packets.push((buf, source_addr));
                            }
                        } else {
                            // Single packet
                            let size = result.bytes;
                            let mut buf = pool.get();
                            buf[..size].copy_from_slice(&iov[..size]);
                            buf.truncate(size);
                            packets.push((buf, source_addr));
                        }
                    }

                    Ok(())
                })
                .await?;

            Ok(())
        }

        fn enable_udp_gro(&self) -> io::Result<()> {
            // TODO: missing constants on Android
            use std::os::fd::AsFd;
            nix::sys::socket::setsockopt(
                &self.inner.as_fd(),
                nix::sys::socket::sockopt::UdpGroSegment,
                &true,
            )?;
            Ok(())
        }
    }
}

#[cfg(target_os = "android")]
mod android {
    use crate::packet::{Packet, PacketBufPool};
    use crate::udp::UdpRecv;
    use std::io;
    use std::net::SocketAddr;

    impl UdpRecv for super::UdpSocket {
        type RecvManyBuf = ();

        async fn recv_from(
            &mut self,
            pool: &mut PacketBufPool,
        ) -> io::Result<(Packet, SocketAddr)> {
            let mut buf = pool.get();
            let (n, src) = self.inner.recv_from(&mut buf).await?;
            buf.truncate(n);
            Ok((buf, src))
        }
    }
}

#[cfg(target_os = "linux")]
#[cfg(test)]
mod tests_linux {
    use bytes::BytesMut;
    use futures::future::select_all;
    use tokio::sync::Barrier;
    use tokio::task;

    use super::gro::RecvManyBuf;
    use crate::packet::{Packet, PacketBufPool};
    use crate::udp::socket::UdpSocket;
    use crate::udp::socket::linux::{MAX_PACKET_COUNT, SendmmsgBuf};
    use crate::udp::{UdpRecv, UdpSend};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::os::fd::AsFd;
    use std::sync::Arc;
    use std::sync::atomic::AtomicUsize;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_sendmmsg_partial_send() {
        //
        // Sendmmsg does not guarantee that all packets are sent in one call.
        //
        // This test simulates a scenario where multiple senders are sending packets burst to a receiver,
        // and forces the sender socket to have a small send buffer to trigger partial sends.
        //
        // Kernel stack is so fast to send packet that we need to enable `flavor = "multi_thread"` and multiple worker threads
        // to increase the chance of partial sends.
        //
        // If you go inside nix::sys::socket::sendmmsg you'll see that it returns the number of messages sent will be less than the number packets send.
        //
        // If send_to_many does not handle partial sends correctly, some packets will be lost and the test will fail.
        //
        //
        let unspecified_localhost_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let sender_sk = UdpSocket::bind(unspecified_localhost_addr).unwrap();
        let opt = nix::sys::socket::sockopt::SndBuf;
        // Sets send buffer to a tiny size to force going through partial send_mmsg
        nix::sys::socket::setsockopt(&sender_sk.as_fd(), opt, &256).unwrap();

        // To make this test more robust, we create two receivers with SO_REUSEPORT enabled
        // to allow load balancing between them.
        // otherwise there is a chance that one receiver might drop packets if the other is not ready.
        // So we create two receivers listening on the same port.
        let recv_sk = UdpSocket::bind(unspecified_localhost_addr).unwrap();
        let recv_sk_addr = recv_sk.local_addr().unwrap();

        // Sets the receve buffer to a large size to avoid packet drops,
        // Sets reuseport to allow load balance between multiple receivers
        let opt = nix::sys::socket::sockopt::RcvBuf;
        nix::sys::socket::setsockopt(&recv_sk.as_fd(), opt, &(100 * 1024 * 1024)).unwrap();
        let opt = nix::sys::socket::sockopt::ReusePort;
        nix::sys::socket::setsockopt(&recv_sk.as_fd(), opt, &true).unwrap();
        // Create a second receiver to make sure we can receive on multiple sockets with the same port
        let recv_sk2 = UdpSocket::bind(recv_sk_addr).unwrap();
        nix::sys::socket::setsockopt(&recv_sk2.as_fd(), opt, &true).unwrap();

        let random_bytes = BytesMut::zeroed(4096);
        let mut packets = Vec::with_capacity(MAX_PACKET_COUNT);
        for _ in 0..MAX_PACKET_COUNT {
            packets.push((Packet::from_bytes(random_bytes.clone()), recv_sk_addr));
        }

        // Create a lot of senders to increase the chance of partial sends
        const SENDERS: usize = 100;

        let recv_counter = Arc::new(AtomicUsize::new(0));
        // Prepare receiver task
        let mut recv_jh_vec = Vec::with_capacity(2);
        for mut recv_sk in [recv_sk, recv_sk2] {
            let recv_counter = recv_counter.clone();
            let jh = task::spawn(async move {
                let mut recv_buf = RecvManyBuf::default();
                let mut pool = PacketBufPool::<4096>::new(MAX_PACKET_COUNT);
                let mut packets = Vec::with_capacity(MAX_PACKET_COUNT);
                while recv_counter.load(std::sync::atomic::Ordering::Relaxed)
                    < MAX_PACKET_COUNT * SENDERS
                {
                    recv_sk
                        .recv_many_from(&mut recv_buf, &mut pool, &mut packets)
                        .await
                        .unwrap();
                    let received = packets.len();
                    recv_counter.fetch_add(received, std::sync::atomic::Ordering::Relaxed);
                    packets.clear();
                }
            });
            recv_jh_vec.push(jh);
        }

        let mut sender_jh_vec = Vec::with_capacity(SENDERS);
        let sender_barrier = Arc::new(Barrier::new(SENDERS + 1));
        for _ in 0..SENDERS {
            let sender_sk = sender_sk.clone();
            let mut send_buf = SendmmsgBuf::default();
            let mut packets = packets.clone();
            let my_barrier = sender_barrier.clone();
            let sender_jh = task::spawn(async move {
                my_barrier.wait().await;
                sender_sk
                    .send_many_to(&mut send_buf, &mut packets)
                    .await
                    .unwrap();
            });
            sender_jh_vec.push(sender_jh);
        }
        sender_barrier.wait().await;
        for sender_jh in sender_jh_vec {
            sender_jh.await.unwrap();
        }

        // sender_sk.send_many_to(&mut send_buf, &mut packets).await.unwrap();
        // join on first recv
        let _ = select_all(recv_jh_vec).await;
        let received_packets = recv_counter.load(std::sync::atomic::Ordering::Relaxed);
        assert_eq!(received_packets, MAX_PACKET_COUNT * SENDERS);
    }
}
