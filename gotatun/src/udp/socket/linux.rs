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

#[cfg(target_os = "linux")]
use nix::sys::socket::ControlMessage;
use nix::sys::socket::{MsgFlags, MultiHeaders, SockaddrStorage};
#[cfg(target_os = "linux")]
use nix::sys::socket::{setsockopt, sockopt};
use std::{
    io::{self, IoSlice},
    net::SocketAddr,
    os::fd::{AsRawFd, RawFd},
};
use tokio::io::Interest;

use crate::{
    packet::Packet,
    udp::{UdpSend, check_send_max_number_of_packets, socket::UdpSocket},
};

/// Max number of packets/messages for sendmmsg/recvmmsg
const MAX_PACKET_COUNT: usize = 100;

/// Maximum UDP payload length for one IPv4 datagram, accounting for IPv4 and UDP headers.
#[cfg(target_os = "linux")]
const MAX_IPV4_PAYLOAD_LEN: usize = (1 << 16) - 1 - 20 - 8;

/// Maximum UDP payload length for one IPv6 datagram, accounting for the UDP header.
#[cfg(target_os = "linux")]
const MAX_IPV6_PAYLOAD_LEN: usize = (1 << 16) - 1 - 8;

/// Kernel-imposed limit for UDP_SEGMENT datagrams in one coalesced message.
#[cfg(target_os = "linux")]
const UDP_SEGMENT_MAX_DATAGRAMS: usize = 64;

#[derive(Default)]
pub struct SendmmsgBuf {
    targets: Vec<Option<SockaddrStorage>>,
    #[cfg(target_os = "linux")]
    gso_batches: Vec<UdpGsoBatch>,
}

#[cfg(all(test, target_os = "linux"))]
impl SendmmsgBuf {
    fn gso_batches(&self) -> &[UdpGsoBatch] {
        &self.gso_batches
    }
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct UdpGsoBatch {
    start: usize,
    datagrams: usize,
    target: SocketAddr,
    segment_size: usize,
    payload_len: usize,
}

#[cfg(target_os = "linux")]
fn plan_udp_gso_batches<I>(packets: I, batches: &mut Vec<UdpGsoBatch>)
where
    I: IntoIterator<Item = (usize, SocketAddr)>,
{
    batches.clear();
    let mut end_batch = false;

    for (packet_index, (packet_len, target)) in packets.into_iter().enumerate() {
        if let Some(batch) = batches.last_mut() {
            let max_payload_len = if batch.target.is_ipv6() {
                MAX_IPV6_PAYLOAD_LEN
            } else {
                MAX_IPV4_PAYLOAD_LEN
            };
            let can_coalesce = batch.payload_len + packet_len <= max_payload_len
                && batch.segment_size != 0
                && packet_len != 0
                && packet_len <= batch.segment_size
                && batch.datagrams < UDP_SEGMENT_MAX_DATAGRAMS
                && target == batch.target
                && !end_batch;

            if can_coalesce {
                batch.payload_len += packet_len;
                batch.datagrams += 1;
                if packet_len < batch.segment_size {
                    end_batch = true;
                }
                continue;
            }
        }

        end_batch = false;
        batches.push(UdpGsoBatch {
            start: packet_index,
            datagrams: 1,
            target,
            segment_size: packet_len,
            payload_len: packet_len,
        });
    }
}

#[cfg(target_os = "linux")]
fn udp_gso_segment_size(batch: &UdpGsoBatch) -> Option<u16> {
    if batch.datagrams <= 1 || batch.segment_size == 0 {
        return None;
    }

    u16::try_from(batch.segment_size).ok()
}

#[cfg(target_os = "linux")]
fn udp_gso_control_messages(segment_size: &u16) -> [ControlMessage<'_>; 1] {
    [ControlMessage::UdpGsoSegments(segment_size)]
}

#[cfg(target_os = "linux")]
fn should_disable_udp_gso(err: &io::Error) -> bool {
    err.raw_os_error() == Some(libc::EIO)
}

struct SendBatch<'a, 'p> {
    socket: &'a tokio::net::UdpSocket,
    fd: RawFd,
    pkts: &'a [[IoSlice<'p>; 1]],
    targets: &'a [Option<SockaddrStorage>],
}

async fn send_plain_range(
    batch: &SendBatch<'_, '_>,
    mut packet_buf_start: usize,
    packet_buf_end: usize,
) -> io::Result<()> {
    while packet_buf_start < packet_buf_end {
        let result = batch
            .socket
            .async_io(Interest::WRITABLE, || {
                let mut multiheaders =
                    MultiHeaders::preallocate(packet_buf_end - packet_buf_start, None);
                let multiresult = nix::sys::socket::sendmmsg(
                    batch.fd,
                    &mut multiheaders,
                    &batch.pkts[packet_buf_start..packet_buf_end],
                    &batch.targets[packet_buf_start..packet_buf_end],
                    [],
                    MsgFlags::MSG_DONTWAIT,
                )?;
                Ok(multiresult.count())
            })
            .await;
        let n = result?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "sendmmsg sent zero UDP datagrams",
            ));
        }
        packet_buf_start += n;
    }

    Ok(())
}

#[cfg(target_os = "linux")]
async fn send_gso_segment(
    udp_socket: &super::UdpSocket,
    batch: &SendBatch<'_, '_>,
    start: usize,
    datagrams: usize,
    segment_size: u16,
) -> io::Result<()> {
    let end = start + datagrams;
    let mut segment_iovs = [IoSlice::new(&[]); UDP_SEGMENT_MAX_DATAGRAMS];
    for (dst, packet_iov) in segment_iovs.iter_mut().zip(&batch.pkts[start..end]) {
        *dst = packet_iov[0];
    }
    let segment_iovs = &segment_iovs[..datagrams];
    let cmsgs = udp_gso_control_messages(&segment_size);

    let result = batch
        .socket
        .async_io(Interest::WRITABLE, || {
            let mut multiheaders = MultiHeaders::preallocate(1, Some(nix::cmsg_space!(u16)));
            let multiresult = nix::sys::socket::sendmmsg(
                batch.fd,
                &mut multiheaders,
                [&segment_iovs],
                &batch.targets[start..start + 1],
                cmsgs,
                MsgFlags::MSG_DONTWAIT,
            )?;
            Ok(multiresult.count())
        })
        .await;

    match result {
        Ok(1) => Ok(()),
        Ok(0) => Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "sendmmsg sent zero UDP GSO segments",
        )),
        Ok(_) => unreachable!("one UDP GSO message was submitted"),
        Err(err) if should_disable_udp_gso(&err) => {
            udp_socket.disable_udp_gso();
            send_plain_range(batch, start, end).await
        }
        Err(err) => Err(err),
    }
}

#[cfg(all(test, target_os = "linux"))]
mod gso_tests {
    use super::{
        MAX_IPV4_PAYLOAD_LEN, MAX_IPV6_PAYLOAD_LEN, UDP_SEGMENT_MAX_DATAGRAMS, UdpGsoBatch,
        plan_udp_gso_batches, udp_gso_control_messages, udp_gso_segment_size,
    };
    use nix::sys::socket::ControlMessage;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

    fn target(port: u16) -> SocketAddr {
        (Ipv4Addr::LOCALHOST, port).into()
    }

    fn target_v6(port: u16) -> SocketAddr {
        (Ipv6Addr::LOCALHOST, port).into()
    }

    fn plan(packet_lens: &[usize], packet_targets: &[SocketAddr], batches: &mut Vec<UdpGsoBatch>) {
        plan_udp_gso_batches(
            packet_lens
                .iter()
                .copied()
                .zip(packet_targets.iter().copied()),
            batches,
        );
    }

    #[test]
    fn gso_plan_coalesces_equal_datagrams() {
        let mut batches = Vec::new();
        plan(
            &[1200, 1200, 1200],
            &[target(1000), target(1000), target(1000)],
            &mut batches,
        );

        assert_eq!(
            batches,
            vec![UdpGsoBatch {
                start: 0,
                datagrams: 3,
                target: target(1000),
                segment_size: 1200,
                payload_len: 3600,
            }]
        );
    }

    #[test]
    fn gso_plan_allows_short_tail_then_starts_new_batch() {
        let mut batches = Vec::new();
        plan(
            &[1200, 800, 1200],
            &[target(1000), target(1000), target(1000)],
            &mut batches,
        );

        assert_eq!(
            batches,
            vec![
                UdpGsoBatch {
                    start: 0,
                    datagrams: 2,
                    target: target(1000),
                    segment_size: 1200,
                    payload_len: 2000,
                },
                UdpGsoBatch {
                    start: 2,
                    datagrams: 1,
                    target: target(1000),
                    segment_size: 1200,
                    payload_len: 1200,
                },
            ]
        );
    }

    #[test]
    fn gso_plan_splits_at_segment_count_limit() {
        let packets = vec![1000; UDP_SEGMENT_MAX_DATAGRAMS + 1];
        let targets = vec![target(1000); packets.len()];
        let mut batches = Vec::new();
        plan(&packets, &targets, &mut batches);

        assert_eq!(
            batches,
            vec![
                UdpGsoBatch {
                    start: 0,
                    datagrams: UDP_SEGMENT_MAX_DATAGRAMS,
                    target: target(1000),
                    segment_size: 1000,
                    payload_len: 1000 * UDP_SEGMENT_MAX_DATAGRAMS,
                },
                UdpGsoBatch {
                    start: UDP_SEGMENT_MAX_DATAGRAMS,
                    datagrams: 1,
                    target: target(1000),
                    segment_size: 1000,
                    payload_len: 1000,
                },
            ]
        );
    }

    #[test]
    fn gso_plan_splits_at_ipv4_payload_limit() {
        let segment_size = MAX_IPV4_PAYLOAD_LEN / 2 + 1;
        let mut batches = Vec::new();
        plan(
            &[segment_size, segment_size],
            &[target(1000), target(1000)],
            &mut batches,
        );

        assert_eq!(
            batches,
            vec![
                UdpGsoBatch {
                    start: 0,
                    datagrams: 1,
                    target: target(1000),
                    segment_size,
                    payload_len: segment_size,
                },
                UdpGsoBatch {
                    start: 1,
                    datagrams: 1,
                    target: target(1000),
                    segment_size,
                    payload_len: segment_size,
                },
            ]
        );
    }

    #[test]
    fn gso_plan_uses_ipv6_payload_limit() {
        let segment_size = MAX_IPV6_PAYLOAD_LEN / 2;
        let packet_lens = [segment_size, segment_size, 2];
        let packet_targets = [target_v6(1000), target_v6(1000), target_v6(1000)];
        let mut batches = Vec::new();

        plan(&packet_lens, &packet_targets, &mut batches);

        assert_eq!(
            batches,
            vec![
                UdpGsoBatch {
                    start: 0,
                    datagrams: 2,
                    target: target_v6(1000),
                    segment_size,
                    payload_len: segment_size * 2,
                },
                UdpGsoBatch {
                    start: 2,
                    datagrams: 1,
                    target: target_v6(1000),
                    segment_size: 2,
                    payload_len: 2,
                },
            ]
        );
    }

    #[test]
    fn gso_plan_splits_at_destination_changes() {
        let mut batches = Vec::new();
        plan(
            &[1200, 1200, 1200],
            &[target(1000), target(2000), target(2000)],
            &mut batches,
        );

        assert_eq!(
            batches,
            vec![
                UdpGsoBatch {
                    start: 0,
                    datagrams: 1,
                    target: target(1000),
                    segment_size: 1200,
                    payload_len: 1200,
                },
                UdpGsoBatch {
                    start: 1,
                    datagrams: 2,
                    target: target(2000),
                    segment_size: 1200,
                    payload_len: 2400,
                },
            ]
        );
    }

    #[test]
    fn gso_plan_does_not_coalesce_zero_length_datagrams() {
        let mut batches = Vec::new();
        plan(
            &[1200, 0, 1200, 0],
            &[target(1000), target(1000), target(1000), target(1000)],
            &mut batches,
        );

        assert_eq!(
            batches,
            vec![
                UdpGsoBatch {
                    start: 0,
                    datagrams: 1,
                    target: target(1000),
                    segment_size: 1200,
                    payload_len: 1200,
                },
                UdpGsoBatch {
                    start: 1,
                    datagrams: 1,
                    target: target(1000),
                    segment_size: 0,
                    payload_len: 0,
                },
                UdpGsoBatch {
                    start: 2,
                    datagrams: 1,
                    target: target(1000),
                    segment_size: 1200,
                    payload_len: 1200,
                },
                UdpGsoBatch {
                    start: 3,
                    datagrams: 1,
                    target: target(1000),
                    segment_size: 0,
                    payload_len: 0,
                },
            ]
        );
    }

    #[test]
    fn gso_plan_splits_at_address_family_changes() {
        let mut batches = Vec::new();
        plan(
            &[1200, 1200, 1200, 1200],
            &[target(1000), target(1000), target_v6(1000), target_v6(1000)],
            &mut batches,
        );

        assert_eq!(
            batches,
            vec![
                UdpGsoBatch {
                    start: 0,
                    datagrams: 2,
                    target: target(1000),
                    segment_size: 1200,
                    payload_len: 2400,
                },
                UdpGsoBatch {
                    start: 2,
                    datagrams: 2,
                    target: target_v6(1000),
                    segment_size: 1200,
                    payload_len: 2400,
                },
            ]
        );
    }

    #[test]
    fn gso_segment_size_only_emits_for_coalesced_batches() {
        assert_eq!(
            udp_gso_segment_size(&UdpGsoBatch {
                start: 0,
                datagrams: 3,
                target: target(1000),
                segment_size: 1200,
                payload_len: 3200,
            }),
            Some(1200)
        );
        assert_eq!(
            udp_gso_segment_size(&UdpGsoBatch {
                start: 3,
                datagrams: 1,
                target: target(1000),
                segment_size: 1200,
                payload_len: 1200,
            }),
            None
        );
        assert_eq!(
            udp_gso_segment_size(&UdpGsoBatch {
                start: 4,
                datagrams: 2,
                target: target(1000),
                segment_size: 0,
                payload_len: 0,
            }),
            None
        );
    }

    #[test]
    fn gso_segment_size_rejects_oversized_segment() {
        assert_eq!(
            udp_gso_segment_size(&UdpGsoBatch {
                start: 0,
                datagrams: 2,
                target: target(1000),
                segment_size: usize::from(u16::MAX) + 1,
                payload_len: (usize::from(u16::MAX) + 1) * 2,
            }),
            None
        );
    }

    #[test]
    fn udp_gso_control_message_uses_udp_segment_size() {
        let segment_size = 1200;
        let [cmsg] = udp_gso_control_messages(&segment_size);

        assert_eq!(cmsg, ControlMessage::UdpGsoSegments(&segment_size));
    }

    #[test]
    fn eio_disables_udp_gso() {
        let error = std::io::Error::from_raw_os_error(libc::EIO);
        assert!(super::should_disable_udp_gso(&error));

        let error = std::io::Error::from_raw_os_error(libc::ECONNREFUSED);
        assert!(!super::should_disable_udp_gso(&error));
    }

    #[tokio::test]
    async fn send_many_to_records_reusable_gso_plan() {
        use crate::packet::PacketBufPool;
        use crate::udp::UdpSend;
        use crate::udp::socket::SockOpt;
        use std::net::{Ipv4Addr, SocketAddr};
        use std::time::Duration;

        let socket = crate::udp::socket::UdpSocket::bind(
            (Ipv4Addr::LOCALHOST, 0).into(),
            SockOpt::default(),
        )
        .unwrap();
        let receiver = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let target: SocketAddr = receiver.local_addr().unwrap();
        let pool = PacketBufPool::<4096>::new(4);
        let mut send_buf = super::SendmmsgBuf::default();
        let mut packets = [1200usize, 1200, 800]
            .into_iter()
            .map(|len| {
                let mut packet = pool.get();
                packet.truncate(len);
                packet.fill(0x42);
                (packet, target)
            })
            .collect();

        socket
            .send_many_to(&mut send_buf, &mut packets)
            .await
            .unwrap();

        assert!(packets.is_empty());
        assert_eq!(
            send_buf.gso_batches(),
            &[UdpGsoBatch {
                start: 0,
                datagrams: 3,
                target,
                segment_size: 1200,
                payload_len: 3200,
            }]
        );

        receiver
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let mut received_lens = Vec::new();
        let mut recv_buf = vec![0u8; 1200];
        for _ in 0..3 {
            let (len, from) = receiver.recv_from(&mut recv_buf).unwrap();
            assert_eq!(from, socket.local_addr().unwrap());
            received_lens.push(len);
        }
        assert_eq!(received_lens, vec![1200, 1200, 800]);
    }

    #[tokio::test]
    async fn send_many_to_records_ipv6_gso_plan() {
        use crate::packet::PacketBufPool;
        use crate::udp::UdpSend;
        use crate::udp::socket::SockOpt;
        use std::time::Duration;

        let socket = crate::udp::socket::UdpSocket::bind(
            (Ipv6Addr::LOCALHOST, 0).into(),
            SockOpt::default(),
        )
        .unwrap();
        let receiver = std::net::UdpSocket::bind((Ipv6Addr::LOCALHOST, 0)).unwrap();
        let target: SocketAddr = receiver.local_addr().unwrap();
        let pool = PacketBufPool::<4096>::new(4);
        let mut send_buf = super::SendmmsgBuf::default();
        let mut packets = [900usize, 900, 700]
            .into_iter()
            .map(|len| {
                let mut packet = pool.get();
                packet.truncate(len);
                packet.fill(0x24);
                (packet, target)
            })
            .collect();

        socket
            .send_many_to(&mut send_buf, &mut packets)
            .await
            .unwrap();

        assert!(packets.is_empty());
        assert_eq!(
            send_buf.gso_batches(),
            &[UdpGsoBatch {
                start: 0,
                datagrams: 3,
                target,
                segment_size: 900,
                payload_len: 2500,
            }]
        );

        receiver
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let mut received_lens = Vec::new();
        let mut recv_buf = vec![0u8; 900];
        for _ in 0..3 {
            let (len, from) = receiver.recv_from(&mut recv_buf).unwrap();
            assert_eq!(from, socket.local_addr().unwrap());
            received_lens.push(len);
        }
        assert_eq!(received_lens, vec![900, 900, 700]);
    }
}

impl UdpSend for super::UdpSocket {
    type SendManyBuf = SendmmsgBuf;

    async fn send_to(&self, packet: Packet, target: SocketAddr) -> io::Result<()> {
        tokio::net::UdpSocket::send_to(self.socket()?, &packet, target).await?;
        Ok(())
    }

    async fn send_many_to(
        &self,
        buf: &mut SendmmsgBuf,
        packets: &mut Vec<(Packet, SocketAddr)>,
    ) -> io::Result<()> {
        check_send_max_number_of_packets(MAX_PACKET_COUNT, packets)?;

        let socket = self.socket()?;
        let fd = socket.as_raw_fd();

        buf.targets.clear();

        // This allocation can't be put in the struct because of lifetimes.
        // So we allocate it on the stack instead.
        let mut packets_buf = [[IoSlice::new(&[])]; MAX_PACKET_COUNT];
        for ((packet, target), packets_buf) in packets.iter().zip(&mut packets_buf) {
            buf.targets.push(Some(SockaddrStorage::from(*target)));
            *packets_buf = [IoSlice::new(&packet[..])];
        }

        let pkts = &packets_buf[..buf.targets.len()];
        let batch = SendBatch {
            socket,
            fd,
            pkts,
            targets: &buf.targets,
        };

        #[cfg(target_os = "linux")]
        {
            plan_udp_gso_batches(
                packets
                    .iter()
                    .map(|(packet, target)| (packet.len(), *target)),
                &mut buf.gso_batches,
            );

            if self.udp_gso_supported() && !self.udp_gso_disabled() {
                let mut plain_start = None;

                for gso_batch in &buf.gso_batches {
                    let Some(segment_size) = udp_gso_segment_size(gso_batch) else {
                        plain_start.get_or_insert(gso_batch.start);
                        continue;
                    };

                    if let Some(start) = plain_start.take() {
                        send_plain_range(&batch, start, gso_batch.start).await?;
                    }

                    if self.udp_gso_disabled() {
                        send_plain_range(
                            &batch,
                            gso_batch.start,
                            gso_batch.start + gso_batch.datagrams,
                        )
                        .await?;
                    } else {
                        send_gso_segment(
                            self,
                            &batch,
                            gso_batch.start,
                            gso_batch.datagrams,
                            segment_size,
                        )
                        .await?;
                    }
                }

                if let Some(start) = plain_start {
                    send_plain_range(&batch, start, buf.targets.len()).await?;
                }
            } else {
                send_plain_range(&batch, 0, buf.targets.len()).await?;
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            send_plain_range(&batch, 0, buf.targets.len()).await?;
        }
        packets.clear();

        Ok(())
    }

    fn max_number_of_packets_to_send(&self) -> usize {
        MAX_PACKET_COUNT
    }

    fn local_addr(&self) -> io::Result<Option<SocketAddr>> {
        #[cfg(target_os = "linux")]
        if self.is_disabled_ipv6() {
            return Ok(None);
        }

        UdpSocket::local_addr(self).map(Some)
    }

    #[cfg(target_os = "linux")]
    fn set_fwmark(&self, mark: u32) -> io::Result<()> {
        if self.is_disabled_ipv6() {
            return Ok(());
        }

        setsockopt(self.socket()?, sockopt::Mark, &mark)?;
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

    use super::super::disabled_ipv6_error;
    use super::MAX_PACKET_COUNT;
    use crate::packet::{Packet, PacketBufPool};
    use crate::udp::{UdpRecv, socket::UdpSocket};
    use bytes::BytesMut;
    use nix::cmsg_space;
    use nix::sys::socket::{ControlMessageOwned, MsgFlags, MultiHeaders, SockaddrStorage};
    use std::io::{self, IoSliceMut};
    use std::net::SocketAddr;
    use std::os::fd::AsRawFd;
    use tokio::io::Interest;

    pub struct RecvManyBuf {
        pub(crate) gro_bufs: Box<[BytesMut; MAX_PACKET_COUNT]>,
    }

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
            if self.is_disabled_ipv6() {
                return Err(disabled_ipv6_error());
            }

            let mut buf = pool.get();
            let (n, src) = self.socket()?.recv_from(&mut buf).await?;
            buf.truncate(n);
            Ok((buf, src))
        }

        async fn recv_many_from(
            &mut self,
            recv_many_bufs: &mut Self::RecvManyBuf,
            pool: &mut PacketBufPool,
            packets: &mut Vec<(Packet, SocketAddr)>,
        ) -> io::Result<()> {
            if self.is_disabled_ipv6() {
                return Err(disabled_ipv6_error());
            }

            let socket = self.socket()?;
            let fd = socket.as_raw_fd();

            socket
                .async_io(Interest::READABLE, move || {
                    // TODO: the CMSG space cannot be reused, so we must allocate new headers each
                    // time [ControlMessageOwned::UdpGroSegments(i32)] contains
                    // the size of all smaller packets/segments
                    // Use a generic sockaddr storage here because this path serves both the IPv4
                    // and IPv6 UDP sockets. Using `SockaddrIn` corrupts IPv6 source addresses and
                    // can poison the peer runtime endpoint with an unspecified IPv4 address.
                    let headers = &mut MultiHeaders::<SockaddrStorage>::preallocate(
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

                        let Some(source_addr) = result.address.as_ref().and_then(|addr| {
                            addr.as_sockaddr_in()
                                .map(|addr| (*addr).into())
                                .or_else(|| addr.as_sockaddr_in6().map(|addr| (*addr).into()))
                        }) else {
                            if cfg!(debug_assertions) {
                                tracing::debug!("recvmmsg returned packet without source");
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
                                // Copy the segment into a packet buffer, growing the buffer if the
                                // segment is larger than the pool's buffer size.
                                // TODO: consider splitting the iov backing buffer into multiple
                                // BytesMut to avoid copying the data here.
                                buf.buf_mut().clear();
                                buf.buf_mut().extend_from_slice(gro_segment);
                                packets.push((buf, source_addr));
                            }
                        } else {
                            // Single packet
                            let size = result.bytes;
                            let mut buf = pool.get();
                            // Copy the datagram into a packet buffer, growing the buffer if the
                            // datagram is larger than the pool's buffer size (reachable via IP
                            // fragment reassembly, up to 64k).
                            buf.buf_mut().clear();
                            buf.buf_mut().extend_from_slice(&iov[..size]);
                            packets.push((buf, source_addr));
                        }
                    }

                    Ok(())
                })
                .await?;

            Ok(())
        }

        fn enable_udp_gro(&self) -> io::Result<()> {
            if self.is_disabled_ipv6() {
                return Ok(());
            }

            // TODO: missing constants on Android
            use std::os::fd::AsFd;
            nix::sys::socket::setsockopt(
                &self.socket()?.as_fd(),
                nix::sys::socket::sockopt::UdpGroSegment,
                &true,
            )?;
            Ok(())
        }
    }

    #[cfg(test)]
    mod tests {
        use super::UdpSocket;
        use crate::packet::{Packet, PacketBufPool};
        use crate::udp::socket::SockOpt;
        use crate::udp::{UdpRecv, UdpSend};
        use std::net::{Ipv6Addr, SocketAddr};
        use std::time::Duration;

        #[tokio::test]
        async fn recv_many_from_preserves_ipv6_source_addr() {
            let mut receiver =
                UdpSocket::bind((Ipv6Addr::LOCALHOST, 0).into(), SockOpt::default()).unwrap();
            receiver.enable_udp_gro().ok();
            let sender =
                UdpSocket::bind((Ipv6Addr::LOCALHOST, 0).into(), SockOpt::default()).unwrap();

            let recv_addr = receiver.local_addr().unwrap();
            let sender_addr = sender.local_addr().unwrap();

            let send_pool = PacketBufPool::<4096>::new(1);
            let mut packet = send_pool.get();
            packet.truncate(5);
            packet.copy_from_slice(b"hello");
            sender.send_to(packet, recv_addr).await.unwrap();

            let mut recv_pool = PacketBufPool::<4096>::new(1);
            let mut recv_many_buf = <UdpSocket as UdpRecv>::RecvManyBuf::default();
            let mut packets = vec![];

            tokio::time::timeout(
                Duration::from_secs(1),
                receiver.recv_many_from(&mut recv_many_buf, &mut recv_pool, &mut packets),
            )
            .await
            .unwrap()
            .unwrap();

            assert!(!packets.is_empty(), "expected at least one IPv6 packet");
            assert_eq!(packets[0].1, sender_addr);
        }

        // A datagram larger than the pool buffer must be received in full by growing
        // the target buffer, not dropped or truncated.
        //
        // Note: a single datagram is not GRO-coalesced, so this exercises the non-GRO
        // receive branch. The GRO branch (segments larger than the buffer) is not
        // covered here - UDP GRO does not engage on loopback.
        #[tokio::test]
        async fn recv_many_from_grows_for_oversized_datagram() {
            let mut receiver =
                UdpSocket::bind((Ipv6Addr::LOCALHOST, 0).into(), SockOpt::default()).unwrap();
            receiver.enable_udp_gro().ok();
            let recv_addr = receiver.local_addr().unwrap();

            // 10000 bytes is larger than the 4096-byte pool buffer.
            let payload = vec![0xABu8; 10_000];
            let sender = std::net::UdpSocket::bind((Ipv6Addr::LOCALHOST, 0)).unwrap();
            sender.send_to(&payload, recv_addr).unwrap();

            let mut recv_pool = PacketBufPool::<4096>::new(1);
            let mut recv_many_buf = <UdpSocket as UdpRecv>::RecvManyBuf::default();
            let mut packets: Vec<(Packet, SocketAddr)> = Vec::new();

            // The datagram is already buffered, so a single read returns it.
            tokio::time::timeout(
                Duration::from_secs(1),
                receiver.recv_many_from(&mut recv_many_buf, &mut recv_pool, &mut packets),
            )
            .await
            .unwrap()
            .unwrap();

            assert_eq!(packets.len(), 1, "expected exactly one packet");
            let (packet, _) = &packets[0];
            assert_eq!(
                packet.len(),
                payload.len(),
                "oversized datagram must be received in full, not dropped or truncated"
            );
            assert_eq!(
                &packet[..],
                &payload[..],
                "datagram must retain same content"
            );
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
            let (n, src) = self.socket()?.recv_from(&mut buf).await?;
            buf.truncate(n);
            Ok((buf, src))
        }
    }
}
