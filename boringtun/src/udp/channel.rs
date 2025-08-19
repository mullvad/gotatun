use bytes::BytesMut;
use either::Either;
use pnet_packet::ip::IpNextHeaderProtocols;
use rand_core::RngCore;
use std::{
    io, iter,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{Arc, atomic::AtomicU16},
};
use tokio::sync::{Mutex, mpsc};
use zerocopy::{FromBytes, IntoBytes};

use crate::{
    packet::{
        Ip, IpNextProtocol, Ipv4, Ipv4Header, Ipv6, Packet, PacketBufPool, TryIntoUdpResult, Udp,
    },
    tun::{IpRecv, IpSend},
    udp::{UdpRecv, UdpSend, UdpTransport, UdpTransportFactory},
};

use super::UdpTransportFactoryParams;
pub use fragmentation::Ipv4Fragments;

/// An implementation of [IpRecv] using tokio channels.
///
/// Enables connecting one [Device](crate::device::Device) directly to another.
/// Can be used to set up a multi-hop wireguard tunnel.
pub struct TunChannelRx {
    tun_rx: mpsc::Receiver<Packet<Ip>>,
}

/// An implementation of [IpSend] using tokio channels.
///
/// Enables connecting one [Device](crate::device::Device) directly to another.
/// Can be used to set up a multi-hop wireguard tunnel.
pub struct TunChannelTx {
    tun_tx_v4: mpsc::Sender<Packet<Ipv4<Udp>>>,
    tun_tx_v6: mpsc::Sender<Packet<Ipv6<Udp>>>,

    /// A map of fragments, keyed by a tuple of (identification, source IP, destination IP).
    /// The value is a BTreeMap of fragment offsets to the corresponding fragments.
    /// The BTreeMap is used to ensure that fragments are kept in order, even if they arrive out of
    /// order. This is used to efficiently check if all fragments have been received.
    fragments_v4: Ipv4Fragments,
    // TODO: Ipv6 fragments?
}

#[derive(Clone)]
pub struct UdpChannelTx {
    source_ip_v4: Ipv4Addr,
    source_ip_v6: Ipv6Addr,
    source_port: u16,
    connection_id: u32,

    udp_tx: mpsc::Sender<Packet<Ip>>,
}

pub struct UdpChannelV4Rx {
    udp_rx_v4: Arc<Mutex<mpsc::Receiver<Packet<Ipv4<Udp>>>>>,
}

pub struct UdpChannelV6Rx {
    udp_rx_v6: Arc<Mutex<mpsc::Receiver<Packet<Ipv6<Udp>>>>>,
}

pub struct PacketChannelUdp {
    source_ip_v4: Ipv4Addr,
    source_ip_v6: Ipv6Addr,

    // FIXME: remove Mutexes
    udp_tx: mpsc::Sender<Packet<Ip>>,
    udp_rx_v4: Arc<Mutex<mpsc::Receiver<Packet<Ipv4<Udp>>>>>,
    udp_rx_v6: Arc<Mutex<mpsc::Receiver<Packet<Ipv6<Udp>>>>>,
}

pub fn get_packet_channels(
    capacity: usize,
    source_ip_v4: Ipv4Addr,
    source_ip_v6: Ipv6Addr,
) -> (TunChannelTx, TunChannelRx, PacketChannelUdp) {
    let (udp_tx, tun_rx) = mpsc::channel(capacity);
    let (tun_tx_v4, udp_rx_v4) = mpsc::channel(capacity);
    let (tun_tx_v6, udp_rx_v6) = mpsc::channel(capacity);
    let tun_tx = TunChannelTx {
        tun_tx_v4,
        tun_tx_v6,

        fragments_v4: Ipv4Fragments::default(),
    };
    let tun_rx = TunChannelRx { tun_rx };
    let udp_channel_factory = PacketChannelUdp {
        source_ip_v4,
        source_ip_v6,
        udp_tx,
        udp_rx_v4: Arc::new(Mutex::new(udp_rx_v4)),
        udp_rx_v6: Arc::new(Mutex::new(udp_rx_v6)),
    };
    (tun_tx, tun_rx, udp_channel_factory)
}

impl IpSend for TunChannelTx {
    async fn send(&mut self, packet: Packet<Ip>) -> io::Result<()> {
        let ip_packet = match packet.try_into_ipvx() {
            Ok(p) => p,
            Err(e) => {
                log::trace!("Invalid IP packet: {e:?}");
                return Ok(());
            }
        };

        match ip_packet {
            Either::Left(ipv4) => {
                match ipv4.try_into_udp() {
                    Ok(TryIntoUdpResult::UdpFragment(ip_fragment)) => {
                        // Check if the packet is a fragment
                        if let Some(complete_ipv4) =
                            self.fragments_v4.assemble_ipv4_fragment(ip_fragment)
                            && let Ok(TryIntoUdpResult::Udp(udp_packet)) =
                                complete_ipv4.try_into_udp()
                        {
                            self.tun_tx_v4
                                .send(udp_packet)
                                .await
                                .expect("receiver exists");
                        }
                    }
                    Ok(TryIntoUdpResult::Udp(udp_packet)) => {
                        self.tun_tx_v4
                            .send(udp_packet)
                            .await
                            .expect("receiver exists");
                    }
                    Err(e) => log::trace!("Invalid UDP packet: {e:?}"),
                }
            }
            Either::Right(ipv6) => match ipv6.try_into_udp() {
                Ok(udp_packet) => {
                    self.tun_tx_v6
                        .send(udp_packet)
                        .await
                        .expect("receiver exists");
                }
                Err(e) => log::trace!("Invalid UDP packet: {e:?}"),
            },
        }

        Ok(())
    }
}

impl IpRecv for TunChannelRx {
    async fn recv<'a>(
        &'a mut self,
        _pool: &mut PacketBufPool,
    ) -> io::Result<impl Iterator<Item = Packet<Ip>> + Send + 'a> {
        let Some(packet) = self.tun_rx.recv().await else {
            tracing::trace!("tun_rx sender dropped and no more packet can be received");
            let () = std::future::pending().await;
            unreachable!();
        };
        Ok(iter::once(packet))
    }
}

impl UdpTransportFactory for PacketChannelUdp {
    type Send = UdpChannelTx;
    type RecvV4 = UdpChannelV4Rx;
    type RecvV6 = UdpChannelV6Rx;

    async fn bind(
        &mut self,
        params: &UdpTransportFactoryParams,
    ) -> io::Result<((Self::Send, Self::RecvV4), (Self::Send, Self::RecvV6))> {
        let connection_id = rand_core::OsRng.next_u32().max(1);
        let source_port = match params.port {
            0 => rand_u16().max(1),
            p => p,
        };

        let channel_tx = UdpChannelTx {
            source_ip_v4: self.source_ip_v4,
            source_ip_v6: self.source_ip_v6,
            source_port,
            connection_id,
            udp_tx: self.udp_tx.clone(),
        };

        let channel_rx_v4 = UdpChannelV4Rx {
            udp_rx_v4: self.udp_rx_v4.clone(),
        };
        let channel_rx_v6 = UdpChannelV6Rx {
            udp_rx_v6: self.udp_rx_v6.clone(),
        };
        Ok((
            (channel_tx.clone(), channel_rx_v4),
            (channel_tx, channel_rx_v6),
        ))
    }
}

const UDP_HEADER_LEN: usize = 8;
const IPV4_HEADER_LEN: usize = 20;
const IPV6_HEADER_LEN: usize = 40;

impl UdpTransport for UdpChannelTx {}

impl UdpSend for UdpChannelTx {
    type SendManyBuf = ();

    async fn send_to(&self, udp_payload: Packet, destination: SocketAddr) -> io::Result<()> {
        // send an IP packet on the channel.
        // the IP and UDP headers will need to be added to `udp_payload`

        match destination {
            SocketAddr::V4(dest) => {
                self.udp_tx
                    .send(
                        create_ipv4_payload(
                            self.source_ip_v4,
                            self.source_port,
                            *dest.ip(),
                            dest.port(),
                            &udp_payload,
                        )
                        .await,
                    )
                    .await
                    .expect("receiver exists");
            }
            SocketAddr::V6(dest) => {
                self.udp_tx
                    .send(
                        create_ipv6_payload(
                            &self.source_ip_v6,
                            self.source_port,
                            dest.ip(),
                            dest.port(),
                            &udp_payload,
                            self.connection_id,
                        )
                        .await,
                    )
                    .await
                    .expect("receiver exists");
            }
        }

        Ok(())
    }
}
impl UdpRecv for UdpChannelV4Rx {
    type RecvManyBuf = ();

    async fn recv_from(&mut self, _pool: &mut PacketBufPool) -> io::Result<(Packet, SocketAddr)> {
        let mut udp_rx_v4 = self
            .udp_rx_v4
            .try_lock()
            .expect("multiple concurrent calls to recv_from");
        let ipv4 = udp_rx_v4.recv().await.expect("sender exists");

        let source_addr = ipv4.header.source();

        let udp = ipv4.into_payload();
        let source_port = udp.header.source_port.get();

        // Packet with IP and UDP headers shed.
        let inner_packet = udp.into_payload();
        let socket_addr = SocketAddr::from((source_addr, source_port));

        Ok((inner_packet, socket_addr))
    }
}

impl UdpRecv for UdpChannelV6Rx {
    type RecvManyBuf = ();

    async fn recv_from(&mut self, _pool: &mut PacketBufPool) -> io::Result<(Packet, SocketAddr)> {
        let mut udp_rx_v6 = self
            .udp_rx_v6
            .try_lock()
            .expect("multiple concurrent calls to recv_from");
        let ipv6 = udp_rx_v6.recv().await.expect("sender exists");

        let source_addr = ipv6.header.source();

        let udp = ipv6.into_payload();
        let source_port = udp.header.source_port.get();

        // Packet with IP and UDP headers shed.
        let inner_packet = udp.into_payload();
        let socket_addr = SocketAddr::from((source_addr, source_port));

        Ok((inner_packet, socket_addr))
    }
}

async fn create_ipv4_payload(
    source_ip: Ipv4Addr,
    source_port: u16,
    destination_ip: Ipv4Addr,
    destination_port: u16,
    udp_payload: &[u8],
) -> Packet<Ip> {
    let udp_len: u16 = (UDP_HEADER_LEN + udp_payload.len()).try_into().unwrap();
    let total_len = u16::try_from(IPV4_HEADER_LEN).unwrap() + udp_len;

    let mut packet = BytesMut::zeroed(usize::from(total_len));

    let ipv4 = Ipv4::<Udp>::mut_from_bytes(&mut packet).expect("bad IP packet buffer");
    ipv4.header =
        Ipv4Header::new_for_length(source_ip, destination_ip, IpNextProtocol::Udp, udp_len);

    static NEXT_ID: AtomicU16 = AtomicU16::new(1);
    ipv4.header.identification = NEXT_ID
        .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
        .into();

    // TODO: Remove dependency on pnet_packet
    let ipv4_checksum = pnet_packet::util::checksum(ipv4.header.as_bytes(), 5);
    ipv4.header.header_checksum = ipv4_checksum.into();

    let udp = &mut ipv4.payload;
    udp.header.source_port = source_port.into();
    udp.header.destination_port = destination_port.into();
    udp.header.length = udp_len.into();
    udp.payload.copy_from_slice(udp_payload);

    // TODO: Remove dependency on pnet_packet
    let csum = pnet_packet::util::ipv4_checksum(
        udp.as_bytes(),
        3,
        &[],
        &source_ip,
        &destination_ip,
        IpNextHeaderProtocols::Udp,
    );
    udp.header.checksum = csum.into();

    Packet::from_bytes(packet)
        .try_into_ip()
        .expect("packet is valid")
}

async fn create_ipv6_payload(
    source_ip: &Ipv6Addr,
    source_port: u16,
    destination_ip: &Ipv6Addr,
    destination_port: u16,
    udp_payload: &[u8],
    connection_id: u32,
) -> Packet<Ip> {
    let udp_len: u16 = (UDP_HEADER_LEN + udp_payload.len()).try_into().unwrap();
    let total_len = u16::try_from(IPV6_HEADER_LEN).unwrap() + udp_len;

    let mut packet = BytesMut::zeroed(usize::from(total_len));

    let ipv6 = Ipv6::<Udp>::mut_from_bytes(&mut packet).expect("bad IP packet buffer");
    ipv6.header.set_version(6);
    ipv6.header.set_flow_label(connection_id);
    ipv6.header.next_header = IpNextProtocol::Udp;
    ipv6.header.source_address = source_ip.to_bits().into();
    ipv6.header.destination_address = destination_ip.to_bits().into();
    ipv6.header.hop_limit = 64;

    let udp = &mut ipv6.payload;
    udp.header.source_port = source_port.into();
    udp.header.destination_port = destination_port.into();
    udp.header.length = udp_len.into();
    udp.payload.copy_from_slice(udp_payload);

    // TODO: Remove dependency on pnet_packet
    let csum = pnet_packet::util::ipv6_checksum(
        udp.as_bytes(),
        3,
        &[],
        source_ip,
        destination_ip,
        IpNextHeaderProtocols::Udp,
    );
    udp.header.checksum = csum.into();

    Packet::from_bytes(packet)
        .try_into_ip()
        .expect("packet is valid")
}

fn rand_u16() -> u16 {
    u16::try_from(rand_core::OsRng.next_u32().overflowing_shr(16).0).unwrap()
}

mod fragmentation {
    use either::Either;
    use zerocopy::{FromBytes, FromZeros};

    use crate::packet::Udp;
    use std::{
        collections::{BTreeMap, HashMap},
        net::Ipv4Addr,
    };

    use crate::packet::{Ipv4, Packet};

    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    struct FragmentId {
        identification: u16,
        source_ip: Ipv4Addr,
        destination_ip: Ipv4Addr,
    }

    #[derive(Debug, Default)]
    pub struct Ipv4Fragments {
        fragments: HashMap<FragmentId, BTreeMap<u16, Packet<Ipv4>>>,
    }

    impl Ipv4Fragments {
        /// Return the number of unique packets that are currently being assembled.
        pub fn incomplete_packet_count(&self) -> usize {
            self.fragments.len()
        }

        pub fn assemble_ipv4_fragment(
            &mut self,
            ipv4_packet: Packet<Ipv4>,
        ) -> Option<Packet<Ipv4>> {
            let fragment_map = &mut self.fragments;
            let header = ipv4_packet.header;
            let fragment_offset = header.fragment_offset();
            let more_fragments = header.more_fragments();
            debug_assert!(more_fragments || fragment_offset != 0);

            let id = FragmentId {
                identification: ipv4_packet.header.identification.get(),
                source_ip: ipv4_packet.header.source(),
                destination_ip: ipv4_packet.header.destination(),
            };
            if let Some(fragments) = fragment_map.get_mut(&id) {
                let frag_with_same_offset = fragments.insert(fragment_offset, ipv4_packet);
                #[cfg(debug_assertions)]
                if frag_with_same_offset.is_some() {
                    tracing::trace!(
                        "Fragment with offset {fragment_offset} already existed for for ID {id:?} and was replaced"
                    );
                }

                let (first_frag_offset, _) = fragments.first_key_value().expect("Cannot be empty");
                let (_, last_frag) = fragments.last_key_value().expect("Cannot be empty");

                // Check that we have the first and last fragment
                if last_frag.header.more_fragments() || *first_frag_offset != 0 {
                    return None;
                }

                // Check if the IP packet can be reassembled.
                // The fragments must be consecutive, i.e. each fragment must begin where the previous one ended.
                // Note that fragment offset is given in units of 8 bytes.
                let fragment_offsets = fragments.keys().cloned();
                let fragment_ends = fragments
                    .iter()
                    .map(|(k, v)| k + (v.payload.len() / 8) as u16);
                if fragment_offsets
                    .skip(1)
                    .eq(fragment_ends.take(fragments.len() - 1))
                {
                    let mut packet_fragment = fragment_map.remove(&id).unwrap();
                    // To avoid allocating a new packet, we will use the first fragment
                    // and extend it with the payloads of the other fragments.
                    let (_, first_packet) = packet_fragment.pop_first().unwrap();

                    let mut bytes = first_packet.into_bytes();
                    for frag in packet_fragment.values() {
                        bytes.buf_mut().extend_from_slice(&frag.payload);
                    }

                    let len = bytes.len();

                    // The header of the first packet is updated to reflect that the packet is no
                    // longer fragmented.
                    {
                        let ip = Ipv4::<Udp>::mut_from_bytes(&mut bytes)
                            .expect("valid IP packet buffer");
                        ip.header.total_len = (len as u16).into();

                        // This set `more_fragments`, `dont_fragment`, and `fragment_offset` to zero.
                        ip.header.flags_and_fragment_offset.zero();

                        // We do not need to recompute the checksum, because the checksum is
                        // only read by the `ExitDevice` and discarded
                        ip.header.header_checksum.zero();
                    }

                    // NOTE: We could change the `tun_tx_vx` channels to take a tuple of source ip,
                    // destination ip, and `Packet<Udp>`, instead of `Packet<Ipv4<Udp>>`, to avoid
                    // having to reconstruct the IP head and validate the IP packet with
                    // `try_into_ipvx`
                    if let Ok(Either::Left(ipv4_packet)) = bytes.try_into_ipvx() {
                        Some(ipv4_packet)
                    } else {
                        log::trace!("Invalid reassembled IPv4 packet, dropping");
                        None
                    }
                } else {
                    None
                }
            } else {
                // Since this was the first fragment, we don't check if the packet
                // can be reassembled yet.
                fragment_map.insert(id, BTreeMap::from([(fragment_offset, ipv4_packet)]));
                None
            }
        }
    }

    #[cfg(test)]
    mod test {
        use super::*;
        use crate::packet::{
            IpNextProtocol, Ipv4FlagsFragmentOffset, Ipv4Header, TryIntoUdpResult,
        };
        use crate::udp::channel::{IPV4_HEADER_LEN, UDP_HEADER_LEN};
        use bytes::BytesMut;
        use rand::rng;
        use rand::seq::SliceRandom;
        use std::collections::HashMap;
        use std::net::Ipv4Addr;
        use zerocopy::IntoBytes;

        fn make_ip_fragment(
            identification: u16,
            source_ip: Ipv4Addr,
            destination_ip: Ipv4Addr,
            offset: u16,
            more_fragments: bool,
            payload: &[u8],
        ) -> Packet<Ipv4> {
            // Build a minimal UDP payload
            let total_len = IPV4_HEADER_LEN + payload.len();
            let mut buf = BytesMut::zeroed(total_len);
            let ipv4 = Ipv4::<[u8]>::mut_from_bytes(&mut buf).unwrap();
            ipv4.header = Ipv4Header::new_for_length(
                source_ip,
                destination_ip,
                IpNextProtocol::Udp,
                payload.len() as u16,
            );
            ipv4.header.identification = identification.into();
            let mut flags = Ipv4FlagsFragmentOffset::new();
            flags.set_more_fragments(more_fragments);
            flags.set_fragment_offset(offset);
            ipv4.header.flags_and_fragment_offset = flags;
            ipv4.payload.copy_from_slice(payload);

            Packet::from_bytes(buf)
                .try_into_ipvx()
                .unwrap()
                .unwrap_left()
        }

        fn make_udp_bytes(payload: &[u8]) -> BytesMut {
            let len = UDP_HEADER_LEN + payload.len();
            let mut buf = BytesMut::zeroed(len);
            let udp = Udp::<[u8]>::mut_from_bytes(&mut buf).unwrap();
            udp.header.source_port = 1234u16.into();
            udp.header.destination_port = 5678u16.into();
            udp.header.length = (len as u16).into();
            udp.header.checksum = 0.into();
            assert_eq!(udp.payload.len(), payload.len());
            udp.payload.copy_from_slice(payload);
            buf
        }

        #[test]
        fn test_ipv4_defragmentation() {
            let mut fragments = Ipv4Fragments::default();
            let src1 = Ipv4Addr::new(10, 0, 0, 1);
            let dst1 = Ipv4Addr::new(10, 0, 0, 2);
            let src2 = Ipv4Addr::new(10, 0, 0, 3);
            let dst2 = Ipv4Addr::new(10, 0, 0, 4);
            let id1 = 100;
            let id2 = 200;
            // Two packets
            let payload1 = make_udp_bytes(b"ABCDEFGHIJKLMN");
            let payload2 = make_udp_bytes(b"MY SLIGHTLY LONGER PACKET");

            // Split each into 3 fragments
            let mut all_frags = vec![
                (
                    id1,
                    make_ip_fragment(id1, src1, dst1, 0, true, &payload1[0..8]),
                ),
                (
                    id1,
                    make_ip_fragment(id1, src1, dst1, 1, true, &payload1[8..16]),
                ),
                (
                    id1,
                    make_ip_fragment(id1, src1, dst1, 2, false, &payload1[16..]),
                ),
                (
                    id2,
                    make_ip_fragment(id2, src2, dst2, 0, true, &payload2[0..16]),
                ),
                (
                    id2,
                    make_ip_fragment(id2, src2, dst2, 2, true, &payload2[16..24]),
                ),
                (
                    id2,
                    make_ip_fragment(id2, src2, dst2, 3, true, &payload2[24..32]),
                ),
                (
                    id2,
                    make_ip_fragment(id2, src2, dst2, 4, false, &payload2[32..]),
                ),
            ];
            all_frags.shuffle(&mut rng());
            let mut seen = HashMap::new();
            for (id, frag) in all_frags {
                let res = fragments.assemble_ipv4_fragment(frag.clone());
                let count = seen.entry(id).or_insert(0);
                *count += 1;
                if let Some(ip_packet) = res {
                    let TryIntoUdpResult::Udp(udp_packet) = ip_packet.try_into_udp().unwrap()
                    else {
                        panic!("Expected UDP packet");
                    };
                    log::debug!(
                        "Reassembled UDP payload (ascii): {:?}",
                        String::from_utf8_lossy(&udp_packet.payload.payload)
                    );

                    if id == id1 {
                        assert_eq!(*count, 3, "Should reassemble on last fragment");
                        assert_eq!(udp_packet.payload.as_bytes(), &payload1[..]);
                    } else {
                        assert_eq!(*count, 4, "Should reassemble on last fragment");
                        assert_eq!(udp_packet.payload.as_bytes(), &payload2[..]);
                    };
                    assert_eq!(udp_packet.header.fragment_offset(), 0);
                    assert!(!udp_packet.header.more_fragments());
                    assert_eq!(
                        udp_packet.header.source(),
                        if id == id1 { src1 } else { src2 }
                    );
                    assert_eq!(
                        udp_packet.header.destination(),
                        if id == id1 { dst1 } else { dst2 }
                    );
                }

                // Last fragment for this id
            }

            assert_eq!(
                fragments.incomplete_packet_count(),
                0,
                "All fragments should be processed"
            );
        }

        #[test]
        fn test_ipv4_defragmentation_single_packet() {
            let mut fragments = Ipv4Fragments::default();
            let src = Ipv4Addr::new(192, 168, 1, 1);
            let dst = Ipv4Addr::new(192, 168, 1, 2);
            let id = 42;
            let payload = make_udp_bytes(b"HELLOFRAGMENTS");
            // Split into 3 fragments
            let mut frags = vec![
                make_ip_fragment(id, src, dst, 0, true, &payload[0..8]),
                make_ip_fragment(id, src, dst, 1, true, &payload[8..16]),
                make_ip_fragment(id, src, dst, 2, false, &payload[16..]),
            ];
            frags.shuffle(&mut rng());
            let mut count = 0;
            for frag in frags {
                let res = fragments.assemble_ipv4_fragment(frag.clone());
                count += 1;
                if let Some(ip_packet) = res {
                    let TryIntoUdpResult::Udp(udp_packet) = ip_packet.try_into_udp().unwrap()
                    else {
                        panic!("Expected UDP packet");
                    };
                    log::debug!(
                        "Reassembled UDP payload (ascii): {:?}",
                        String::from_utf8_lossy(&udp_packet.payload.payload)
                    );
                    assert_eq!(count, 3, "Should reassemble on last fragment");
                    assert_eq!(udp_packet.payload.as_bytes(), &payload[..]);
                    assert_eq!(udp_packet.header.fragment_offset(), 0);
                    assert!(!udp_packet.header.more_fragments());
                    assert_eq!(udp_packet.header.source(), src);
                    assert_eq!(udp_packet.header.destination(), dst);
                } else {
                    assert!(count < 3, "Should not reassemble until last fragment");
                }
            }
            assert_eq!(
                fragments.incomplete_packet_count(),
                0,
                "All fragments should be processed"
            );
        }
    }
}
