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
    packet::{Ip, IpNextProtocol, Ipv4, Ipv4Header, Ipv6, Packet, PacketBufPool, Udp},
    tun::{IpRecv, IpSend},
    udp::{UdpRecv, UdpSend, UdpTransport, UdpTransportFactory},
};

use super::UdpTransportFactoryParams;
pub use fragmentation::Ipv4Fragments;

/// An implementation of [`IpRecv`] using tokio channels. Create using
/// [`get_packet_channels`].
pub struct TunChannelRx {
    tun_rx: mpsc::Receiver<Packet<Ip>>,
}

/// An implementation of [`IpSend`] using tokio channels. Create using
/// [`get_packet_channels`].
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

/// An implementation of [`UdpSend`] using tokio channels. Create using
/// [`get_packet_channels`].
#[derive(Clone)]
pub struct UdpChannelTx {
    source_ip_v4: Ipv4Addr,
    source_ip_v6: Ipv6Addr,
    source_port: u16,
    connection_id: u32,

    udp_tx: mpsc::Sender<Packet<Ip>>,
}

type Ipv4UdpReceiver = mpsc::Receiver<Packet<Ipv4<Udp>>>;
type Ipv6UdpReceiver = mpsc::Receiver<Packet<Ipv6<Udp>>>;

/// An implementation of [`UdpRecv`] for IPv4 UDP packets. Create using
/// [`get_packet_channels`].
pub struct UdpChannelV4Rx {
    /// The receiver for IPv4 UDP packets. Is always `Some` until drop.
    udp_rx_v4: Option<Ipv4UdpReceiver>,
    /// Shared memory with `PacketChannelUdp` to return the receiver after drop.
    return_udp_rx_v4: Arc<Mutex<Option<Ipv4UdpReceiver>>>,
}

impl Drop for UdpChannelV4Rx {
    fn drop(&mut self) {
        // Return the receiver to `PacketChannelUdp`
        *self
            .return_udp_rx_v4
            .try_lock()
            .expect("multiple concurrent calls to drop") = self.udp_rx_v4.take();
    }
}

/// An implementation of [`UdpRecv`] for IPv6 UDP packets. Create using
/// [`get_packet_channels`].
pub struct UdpChannelV6Rx {
    /// The receiver for IPv6 UDP packets. Is always `Some` until drop.
    udp_rx_v6: Option<Ipv6UdpReceiver>,
    /// Shared memory with `PacketChannelUdp` to return the receiver after drop.
    return_udp_rx_v6: Arc<Mutex<Option<Ipv6UdpReceiver>>>,
}

impl Drop for UdpChannelV6Rx {
    fn drop(&mut self) {
        // Return the receiver to `PacketChannelUdp`
        *self
            .return_udp_rx_v6
            .try_lock()
            .expect("multiple concurrent calls to drop") = self.udp_rx_v6.take();
    }
}

/// An implementation of [`UdpTransportFactory`], producing [`UdpSend`] and
/// [`UdpRecv`] implementations that use channels to send and receive packets.
pub struct PacketChannelUdp {
    source_ip_v4: Ipv4Addr,
    source_ip_v6: Ipv6Addr,

    udp_tx: mpsc::Sender<Packet<Ip>>,
    udp_rx_v4: Arc<Mutex<Option<Ipv4UdpReceiver>>>,
    udp_rx_v6: Arc<Mutex<Option<Ipv6UdpReceiver>>>,
}

/// Create a set of channel-based TUN and UDP endpoints for in-process device communication.
///
/// This function returns a tuple of (TunChannelTx, TunChannelRx, PacketChannelUdp), which can be used
/// to connect two [`Device`]s (e.g. for a multihop tunnel or for testing) entirely in memory.
///
/// # Arguments
/// * `capacity` - The channel buffer size for each direction.
/// * `source_ip_v4` - The IPv4 address to use as the source for outgoing packets.
/// * `source_ip_v6` - The IPv6 address to use as the source for outgoing packets.
///
/// # Returns
/// A tuple of (TunChannelTx, TunChannelRx, PacketChannelUdp).
///
/// # Example
/// ```no_run
/// use boringtun::udp::channel::{get_packet_channels, TunChannelTx, TunChannelRx, PacketChannelUdp};
/// use boringtun::device::{DeviceHandle, DeviceConfig};
/// use std::net::{Ipv4Addr, Ipv6Addr};
/// use std::sync::Arc;
/// use tokio::runtime::Runtime;
///
/// let capacity = 100;
/// let source_v4 = Ipv4Addr::new(10, 0, 0, 1);
/// let source_v6 = Ipv6Addr::UNSPECIFIED;
/// let (tun_tx, tun_rx, udp_channels) = get_packet_channels(capacity, source_v4, source_v6);
///
/// // Create entry and exit devices using the returned channels
/// let entry_device = DeviceHandle::new(UdpSocketFactory, tun_tx, tun_rx, /* device_config */);
/// let exit_device = DeviceHandle::new(udp_channels, Arc::new(/* async_tun */), Arc::new(/* async_tun */), /* device_config */);
/// // Now entry_device and exit_device can communicate in-process via the channels.
/// ```
///
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
        udp_rx_v4: Arc::new(Mutex::new(Some(udp_rx_v4))),
        udp_rx_v6: Arc::new(Mutex::new(Some(udp_rx_v6))),
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
                let ipv4 = if ipv4.header.fragment_offset() == 0 && !ipv4.header.more_fragments() {
                    ipv4
                } else if let Some(ipv4) = self.fragments_v4.assemble_ipv4_fragment(ipv4) {
                    ipv4
                } else {
                    // No complete IPv4 packet was reassembled, nothing to do
                    return Ok(());
                };

                match ipv4.try_into_udp() {
                    Ok(udp_packet) => {
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
        let packet = self.tun_rx.recv().await.expect("sender exists");
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
            return_udp_rx_v4: self.udp_rx_v4.clone(),
            udp_rx_v4: self.udp_rx_v4.clone().lock().await.take(),
        };
        let channel_rx_v6 = UdpChannelV6Rx {
            return_udp_rx_v6: self.udp_rx_v6.clone(),
            udp_rx_v6: self.udp_rx_v6.clone().lock().await.take(),
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
        let ipv4 = self
            .udp_rx_v4
            .as_mut()
            .expect("UdpChannelV4Rx holds sender for its entire lifetime")
            .recv()
            .await
            .expect("sender exists");

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
        let ipv6 = self
            .udp_rx_v6
            .as_mut()
            .expect("UdpChannelV4Rx holds sender for its entire lifetime")
            .recv()
            .await
            .expect("sender exists");

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
    use zerocopy::{FromBytes, FromZeros};

    use crate::{
        packet::Udp,
        udp::channel::{IPV4_HEADER_LEN, IPV4_MAX_LEN},
    };
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

            // All fragments except the last must have a length that is a multiple of 8
            // bytes, and the last fragment must not exceed the maximum IPv4 length.
            let fragment_len = ipv4_packet.payload.len();
            if (more_fragments && fragment_len % 8 != 0)
                || fragment_len + fragment_offset as usize * 8 > IPV4_MAX_LEN
            {
                log::trace!("Invalid fragment size: {fragment_len}, dropping",);
                return None;
            }

            let id = FragmentId {
                identification: ipv4_packet.header.identification.get(),
                source_ip: ipv4_packet.header.source(),
                destination_ip: ipv4_packet.header.destination(),
            };
            let Some(fragments) = fragment_map.get_mut(&id) else {
                // Since this was the first fragment, we don't check if the packet
                // can be reassembled yet.
                fragment_map.insert(id, BTreeMap::from([(fragment_offset, ipv4_packet)]));
                return None;
            };
            let _frag_with_same_offset = fragments.insert(fragment_offset, ipv4_packet);
            #[cfg(debug_assertions)]
            if _frag_with_same_offset.is_some() {
                log::trace!(
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
            if !fragment_offsets
                .skip(1)
                .eq(fragment_ends.take(fragments.len() - 1))
            {
                return None;
            }
            let len = last_frag.header.fragment_offset() as usize * 8
                + last_frag.payload.len()
                + IPV4_HEADER_LEN;
            let mut packet_fragments = fragment_map.remove(&id).unwrap();
            // To potentially avoid allocating a new packet, we will use the first fragment
            // and extend it with the payloads of the other fragments.
            let (_, first_packet) = packet_fragments.pop_first().unwrap();

            let mut bytes = first_packet.into_bytes();
            let additional_bytes_needed = len.saturating_sub(bytes.buf_mut().len());
            bytes.buf_mut().reserve(additional_bytes_needed);
            for frag in packet_fragments.values() {
                bytes.buf_mut().extend_from_slice(&frag.payload);
            }

            // The header of the first packet is updated to reflect that the packet is no
            // longer fragmented.
            {
                let ip = Ipv4::<Udp>::mut_from_bytes(&mut bytes).expect("valid IP packet buffer");
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
            Some(
                bytes
                    .try_into_ipvx()
                    .expect("Previously valid Ipv4 packet should still be valid")
                    .unwrap_left(),
            )
        }
    }
}
