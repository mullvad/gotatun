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

//! Source/destination NAT adapters for [`IpRecv`] and [`IpSend`].
//!
//! [`NatIpRecv`] rewrites the source IP on TUN read.
//! [`NatIpSend`] rewrites the destination IP on TUN write.

// TODO: May need state to make sure outer tunnel cannot talk to port "owned" by inner

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr};

use duplicate::duplicate_item;
use zerocopy::{FromBytes, IntoBytes, big_endian};

use crate::packet::{
    Ip, IpNextProtocol, Ipv4, Ipv6, Packet, PacketBufPool, Udp, incremental_checksum_update,
    incremental_checksum_update_v6,
};
use crate::tun::{IpRecv, IpSend, MtuWatcher};

/// Rewrites source IP on TUN-received packets (outbound NAT).
pub struct NatIpRecv<R: IpRecv> {
    inner: R,
    /// Source IPv4 to match and replace (the outer VPN IP)
    from_v4: Ipv4Addr,
    /// Replacement source IPv4 (the inner tunnel IP)
    to_v4: Ipv4Addr,
    /// Source IPv6 to match and replace (the outer VPN IP)
    from_v6: Option<Ipv6Addr>,
    /// Replacement source IPv6 (the inner tunnel IP)
    to_v6: Option<Ipv6Addr>,
}

/// Rewrites destination IP on TUN-sent packets (inbound NAT).
pub struct NatIpSend<S: IpSend> {
    inner: S,
    /// Dest IPv4 to match and replace (the inner tunnel IP)
    from_v4: Ipv4Addr,
    /// Replacement dest IPv4 (the outer VPN IP)
    to_v4: Ipv4Addr,
    /// Dest IPv6 to match and replace (the inner tunnel IP)
    from_v6: Option<Ipv6Addr>,
    /// Replacement dest IPv6 (the outer VPN IP)
    to_v6: Option<Ipv6Addr>,
}

impl<R: IpRecv> NatIpRecv<R> {
    pub fn new(inner: R, from: Ipv4Addr, to: Ipv4Addr) -> Self {
        Self {
            inner,
            from_v4: from,
            to_v4: to,
            from_v6: None,
            to_v6: None,
        }
    }

    pub fn with_v6(mut self, from: Ipv6Addr, to: Ipv6Addr) -> Self {
        self.from_v6 = Some(from);
        self.to_v6 = Some(to);
        self
    }
}

impl<S: IpSend> NatIpSend<S> {
    pub fn new(inner: S, from: Ipv4Addr, to: Ipv4Addr) -> Self {
        Self {
            inner,
            from_v4: from,
            to_v4: to,
            from_v6: None,
            to_v6: None,
        }
    }

    pub fn with_v6(mut self, from: Ipv6Addr, to: Ipv6Addr) -> Self {
        self.from_v6 = Some(from);
        self.to_v6 = Some(to);
        self
    }
}

impl<R: IpRecv> IpRecv for NatIpRecv<R> {
    async fn recv<'a>(
        &'a mut self,
        pool: &mut PacketBufPool,
    ) -> io::Result<impl Iterator<Item = Packet<Ip>> + Send + 'a> {
        let packets = self.inner.recv(pool).await?;
        let from_v4 = self.from_v4;
        let to_v4 = self.to_v4;
        let from_v6 = self.from_v6;
        let to_v6 = self.to_v6;
        Ok(packets.map(move |mut packet| {
            rewrite_source_ip(&mut packet, from_v4, to_v4, from_v6, to_v6);
            packet
        }))
    }

    fn mtu(&self) -> MtuWatcher {
        self.inner.mtu()
    }
}

impl<S: IpSend> IpSend for NatIpSend<S> {
    async fn send(&mut self, mut packet: Packet<Ip>) -> io::Result<()> {
        rewrite_dest_ip(
            &mut packet,
            self.from_v4,
            self.to_v4,
            self.from_v6,
            self.to_v6,
        );
        self.inner.send(packet).await
    }
}

fn rewrite_source_ip(
    packet: &mut Packet<Ip>,
    from_v4: Ipv4Addr,
    to_v4: Ipv4Addr,
    from_v6: Option<Ipv6Addr>,
    to_v6: Option<Ipv6Addr>,
) {
    match packet.header.version() {
        4 => {
            let Ok(ipv4) = Ipv4::<[u8]>::mut_from_bytes(packet.as_mut_bytes()) else {
                return;
            };
            rewrite_source_ipv4(ipv4, from_v4, to_v4);
        }
        6 => {
            if let (Some(from), Some(to)) = (from_v6, to_v6) {
                let Ok(ipv6) = Ipv6::<[u8]>::mut_from_bytes(packet.as_mut_bytes()) else {
                    return;
                };
                rewrite_source_ipv6(ipv6, from, to);
            }
        }
        _ => {}
    }
}

fn rewrite_dest_ip(
    packet: &mut Packet<Ip>,
    from_v4: Ipv4Addr,
    to_v4: Ipv4Addr,
    from_v6: Option<Ipv6Addr>,
    to_v6: Option<Ipv6Addr>,
) {
    match packet.header.version() {
        4 => {
            let Ok(ipv4) = Ipv4::<[u8]>::mut_from_bytes(packet.as_mut_bytes()) else {
                return;
            };
            rewrite_dest_ipv4(ipv4, from_v4, to_v4);
        }
        6 => {
            if let (Some(from), Some(to)) = (from_v6, to_v6) {
                let Ok(ipv6) = Ipv6::<[u8]>::mut_from_bytes(packet.as_mut_bytes()) else {
                    return;
                };
                rewrite_dest_ipv6(ipv6, from, to);
            }
        }
        _ => {}
    }
}

fn rewrite_source_ipv4(ipv4: &mut Ipv4<[u8]>, from: Ipv4Addr, to: Ipv4Addr) {
    if ipv4.header.source() != from {
        return;
    }
    if ipv4.header.ihl() != 5 {
        return;
    }

    let protocol = ipv4.header.protocol;

    ipv4.header.source_address = big_endian::U32::from_bytes(to.octets());
    ipv4.header.recompute_checksum();
    update_transport_checksum_v4(&mut ipv4.payload, protocol, &from.octets(), &to.octets());
}

fn rewrite_dest_ipv4(ipv4: &mut Ipv4<[u8]>, from: Ipv4Addr, to: Ipv4Addr) {
    if ipv4.header.destination() != from {
        return;
    }
    if ipv4.header.ihl() != 5 {
        return;
    }

    let protocol = ipv4.header.protocol;
    ipv4.header.destination_address = big_endian::U32::from_bytes(to.octets());
    ipv4.header.recompute_checksum();

    update_transport_checksum_v4(&mut ipv4.payload, protocol, &from.octets(), &to.octets());
}

fn rewrite_source_ipv6(ipv6: &mut Ipv6<[u8]>, from: Ipv6Addr, to: Ipv6Addr) {
    if ipv6.header.source() != from {
        return;
    }

    let protocol = ipv6.header.next_header;
    ipv6.header.source_address = big_endian::U128::from_bytes(to.octets());
    update_transport_checksum_v6(&mut ipv6.payload, protocol, &from.octets(), &to.octets());
}

fn rewrite_dest_ipv6(ipv6: &mut Ipv6<[u8]>, from: Ipv6Addr, to: Ipv6Addr) {
    if ipv6.header.destination() != from {
        return;
    }

    let protocol = ipv6.header.next_header;
    ipv6.header.destination_address = big_endian::U128::from_bytes(to.octets());
    update_transport_checksum_v6(&mut ipv6.payload, protocol, &from.octets(), &to.octets());
}

/// Incrementally update the transport-layer (TCP/UDP) checksum after an IP address change.
///
/// `transport` is the transport-layer payload (starting at the TCP/UDP header).
/// `old_addr` and `new_addr` are the IP addresses that changed.
#[duplicate_item(
    update_transport_checksum AddrIn incremental_checksum_update into_addr;
    [update_transport_checksum_v4] [[u8; 4]] [incremental_checksum_update] [big_endian::U32::from_bytes];
    [update_transport_checksum_v6] [[u8; 16]] [incremental_checksum_update_v6] [big_endian::U128::from_bytes];
)]
fn update_transport_checksum(
    transport: &mut [u8],
    protocol: IpNextProtocol,
    old_addr: &AddrIn,
    new_addr: &AddrIn,
) {
    match protocol {
        IpNextProtocol::Udp => {
            let Ok(udp) = Udp::<[u8]>::mut_from_bytes(transport) else {
                return;
            };
            let old_check = udp.header.checksum.get();
            // For UDP, a checksum of 0 means "no checksum"; don't update it.
            if old_check == 0 {
                return;
            }
            udp.header.checksum =
                incremental_checksum_update(old_check, into_addr(*old_addr), into_addr(*new_addr))
                    .into();
        }
        IpNextProtocol::Tcp => {
            // TCP checksum is at byte offset 16 in the TCP header.
            const CHECKSUM_OFFSET: usize = 16;
            if transport.len() < CHECKSUM_OFFSET + 2 {
                return;
            }
            let old_check =
                u16::from_be_bytes([transport[CHECKSUM_OFFSET], transport[CHECKSUM_OFFSET + 1]]);
            let new_check =
                incremental_checksum_update(old_check, into_addr(*old_addr), into_addr(*new_addr));
            transport[CHECKSUM_OFFSET..CHECKSUM_OFFSET + 2]
                .copy_from_slice(&new_check.to_be_bytes());
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;
    use std::net::Ipv6Addr;
    use zerocopy::FromBytes;

    use crate::packet::{
        IpNextProtocol, Ipv4, Ipv4Header, Ipv6, Ipv6Header, PseudoHeaderV4, PseudoHeaderV6, Udp,
        UdpHeader, checksum, checksum_udp,
    };

    /// Build a minimal IPv4/UDP packet with a valid header checksum and UDP checksum.
    fn make_ipv4_udp_packet(src: Ipv4Addr, dst: Ipv4Addr, udp_payload: &[u8]) -> Packet<Ip> {
        let udp_len = UdpHeader::LEN + udp_payload.len();
        let total_len = Ipv4Header::LEN + udp_len;
        let mut buf = BytesMut::zeroed(total_len);

        // Build IPv4 and UDP headers.
        {
            let ipv4 = Ipv4::<[u8]>::mut_from_bytes(&mut buf).unwrap();
            ipv4.header = Ipv4Header::new_for_length(src, dst, IpNextProtocol::Udp, udp_len as u16);
            let udp = crate::packet::Udp::<[u8]>::mut_from_bytes(&mut ipv4.payload).unwrap();
            udp.header.source_port = 1234u16.into();
            udp.header.destination_port = 5678u16.into();
            udp.header.length = (udp_len as u16).into();
            udp.header.checksum = 0u16.into();
            udp.payload.copy_from_slice(udp_payload);
        }

        // Compute valid IPv4 header checksum.
        {
            let ipv4 = Ipv4::<[u8]>::mut_from_bytes(&mut buf).unwrap();
            ipv4.header.recompute_checksum();
        }

        // Compute valid UDP checksum (pseudo-header + UDP).
        {
            let ipv4 = Ipv4::<[u8]>::ref_from_bytes(&buf).unwrap();
            let udp = Udp::<[u8]>::ref_from_bytes(&ipv4.payload).unwrap();
            let pseudo = PseudoHeaderV4::from_udp(
                ipv4.header.source_address,
                ipv4.header.destination_address,
                udp,
            );
            let cksum = checksum_udp(pseudo, &ipv4.payload);
            let ipv4 = Ipv4::<[u8]>::mut_from_bytes(&mut buf).unwrap();
            let udp = Udp::<[u8]>::mut_from_bytes(&mut ipv4.payload).unwrap();
            udp.header.checksum = cksum.into();
        }

        Packet::from_bytes(buf).try_into_ip().unwrap()
    }

    /// Build a minimal IPv6/UDP packet with a valid UDP checksum.
    fn make_ipv6_udp_packet(src: Ipv6Addr, dst: Ipv6Addr, udp_payload: &[u8]) -> Packet<Ip> {
        let udp_len = UdpHeader::LEN + udp_payload.len();
        let total_len = Ipv6Header::LEN + udp_len;
        let mut buf = BytesMut::zeroed(total_len);

        {
            let ipv6 = Ipv6::<[u8]>::mut_from_bytes(&mut buf).unwrap();
            ipv6.header.set_version(6);
            ipv6.header.payload_length = (udp_len as u16).into();
            ipv6.header.next_header = IpNextProtocol::Udp;
            ipv6.header.hop_limit = 64;
            ipv6.header.source_address = big_endian::U128::from_bytes(src.octets());
            ipv6.header.destination_address = big_endian::U128::from_bytes(dst.octets());

            let udp = crate::packet::Udp::<[u8]>::mut_from_bytes(&mut ipv6.payload).unwrap();
            udp.header.source_port = 1234u16.into();
            udp.header.destination_port = 5678u16.into();
            udp.header.length = (udp_len as u16).into();
            udp.header.checksum = 0u16.into();
            udp.payload.copy_from_slice(udp_payload);
        }

        {
            let ipv6 = Ipv6::<[u8]>::ref_from_bytes(&buf).unwrap();
            let udp = Udp::<[u8]>::ref_from_bytes(&ipv6.payload).unwrap();
            let pseudo = PseudoHeaderV6::from_udp(
                ipv6.header.source_address,
                ipv6.header.destination_address,
                udp,
            );
            let cksum = checksum_udp(pseudo, &ipv6.payload);
            let ipv6 = Ipv6::<[u8]>::mut_from_bytes(&mut buf).unwrap();
            let udp = Udp::<[u8]>::mut_from_bytes(&mut ipv6.payload).unwrap();
            udp.header.checksum = cksum.into();
        }

        Packet::from_bytes(buf).try_into_ip().unwrap()
    }

    fn verify_ipv4_header_checksum(buf: &[u8]) -> bool {
        let ipv4 = Ipv4::<[u8]>::ref_from_bytes(buf).unwrap();
        checksum(&[ipv4.header.as_bytes()]) == 0
    }

    fn verify_udp_checksum_v4(buf: &[u8]) -> bool {
        let ipv4 = Ipv4::<[u8]>::ref_from_bytes(buf).unwrap();
        let udp = Udp::<[u8]>::ref_from_bytes(&ipv4.payload).unwrap();
        if udp.header.checksum.get() == 0 {
            return true;
        }
        let pseudo = PseudoHeaderV4::from_udp(
            ipv4.header.source_address,
            ipv4.header.destination_address,
            udp,
        );
        checksum(&[pseudo.as_bytes(), &ipv4.payload]) == 0
    }

    fn verify_udp_checksum_v6(buf: &[u8]) -> bool {
        let ipv6 = Ipv6::<[u8]>::ref_from_bytes(buf).unwrap();
        let udp = Udp::<[u8]>::ref_from_bytes(&ipv6.payload).unwrap();
        if udp.header.checksum.get() == 0 {
            return true;
        }
        let pseudo = PseudoHeaderV6::from_udp(
            ipv6.header.source_address,
            ipv6.header.destination_address,
            udp,
        );
        checksum(&[pseudo.as_bytes(), &ipv6.payload]) == 0
    }

    #[test]
    fn rewrite_source_ip_changes_address_and_checksums() {
        let src = Ipv4Addr::new(10, 64, 0, 2);
        let dst = Ipv4Addr::new(192, 168, 1, 1);
        let new_src = Ipv4Addr::new(10, 100, 0, 5);

        let mut packet = make_ipv4_udp_packet(src, dst, b"hello nat");

        // Verify initial checksums are valid.
        let buf = packet.as_bytes();
        assert!(
            verify_ipv4_header_checksum(buf),
            "initial IP checksum invalid"
        );
        assert!(verify_udp_checksum_v4(buf), "initial UDP checksum invalid");

        rewrite_source_ip(&mut packet, src, new_src, None, None);

        let buf = packet.as_bytes();
        let ipv4 = Ipv4::<[u8]>::ref_from_bytes(buf).unwrap();
        // Source address should now be new_src.
        assert_eq!(ipv4.header.source(), new_src);
        // Destination should be unchanged.
        assert_eq!(ipv4.header.destination(), dst);
        // Checksums should still be valid.
        assert!(
            verify_ipv4_header_checksum(buf),
            "IP checksum invalid after NAT"
        );
        assert!(
            verify_udp_checksum_v4(buf),
            "UDP checksum invalid after NAT"
        );
    }

    #[test]
    fn rewrite_dest_ip_changes_address_and_checksums() {
        let src = Ipv4Addr::new(192, 168, 1, 1);
        let dst = Ipv4Addr::new(10, 100, 0, 5);
        let new_dst = Ipv4Addr::new(10, 64, 0, 2);

        let mut packet = make_ipv4_udp_packet(src, dst, b"hello nat");

        let buf = packet.as_bytes();
        assert!(verify_ipv4_header_checksum(buf));
        assert!(verify_udp_checksum_v4(buf));

        rewrite_dest_ip(&mut packet, dst, new_dst, None, None);

        let buf = packet.as_bytes();
        let ipv4 = Ipv4::<[u8]>::ref_from_bytes(buf).unwrap();
        // Destination address should now be new_dst.
        assert_eq!(ipv4.header.destination(), new_dst);
        // Source should be unchanged.
        assert_eq!(ipv4.header.source(), src);
        assert!(
            verify_ipv4_header_checksum(buf),
            "IP checksum invalid after NAT"
        );
        assert!(
            verify_udp_checksum_v4(buf),
            "UDP checksum invalid after NAT"
        );
    }

    #[test]
    fn no_rewrite_when_address_does_not_match() {
        let src = Ipv4Addr::new(10, 64, 0, 2);
        let dst = Ipv4Addr::new(192, 168, 1, 1);
        let wrong_from = Ipv4Addr::new(10, 64, 0, 99);
        let to = Ipv4Addr::new(10, 100, 0, 5);

        let mut packet = make_ipv4_udp_packet(src, dst, b"no match");
        let original_bytes = packet.as_bytes().to_vec();

        rewrite_source_ip(&mut packet, wrong_from, to, None, None);

        // Packet should be unchanged.
        assert_eq!(packet.as_bytes(), &original_bytes[..]);
    }

    #[test]
    fn udp_zero_checksum_not_modified() {
        let src = Ipv4Addr::new(10, 64, 0, 2);
        let dst = Ipv4Addr::new(192, 168, 1, 1);
        let new_src = Ipv4Addr::new(10, 100, 0, 5);

        let udp_len = UdpHeader::LEN + 4;
        let total_len = Ipv4Header::LEN + udp_len;
        let mut buf = BytesMut::zeroed(total_len);

        {
            let ipv4 = Ipv4::<[u8]>::mut_from_bytes(&mut buf).unwrap();
            ipv4.header = Ipv4Header::new_for_length(src, dst, IpNextProtocol::Udp, udp_len as u16);
            let udp = crate::packet::Udp::<[u8]>::mut_from_bytes(&mut ipv4.payload).unwrap();
            udp.header.source_port = 1234u16.into();
            udp.header.destination_port = 5678u16.into();
            udp.header.length = (udp_len as u16).into();
            udp.header.checksum = 0u16.into(); // Explicitly zero = no checksum.
            udp.payload.copy_from_slice(b"test");
        }

        {
            let ipv4 = Ipv4::<[u8]>::mut_from_bytes(&mut buf).unwrap();
            ipv4.header.recompute_checksum();
        }

        let mut packet = Packet::from_bytes(buf).try_into_ip().unwrap();
        rewrite_source_ip(&mut packet, src, new_src, None, None);

        let buf = packet.as_bytes();
        let ipv4 = Ipv4::<[u8]>::ref_from_bytes(buf).unwrap();
        let udp = Udp::<[u8]>::ref_from_bytes(&ipv4.payload).unwrap();
        // UDP checksum should still be zero.
        assert_eq!(udp.header.checksum.get(), 0);
        // But source should be rewritten.
        assert_eq!(ipv4.header.source(), new_src);
        // And IP checksum should be valid.
        assert!(verify_ipv4_header_checksum(buf));
    }

    #[test]
    fn incremental_checksum_matches_full_recompute() {
        // Build a packet, NAT it, and verify the UDP checksum matches a full recompute.
        let src = Ipv4Addr::new(10, 64, 0, 2);
        let dst = Ipv4Addr::new(8, 8, 8, 8);
        let new_src = Ipv4Addr::new(172, 16, 0, 42);

        let mut packet = make_ipv4_udp_packet(src, dst, b"checksum test payload");
        rewrite_source_ip(&mut packet, src, new_src, None, None);

        let buf = packet.as_bytes();
        let ipv4 = Ipv4::<[u8]>::ref_from_bytes(buf).unwrap();
        let incremental_cksum = Udp::<[u8]>::ref_from_bytes(&ipv4.payload)
            .unwrap()
            .header
            .checksum
            .get();

        // Verify the checksum is valid by summing pseudo-header + UDP; should fold to 0.
        let udp = Udp::<[u8]>::ref_from_bytes(&ipv4.payload).unwrap();
        let pseudo = PseudoHeaderV4::from_udp(
            ipv4.header.source_address,
            ipv4.header.destination_address,
            udp,
        );
        assert_eq!(
            checksum(&[pseudo.as_bytes(), &ipv4.payload]),
            0,
            "incremental checksum {incremental_cksum:#06x} is invalid"
        );
    }

    #[test]
    fn rewrite_source_ipv6_changes_address_and_checksum() {
        let src = Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 1);
        let dst = Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111);
        let new_src = Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 2);

        let mut packet = make_ipv6_udp_packet(src, dst, b"hello ipv6 nat");

        assert!(
            verify_udp_checksum_v6(packet.as_bytes()),
            "initial UDP checksum invalid"
        );

        rewrite_source_ip(
            &mut packet,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::UNSPECIFIED,
            Some(src),
            Some(new_src),
        );

        let buf = packet.as_bytes();
        let ipv6 = Ipv6::<[u8]>::ref_from_bytes(buf).unwrap();
        assert_eq!(
            ipv6.header.source(),
            new_src,
            "source address not rewritten"
        );
        assert_eq!(
            ipv6.header.destination(),
            dst,
            "destination address changed unexpectedly"
        );
        assert!(
            verify_udp_checksum_v6(buf),
            "UDP checksum invalid after NAT"
        );
    }

    #[test]
    fn rewrite_dest_ipv6_changes_address_and_checksum() {
        let src = Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 1);
        let dst = Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 2);
        let new_dst = Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 3);

        let mut packet = make_ipv6_udp_packet(src, dst, b"hello ipv6 nat dest");

        assert!(
            verify_udp_checksum_v6(packet.as_bytes()),
            "initial UDP checksum invalid"
        );

        rewrite_dest_ip(
            &mut packet,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::UNSPECIFIED,
            Some(dst),
            Some(new_dst),
        );

        let buf = packet.as_bytes();
        let ipv6 = Ipv6::<[u8]>::ref_from_bytes(buf).unwrap();
        assert_eq!(
            ipv6.header.source(),
            src,
            "source address changed unexpectedly"
        );
        assert_eq!(
            ipv6.header.destination(),
            new_dst,
            "destination address not rewritten"
        );
        assert!(
            verify_udp_checksum_v6(buf),
            "UDP checksum invalid after NAT"
        );
    }

    #[test]
    fn ipv6_incremental_checksum_matches_full_recompute() {
        let src = Ipv6Addr::new(0xfc00, 0xbbbb, 0xbbbb, 0xbb01, 0xd, 0, 0xc, 0xc2dd);
        let dst = Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111);
        let new_src = Ipv6Addr::new(0xfd00, 0x1111, 0, 0, 0, 0, 0, 0x42);

        let mut packet = make_ipv6_udp_packet(src, dst, b"ipv6 checksum test payload");
        rewrite_source_ip(
            &mut packet,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::UNSPECIFIED,
            Some(src),
            Some(new_src),
        );

        let buf = packet.as_bytes();
        let ipv6 = Ipv6::<[u8]>::ref_from_bytes(buf).unwrap();
        let incremental_cksum = Udp::<[u8]>::ref_from_bytes(&ipv6.payload)
            .unwrap()
            .header
            .checksum
            .get();

        // Verify the checksum is valid by summing pseudo-header + UDP; should fold to 0.
        let udp = Udp::<[u8]>::ref_from_bytes(&ipv6.payload).unwrap();
        let pseudo = PseudoHeaderV6::from_udp(
            ipv6.header.source_address,
            ipv6.header.destination_address,
            udp,
        );
        assert_eq!(
            checksum(&[pseudo.as_bytes(), &ipv6.payload]),
            0,
            "incremental checksum {incremental_cksum:#06x} is invalid"
        );
    }
}
