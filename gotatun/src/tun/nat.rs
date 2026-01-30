// Copyright (c) 2025 Mullvad VPN AB. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Source/destination NAT adapters for [`IpRecv`] and [`IpSend`].
//!
//! [`NatIpRecv`] rewrites the source IP on received (outbound) packets.
//! [`NatIpSend`] rewrites the destination IP on sent (inbound) packets.

use std::io;
use std::net::Ipv4Addr;

use zerocopy::IntoBytes;

use crate::packet::{Ip, Ipv4Header, Packet, PacketBufPool};
use crate::tun::{IpRecv, IpSend, MtuWatcher};

// TODO: could be single type that implements both IpRecv and IpSend

/// Rewrites source IP on received packets (outbound NAT).
pub struct NatIpRecv<R: IpRecv> {
    inner: R,
    /// Source IP to match and replace (the outer VPN IP)
    from_v4: Ipv4Addr,
    /// Replacement source IP (the inner tunnel IP)
    to_v4: Ipv4Addr,
}

/// Rewrites destination IP on sent packets (inbound NAT).
pub struct NatIpSend<S: IpSend> {
    inner: S,
    /// Dest IP to match and replace (the inner tunnel IP)
    from_v4: Ipv4Addr,
    /// Replacement dest IP (the outer VPN IP)
    to_v4: Ipv4Addr,
}

impl<R: IpRecv> NatIpRecv<R> {
    pub fn new(inner: R, from: Ipv4Addr, to: Ipv4Addr) -> Self {
        Self {
            inner,
            from_v4: from,
            to_v4: to,
        }
    }
}

impl<S: IpSend> NatIpSend<S> {
    pub fn new(inner: S, from: Ipv4Addr, to: Ipv4Addr) -> Self {
        Self {
            inner,
            from_v4: from,
            to_v4: to,
        }
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
        Ok(packets.map(move |mut packet| {
            rewrite_source_ip(&mut packet, from_v4, to_v4);
            packet
        }))
    }

    fn mtu(&self) -> MtuWatcher {
        self.inner.mtu()
    }
}

impl<S: IpSend> IpSend for NatIpSend<S> {
    async fn send(&mut self, mut packet: Packet<Ip>) -> io::Result<()> {
        rewrite_dest_ip(&mut packet, self.from_v4, self.to_v4);
        self.inner.send(packet).await
    }
}

// --- IP rewriting ---

/// Rewrite the source IP of a packet if it matches `from`.
fn rewrite_source_ip(packet: &mut Packet<Ip>, from_v4: Ipv4Addr, to_v4: Ipv4Addr) {
    let buf = packet.as_bytes();
    let version = buf[0] >> 4;
    match version {
        4 => rewrite_source_ipv4(packet, from_v4, to_v4),
        6 => { /* IPv6 NAT not yet needed */ }
        _ => {}
    }
}

/// Rewrite the destination IP of a packet if it matches `from`.
fn rewrite_dest_ip(packet: &mut Packet<Ip>, from_v4: Ipv4Addr, to_v4: Ipv4Addr) {
    let buf = packet.as_bytes();
    let version = buf[0] >> 4;
    match version {
        4 => rewrite_dest_ipv4(packet, from_v4, to_v4),
        6 => { /* IPv6 NAT not yet needed */ }
        _ => {}
    }
}

fn rewrite_source_ipv4(packet: &mut Packet<Ip>, from: Ipv4Addr, to: Ipv4Addr) {
    // Source address is at offset 12..16 in the IPv4 header.
    let buf = packet.as_bytes();
    if buf.len() < Ipv4Header::LEN {
        return;
    }
    let current_src = Ipv4Addr::new(buf[12], buf[13], buf[14], buf[15]);
    if current_src != from {
        return;
    }

    let old_addr = from.to_bits().to_be_bytes();
    let new_addr = to.to_bits().to_be_bytes();
    let ihl = (buf[0] & 0x0f) as usize;
    let ip_header_len = ihl * 4;
    let protocol = buf[9];

    // Rewrite source address.
    let buf = packet.as_mut_bytes();
    buf[12..16].copy_from_slice(&new_addr);

    // Recompute IPv4 header checksum.
    recompute_ipv4_header_checksum(buf);

    // Incrementally update transport checksum.
    update_transport_checksum(buf, ip_header_len, protocol, &old_addr, &new_addr);
}

fn rewrite_dest_ipv4(packet: &mut Packet<Ip>, from: Ipv4Addr, to: Ipv4Addr) {
    // Destination address is at offset 16..20 in the IPv4 header.
    let buf = packet.as_bytes();
    if buf.len() < Ipv4Header::LEN {
        return;
    }
    let current_dst = Ipv4Addr::new(buf[16], buf[17], buf[18], buf[19]);
    if current_dst != from {
        return;
    }

    let old_addr = from.to_bits().to_be_bytes();
    let new_addr = to.to_bits().to_be_bytes();
    let ihl = (buf[0] & 0x0f) as usize;
    let ip_header_len = ihl * 4;
    let protocol = buf[9];

    // Rewrite destination address.
    let buf = packet.as_mut_bytes();
    buf[16..20].copy_from_slice(&new_addr);

    // Recompute IPv4 header checksum.
    recompute_ipv4_header_checksum(buf);

    // Incrementally update transport checksum.
    update_transport_checksum(buf, ip_header_len, protocol, &old_addr, &new_addr);
}

/// Recompute the IPv4 header checksum from scratch.
///
/// The header checksum field (offset 10..12) is set to zero before computing.
fn recompute_ipv4_header_checksum(buf: &mut [u8]) {
    let ihl = (buf[0] & 0x0f) as usize;
    let header_len = ihl * 4;
    if buf.len() < header_len {
        return;
    }

    // Zero out the checksum field before computing.
    buf[10] = 0;
    buf[11] = 0;

    let mut sum: u32 = 0;
    for i in (0..header_len).step_by(2) {
        let word = if i + 1 < header_len {
            u16::from_be_bytes([buf[i], buf[i + 1]])
        } else {
            u16::from_be_bytes([buf[i], 0])
        };
        sum += u32::from(word);
    }

    // Fold carry bits.
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    let checksum = !(sum as u16);
    buf[10..12].copy_from_slice(&checksum.to_be_bytes());
}

/// Incrementally update the transport-layer (TCP/UDP) checksum per RFC 1624.
///
/// `old_addr` and `new_addr` are the 4-byte IPv4 addresses that changed.
fn update_transport_checksum(
    buf: &mut [u8],
    ip_header_len: usize,
    protocol: u8,
    old_addr: &[u8; 4],
    new_addr: &[u8; 4],
) {
    // Determine transport checksum offset within the transport header.
    let checksum_offset = match protocol {
        6 => Some(16), // TCP: checksum at offset 16 in TCP header
        17 => Some(6), // UDP: checksum at offset 6 in UDP header
        _ => None,     // Other protocols: skip
    };

    let Some(offset) = checksum_offset else {
        return;
    };

    let cksum_pos = ip_header_len + offset;
    if buf.len() < cksum_pos + 2 {
        return;
    }

    let old_check = u16::from_be_bytes([buf[cksum_pos], buf[cksum_pos + 1]]);

    // For UDP, a checksum of 0 means "no checksum"; don't update it.
    if protocol == 17 && old_check == 0 {
        return;
    }

    let new_check = incremental_checksum_update(old_check, old_addr, new_addr);

    buf[cksum_pos..cksum_pos + 2].copy_from_slice(&new_check.to_be_bytes());
}

/// RFC 1624 incremental checksum update.
///
/// Given the old checksum and the old/new values of the changed 16-bit words,
/// compute the new checksum without re-scanning the entire packet.
///
/// HC' = ~(~HC + ~m + m')  where HC is the old checksum, m is old data, m' is new data.
/// All arithmetic is ones'-complement (with carry folding).
fn incremental_checksum_update(old_check: u16, old_addr: &[u8; 4], new_addr: &[u8; 4]) -> u16 {
    let mut sum: u32 = u32::from(!old_check);

    // Subtract old address words, add new address words.
    let old_w0 = u16::from_be_bytes([old_addr[0], old_addr[1]]);
    let old_w1 = u16::from_be_bytes([old_addr[2], old_addr[3]]);
    let new_w0 = u16::from_be_bytes([new_addr[0], new_addr[1]]);
    let new_w1 = u16::from_be_bytes([new_addr[2], new_addr[3]]);

    sum += u32::from(!old_w0);
    sum += u32::from(!old_w1);
    sum += u32::from(new_w0);
    sum += u32::from(new_w1);

    // Fold carry.
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;
    use zerocopy::{FromBytes, IntoBytes};

    use crate::packet::{IpNextProtocol, Ipv4, Ipv4Header, UdpHeader};

    /// Build a minimal IPv4/UDP packet with a valid header checksum and UDP checksum.
    fn make_ipv4_udp_packet(src: Ipv4Addr, dst: Ipv4Addr, udp_payload: &[u8]) -> Packet<Ip> {
        let udp_len = UdpHeader::LEN + udp_payload.len();
        let total_len = Ipv4Header::LEN + udp_len;
        let mut buf = BytesMut::zeroed(total_len);

        // Build IPv4 header.
        {
            let ipv4 = Ipv4::<[u8]>::mut_from_bytes(&mut buf).unwrap();
            ipv4.header = Ipv4Header::new_for_length(src, dst, IpNextProtocol::Udp, udp_len as u16);
            // Write UDP header into the payload.
            let udp = crate::packet::Udp::<[u8]>::mut_from_bytes(&mut ipv4.payload).unwrap();
            udp.header.source_port = 1234u16.into();
            udp.header.destination_port = 5678u16.into();
            udp.header.length = (udp_len as u16).into();
            udp.header.checksum = 0u16.into();
            udp.payload.copy_from_slice(udp_payload);
        }

        // Compute valid IPv4 header checksum.
        recompute_ipv4_header_checksum(&mut buf);

        // Compute valid UDP checksum (pseudo-header + UDP).
        {
            let ipv4 = Ipv4::<[u8]>::ref_from_bytes(&buf).unwrap();
            let cksum = compute_udp_checksum_v4(&ipv4.header, &ipv4.payload);
            let ipv4 = Ipv4::<[u8]>::mut_from_bytes(&mut buf).unwrap();
            let udp = crate::packet::Udp::<[u8]>::mut_from_bytes(&mut ipv4.payload).unwrap();
            udp.header.checksum = cksum.into();
        }

        Packet::from_bytes(buf).try_into_ip().unwrap()
    }

    /// Compute the UDP checksum over pseudo-header + UDP header + payload.
    fn compute_udp_checksum_v4(ip_header: &Ipv4Header, transport: &[u8]) -> u16 {
        let mut sum: u32 = 0;

        // Pseudo-header: src IP, dst IP, zero, protocol, UDP length.
        let src = ip_header.source().to_bits().to_be_bytes();
        let dst = ip_header.destination().to_bits().to_be_bytes();
        sum += u32::from(u16::from_be_bytes([src[0], src[1]]));
        sum += u32::from(u16::from_be_bytes([src[2], src[3]]));
        sum += u32::from(u16::from_be_bytes([dst[0], dst[1]]));
        sum += u32::from(u16::from_be_bytes([dst[2], dst[3]]));
        sum += u32::from(IpNextProtocol::Udp.as_bytes()[0]) as u32;
        sum += transport.len() as u32;

        // UDP header + payload (with checksum field zeroed).
        for i in (0..transport.len()).step_by(2) {
            // Skip the checksum field (offset 6..8 in UDP header).
            if i == 6 {
                continue;
            }
            let word = if i + 1 < transport.len() {
                u16::from_be_bytes([transport[i], transport[i + 1]])
            } else {
                u16::from_be_bytes([transport[i], 0])
            };
            sum += u32::from(word);
        }

        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }

        let cksum = !(sum as u16);
        if cksum == 0 { 0xffff } else { cksum }
    }

    /// Verify that the IPv4 header checksum in `buf` is correct.
    fn verify_ipv4_header_checksum(buf: &[u8]) -> bool {
        let ihl = (buf[0] & 0x0f) as usize;
        let header_len = ihl * 4;
        let mut sum: u32 = 0;
        for i in (0..header_len).step_by(2) {
            let word = if i + 1 < header_len {
                u16::from_be_bytes([buf[i], buf[i + 1]])
            } else {
                u16::from_be_bytes([buf[i], 0])
            };
            sum += u32::from(word);
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        sum as u16 == 0xffff
    }

    /// Verify UDP checksum with pseudo-header.
    fn verify_udp_checksum_v4(buf: &[u8]) -> bool {
        let ihl = (buf[0] & 0x0f) as usize;
        let ip_header_len = ihl * 4;
        let transport = &buf[ip_header_len..];
        let cksum_field = u16::from_be_bytes([transport[6], transport[7]]);
        if cksum_field == 0 {
            return true; // no checksum
        }

        let mut sum: u32 = 0;

        // Pseudo-header.
        sum += u32::from(u16::from_be_bytes([buf[12], buf[13]]));
        sum += u32::from(u16::from_be_bytes([buf[14], buf[15]]));
        sum += u32::from(u16::from_be_bytes([buf[16], buf[17]]));
        sum += u32::from(u16::from_be_bytes([buf[18], buf[19]]));
        sum += u32::from(buf[9]); // protocol
        sum += transport.len() as u32;

        // Transport data.
        for i in (0..transport.len()).step_by(2) {
            let word = if i + 1 < transport.len() {
                u16::from_be_bytes([transport[i], transport[i + 1]])
            } else {
                u16::from_be_bytes([transport[i], 0])
            };
            sum += u32::from(word);
        }

        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        sum as u16 == 0xffff
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

        rewrite_source_ip(&mut packet, src, new_src);

        let buf = packet.as_bytes();
        // Source address should now be new_src.
        assert_eq!(Ipv4Addr::new(buf[12], buf[13], buf[14], buf[15]), new_src,);
        // Destination should be unchanged.
        assert_eq!(Ipv4Addr::new(buf[16], buf[17], buf[18], buf[19]), dst,);
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

        rewrite_dest_ip(&mut packet, dst, new_dst);

        let buf = packet.as_bytes();
        // Destination address should now be new_dst.
        assert_eq!(Ipv4Addr::new(buf[16], buf[17], buf[18], buf[19]), new_dst,);
        // Source should be unchanged.
        assert_eq!(Ipv4Addr::new(buf[12], buf[13], buf[14], buf[15]), src,);
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

        rewrite_source_ip(&mut packet, wrong_from, to);

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
        recompute_ipv4_header_checksum(&mut buf);

        let mut packet = Packet::from_bytes(buf).try_into_ip().unwrap();
        rewrite_source_ip(&mut packet, src, new_src);

        let buf = packet.as_bytes();
        // UDP checksum should still be zero.
        let ihl = (buf[0] & 0x0f) as usize;
        let udp_cksum_pos = ihl * 4 + 6;
        assert_eq!(buf[udp_cksum_pos], 0);
        assert_eq!(buf[udp_cksum_pos + 1], 0);
        // But source should be rewritten.
        assert_eq!(Ipv4Addr::new(buf[12], buf[13], buf[14], buf[15]), new_src);
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
        rewrite_source_ip(&mut packet, src, new_src);

        let buf = packet.as_bytes();
        let ihl = (buf[0] & 0x0f) as usize;
        let ip_header_len = ihl * 4;

        // Extract the incremental checksum.
        let incremental_cksum =
            u16::from_be_bytes([buf[ip_header_len + 6], buf[ip_header_len + 7]]);

        // Compute full checksum from scratch.
        let ipv4 = Ipv4::<[u8]>::ref_from_bytes(buf).unwrap();
        let full_cksum = compute_udp_checksum_v4(&ipv4.header, &ipv4.payload);

        assert_eq!(
            incremental_cksum, full_cksum,
            "incremental checksum {incremental_cksum:#06x} != full checksum {full_cksum:#06x}"
        );
    }
}
