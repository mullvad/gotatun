use std::fmt;

use bitfield_struct::bitfield;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned, big_endian};

use crate::packet::util::size_must_be;

use super::{Ipv4, Ipv6};

#[repr(C)]
#[derive(FromBytes, IntoBytes, KnownLayout, Unaligned, Immutable)]
pub struct Tcp<OptionsAndPayload: ?Sized = [u8]> {
    pub header: TcpHeader,
    pub options_and_payload: OptionsAndPayload,
}

impl fmt::Debug for Tcp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Tcp")
            .field("header", &self.header)
            .field("options", &self.options())
            .field("payload", &self.payload())
            .finish()
    }
}

#[repr(C, packed)]
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Unaligned, Immutable)]
pub struct TcpHeader {
    pub source_port: big_endian::U16,
    pub destination_port: big_endian::U16,
    pub seq_num: big_endian::U32,
    pub ack_num: big_endian::U32,
    pub data_offset: TcpDataOffset,
    pub flags: TcpFlags,
    pub window: big_endian::U16,
    pub checksum: big_endian::U16,
    pub urgent_pointer: big_endian::U16,
}

#[bitfield(u8, order = Msb)]
#[derive(FromBytes, IntoBytes, KnownLayout, Unaligned, Immutable, PartialEq, Eq)]
pub struct TcpFlags {
    pub cwr: bool,
    pub ece: bool,
    pub urg: bool,
    pub ack: bool,
    pub psh: bool,
    pub rst: bool,
    pub syn: bool,
    pub fin: bool,
}

#[bitfield(u8, order = Msb)]
#[derive(FromBytes, IntoBytes, KnownLayout, Unaligned, Immutable, PartialEq, Eq)]
pub struct TcpDataOffset {
    /// Offset in `u32`s from the start of [TcpHeader] to the start of the payload.
    ///
    /// Must be at least 5.
    #[bits(4)]
    pub data_offset: u8,

    #[bits(4)]
    _reserved: u8,
}

impl TcpDataOffset {
    /// Set data_offset to `5`, which means that the TCP header contains _no_ options.
    pub const fn no_options() -> Self {
        TcpDataOffset::new().with_data_offset(5)
    }
}

impl TcpHeader {
    /// Length of a [TcpHeader]. Not including TCP options.
    pub const LEN: usize = size_must_be::<TcpHeader>(20);

    pub const fn fin(&self) -> bool {
        self.flags.fin()
    }
    pub const fn syn(&self) -> bool {
        self.flags.syn()
    }
    pub const fn rst(&self) -> bool {
        self.flags.rst()
    }
    pub const fn psh(&self) -> bool {
        self.flags.psh()
    }
    pub const fn ack(&self) -> bool {
        self.flags.ack()
    }
    pub const fn urg(&self) -> bool {
        self.flags.urg()
    }
    pub const fn ece(&self) -> bool {
        self.flags.ece()
    }
    pub const fn cwr(&self) -> bool {
        self.flags.cwr()
    }

    pub const fn set_fin(&mut self, value: bool) {
        self.flags.set_fin(value);
    }
    pub const fn set_syn(&mut self, value: bool) {
        self.flags.set_syn(value);
    }
    pub const fn set_rst(&mut self, value: bool) {
        self.flags.set_rst(value);
    }
    pub const fn set_psh(&mut self, value: bool) {
        self.flags.set_psh(value);
    }
    pub const fn set_ack(&mut self, value: bool) {
        self.flags.set_ack(value);
    }
    pub const fn set_urg(&mut self, value: bool) {
        self.flags.set_urg(value);
    }
    pub const fn set_ece(&mut self, value: bool) {
        self.flags.set_ece(value);
    }
    pub const fn set_cwr(&mut self, value: bool) {
        self.flags.set_cwr(value);
    }

    pub const fn data_offset(&self) -> u8 {
        self.data_offset.data_offset()
    }
}

impl Tcp {
    /// Get the length of the TCP header options, in bytes.
    pub fn options_len(&self) -> Option<usize> {
        let data_offset = usize::from(self.header.data_offset());
        let options_words = data_offset.checked_sub(5)?;
        Some(options_words * size_of::<u32>())
    }

    /// Get the TCP payload portion of this packet.
    ///
    /// Returns `None` if [TcpHeader::data_offset] is either:
    /// - Malformed (i.e. `data_offset < 5`)
    /// - Too big and would overflow [Tcp::options_and_payload].
    pub fn payload(&self) -> Option<&[u8]> {
        let i = self.options_len()?;
        self.options_and_payload.get(i..)
    }

    /// Get the TCP options portion of the header.
    ///
    /// Returns `None` if [TcpHeader::data_offset] is either:
    /// - Malformed (i.e. `data_offset < 5`)
    /// - Too big and would overflow [Tcp::options_and_payload].
    pub fn options(&self) -> Option<&[u8]> {
        let i = self.options_len()?;
        self.options_and_payload.get(..i)
    }
}

impl Ipv4<Tcp> {
    /// Calculate and return the TCP checksum for this packet.
    #[must_use]
    pub fn calculate_tcp_checksum(&self) -> u16 {
        let tcp = &self.payload;
        pnet_packet::util::ipv4_checksum(
            tcp.as_bytes(),
            8,
            &[],
            &self.header.source(),
            &self.header.destination(),
            pnet_packet::ip::IpNextHeaderProtocols::Tcp,
        )
    }

    /// Calculate and set the TCP checksum for this packet.
    pub fn update_tcp_checksum(&mut self) {
        self.payload.header.checksum = self.calculate_tcp_checksum().into();
    }
}

impl Ipv6<Tcp> {
    /// Calculate and return the TCP checksum for this packet.
    #[must_use]
    pub fn calculate_tcp_checksum(&self) -> u16 {
        let tcp = &self.payload;
        pnet_packet::util::ipv6_checksum(
            tcp.as_bytes(),
            8,
            &[],
            &self.header.source(),
            &self.header.destination(),
            pnet_packet::ip::IpNextHeaderProtocols::Tcp,
        )
    }

    /// Calculate and set the TCP checksum for this packet.
    pub fn update_tcp_checksum(&mut self) {
        self.payload.header.checksum = self.calculate_tcp_checksum().into();
    }
}

impl fmt::Debug for TcpHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TcpHeader")
            .field("source_port", &self.source_port.get())
            .field("destination_port", &self.destination_port.get())
            .field("seq_num", &self.seq_num.get())
            .field("ack_num", &self.ack_num.get())
            .field("fin", &self.fin())
            .field("syn", &self.syn())
            .field("rst", &self.rst())
            .field("psh", &self.psh())
            .field("ack", &self.ack())
            .field("urg", &self.urg())
            .field("ece", &self.ece())
            .field("cwr", &self.cwr())
            .field("data_offset", &self.data_offset())
            .field("window", &self.window.get())
            .field("checksum", &self.checksum.get())
            .field("urgent_pointer", &self.urgent_pointer.get())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use crate::packet::{Ipv4, Tcp};
    use zerocopy::TryFromBytes;

    const EXAMPLE_IPV4_TCP: &[u8] = &[
        0x45, 0x0, 0x1, 0x88, 0x47, 0x7a, 0x40, 0x0, 0x40, 0x6, 0xa5, 0x8f, 0xc0, 0xa8, 0x65, 0x7e,
        0xc0, 0xa8, 0x65, 0x97, 0xc5, 0xd8, 0x17, 0x66, 0x8f, 0x1, 0xa5, 0x50, 0xc2, 0x1d, 0x36,
        0x16, 0x80, 0x18, 0x60, 0x76, 0x7b, 0x9a, 0x0, 0x0, 0x1, 0x1, 0x8, 0xa, 0xcf, 0xc9, 0x84,
        0xe5, 0xd7, 0xd0, 0xdf, 0x50, /* payload snipped */
    ];

    #[test]
    fn tcp_header_layout() {
        let packet = Ipv4::<Tcp>::try_ref_from_bytes(EXAMPLE_IPV4_TCP).unwrap();
        let packet = &packet.payload;
        let header = &packet.header;

        assert!(header.psh());
        assert!(header.ack());

        assert!(!header.fin());
        assert!(!header.syn());
        assert!(!header.rst());
        assert!(!header.urg());
        assert!(!header.ece());
        assert!(!header.cwr());

        assert_eq!(header.data_offset(), 8);
        assert_eq!(packet.payload(), Some(&[][..]));

        assert_eq!(header.ack_num, 3256694294);
        assert_eq!(header.seq_num, 2399249744);
        assert_eq!(header.urgent_pointer, 0);
    }
}
