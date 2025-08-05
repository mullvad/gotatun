use std::fmt;

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned, big_endian};

use super::util::assert_size;

#[repr(C)]
#[derive(Debug, FromBytes, IntoBytes, KnownLayout, Unaligned, Immutable)]
pub struct Udp<Payload: ?Sized = [u8]> {
    pub header: UdpHeader,
    pub payload: Payload,
}

#[repr(C, packed)]
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Unaligned, Immutable)]
pub struct UdpHeader {
    pub source_port: big_endian::U16,
    pub destination_port: big_endian::U16,

    /// Length of the UDP datagram, header + payload.
    pub length: big_endian::U16,

    /// Checksum of header + payload.
    pub checksum: big_endian::U16,
}

const _: () = assert_size::<UdpHeader>(UdpHeader::LEN);
impl UdpHeader {
    pub const LEN: usize = 8;
}

impl Udp {
    /// Maximum theoretical length of a UDP packet (including the header).
    ///
    /// In practice, you'll need to subtract the IP header from this.
    pub const MAX_LEN: usize = (1 << 16) - 1;

    /// Maximum theoretical length of a UDP payload.
    pub const MAX_PAYLOAD_LEN: usize = Udp::MAX_LEN - UdpHeader::LEN;
}

impl fmt::Debug for UdpHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UdpHeader")
            .field("source_port", &self.source_port.get())
            .field("destination_port", &self.destination_port.get())
            .field("length", &self.length.get())
            .field("checksum", &self.checksum.get())
            .finish()
    }
}
