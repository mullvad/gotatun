use std::fmt::{self, Debug};
use std::mem::offset_of;

use eyre::{bail, eyre};
use zerocopy::{FromBytes, FromZeros, Immutable, IntoBytes, KnownLayout, Unaligned, little_endian};

use crate::packet::util::size_must_be;
use crate::packet::{CheckedPayload, Packet};

#[derive(FromBytes, IntoBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
pub struct Wg {
    pub packet_type: WgPacketType,
    rest: [u8],
}

impl Debug for Wg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Wg")
            .field("packet_type", &self.packet_type)
            .finish()
    }
}

pub enum WgKind {
    HandshakeInit(Packet<WgHandshakeInit>),
    HandshakeResp(Packet<WgHandshakeResp>),
    CookieReply(Packet<WgCookieReply>),
    Data(Packet<WgData>),
}

impl From<WgKind> for Packet {
    fn from(kind: WgKind) -> Self {
        match kind {
            WgKind::HandshakeInit(packet) => packet.into(),
            WgKind::HandshakeResp(packet) => packet.into(),
            WgKind::CookieReply(packet) => packet.into(),
            WgKind::Data(packet) => packet.into(),
        }
    }
}

#[derive(FromBytes, IntoBytes, KnownLayout, Unaligned, Immutable, PartialEq, Eq, Clone, Copy)]
#[repr(transparent)]
// TODO: This is just one byte
pub struct WgPacketType(pub little_endian::U32);

impl WgPacketType {
    #![allow(non_upper_case_globals)]
    pub const HandshakeInit: WgPacketType = WgPacketType(little_endian::U32::new(1));
    pub const HandshakeResp: WgPacketType = WgPacketType(little_endian::U32::new(2));
    pub const CookieReply: WgPacketType = WgPacketType(little_endian::U32::new(3));
    pub const Data: WgPacketType = WgPacketType(little_endian::U32::new(4));
}

#[derive(FromBytes, IntoBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
pub struct WgDataHeader {
    // INVARIANT: Must be WgPacketType::Data
    // TODO: make private
    pub packet_type: WgPacketType,

    pub receiver_idx: little_endian::U32,
    pub counter: little_endian::U64,
}

impl WgDataHeader {
    /// Header length
    pub const LEN: usize = size_must_be::<Self>(16);
    /// Data packet overhead: header and tag (16 bytes)
    pub const OVERHEAD: usize = Self::LEN + 16;
}

#[derive(FromBytes, IntoBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
pub struct WgData {
    pub header: WgDataHeader,
    pub encrypted_encapsulated_packet_and_tag: [u8],
}

impl WgData {
    pub fn encrypted_encapsulated_packet_mut(&mut self) -> &mut [u8] {
        let (encrypted_encapsulated_packet, _tag) = self
            .encrypted_encapsulated_packet_and_tag
            .split_last_chunk_mut::<16>()
            .unwrap(); // TODO

        encrypted_encapsulated_packet
    }

    pub fn tag_mut(&mut self) -> &mut [u8] {
        let (_, tag) = self
            .encrypted_encapsulated_packet_and_tag
            .split_last_chunk_mut::<16>()
            .unwrap(); // TODO

        tag
    }
}

/// Trait for common handshake fields
pub trait WgHandshakeBase:
    FromBytes + IntoBytes + KnownLayout + Unaligned + Immutable + CheckedPayload
{
    const LEN: usize;
    const MAC1_OFF: usize;
    const MAC2_OFF: usize;

    /// Get sender_id
    fn sender_idx(&self) -> u32;

    /// Get a mutable reference to MAC1
    fn mac1_mut(&mut self) -> &mut [u8; 16];

    /// Get a mutable reference to MAC2
    fn mac2_mut(&mut self) -> &mut [u8; 16];

    /// Get MAC1
    fn mac1(&self) -> &[u8; 16];

    /// Get MAC2
    fn mac2(&self) -> &[u8; 16];
}

#[derive(FromBytes, IntoBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
pub struct WgHandshakeInit {
    // INVARIANT: Must be WgPacketType::HandshakeInit
    packet_type: WgPacketType,

    pub sender_idx: little_endian::U32,
    pub unencrypted_ephemeral: [u8; 32],
    pub encrypted_static: [u8; 48],
    pub encrypted_timestamp: [u8; 28],
    pub mac1: [u8; 16],
    pub mac2: [u8; 16],
}

impl WgHandshakeInit {
    pub const LEN: usize = size_must_be::<Self>(148);

    pub fn new() -> Self {
        Self {
            packet_type: WgPacketType::HandshakeInit,
            ..WgHandshakeInit::new_zeroed()
        }
    }

    pub fn packet_type(&self) -> WgPacketType {
        self.packet_type
    }
}

impl WgHandshakeBase for WgHandshakeInit {
    const LEN: usize = Self::LEN;
    const MAC1_OFF: usize = offset_of!(Self, mac1);
    const MAC2_OFF: usize = offset_of!(Self, mac2);

    fn sender_idx(&self) -> u32 {
        self.sender_idx.get()
    }

    fn mac1_mut(&mut self) -> &mut [u8; 16] {
        &mut self.mac1
    }

    fn mac2_mut(&mut self) -> &mut [u8; 16] {
        &mut self.mac2
    }

    fn mac1(&self) -> &[u8; 16] {
        &self.mac1
    }

    fn mac2(&self) -> &[u8; 16] {
        &self.mac2
    }
}

impl Default for WgHandshakeInit {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(FromBytes, IntoBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
pub struct WgHandshakeResp {
    // INVARIANT: Must be WgPacketType::HandshakeResp
    packet_type: WgPacketType,

    pub sender_idx: little_endian::U32,
    pub receiver_idx: little_endian::U32,
    pub unencrypted_ephemeral: [u8; 32],
    pub encrypted_nothing: [u8; 16],
    pub mac1: [u8; 16],
    pub mac2: [u8; 16],
}

impl WgHandshakeResp {
    pub const LEN: usize = size_must_be::<Self>(92);

    pub fn new(sender_idx: u32, receiver_idx: u32, unencrypted_ephemeral: [u8; 32]) -> Self {
        Self {
            packet_type: WgPacketType::HandshakeResp,
            sender_idx: sender_idx.into(),
            receiver_idx: receiver_idx.into(),
            unencrypted_ephemeral,
            encrypted_nothing: [0; 16],
            mac1: [0u8; 16],
            mac2: [0u8; 16],
        }
    }
}

impl WgHandshakeBase for WgHandshakeResp {
    const LEN: usize = Self::LEN;
    const MAC1_OFF: usize = offset_of!(Self, mac1);
    const MAC2_OFF: usize = offset_of!(Self, mac2);

    fn sender_idx(&self) -> u32 {
        self.sender_idx.get()
    }

    fn mac1_mut(&mut self) -> &mut [u8; 16] {
        &mut self.mac1
    }

    fn mac2_mut(&mut self) -> &mut [u8; 16] {
        &mut self.mac2
    }

    fn mac1(&self) -> &[u8; 16] {
        &self.mac1
    }

    fn mac2(&self) -> &[u8; 16] {
        &self.mac2
    }
}

#[derive(FromBytes, IntoBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
pub struct WgCookieReply {
    // INVARIANT: Must be WgPacketType::CookieReply
    packet_type: WgPacketType,

    pub receiver_idx: little_endian::U32,
    pub nonce: [u8; 24],
    pub encrypted_cookie: [u8; 32],
}

impl WgCookieReply {
    const LEN: usize = size_must_be::<Self>(64);

    pub fn new() -> Self {
        Self {
            packet_type: WgPacketType::CookieReply,
            ..Self::new_zeroed()
        }
    }
}

impl Default for WgCookieReply {
    fn default() -> Self {
        Self::new()
    }
}

impl Packet {
    /// Convert into a wireguard packet while sanity-checking packet type and size.
    pub fn try_into_wg(self) -> eyre::Result<Packet<Wg>> {
        let _wg = Wg::ref_from_bytes(self.as_bytes())
            .map_err(|_| eyre!("Not a wireguard packet, too small."))?;

        Ok(self.cast())
    }
}

impl Packet<Wg> {
    pub fn into_kind(self) -> eyre::Result<WgKind> {
        let len = self.as_bytes().len();
        match (self.packet_type, len) {
            (WgPacketType::HandshakeInit, WgHandshakeInit::LEN) => {
                Ok(WgKind::HandshakeInit(self.cast()))
            }
            (WgPacketType::HandshakeResp, WgHandshakeResp::LEN) => {
                Ok(WgKind::HandshakeResp(self.cast()))
            }
            (WgPacketType::CookieReply, WgCookieReply::LEN) => Ok(WgKind::CookieReply(self.cast())),
            (WgPacketType::Data, WgDataHeader::OVERHEAD..) => Ok(WgKind::Data(self.cast())),
            _ => bail!("Not a wireguard packet, bad type/size."),
        }
    }
}

impl Debug for WgPacketType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            &WgPacketType::HandshakeInit => "HandshakeInit",
            &WgPacketType::HandshakeResp => "HandshakeResp",
            &WgPacketType::CookieReply => "CookieReply",
            &WgPacketType::Data => "Data",

            WgPacketType(t) => return Debug::fmt(t, f),
        };

        f.debug_tuple(name).finish()
    }
}
