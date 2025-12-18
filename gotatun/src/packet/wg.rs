// Copyright (c) 2025 Mullvad VPN AB. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

#![deny(clippy::unwrap_used)]
use std::fmt::{self, Debug};
use std::mem::offset_of;
use std::ops::Deref;

use eyre::{bail, eyre};
use zerocopy::{FromBytes, FromZeros, Immutable, IntoBytes, KnownLayout, Unaligned, little_endian};

use crate::packet::util::size_must_be;
use crate::packet::{CheckedPayload, Packet};

#[derive(FromBytes, IntoBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct Wg {
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

/// An owned WireGuard [`Packet`] where its [`WgPacketType`] is known. See [`Packet::try_into_wg`].
pub enum WgKind {
    /// An owned [`WgHandshakeInit`] packet.
    HandshakeInit(Packet<WgHandshakeInit>),

    /// An owned [`WgHandshakeResp`] packet.
    HandshakeResp(Packet<WgHandshakeResp>),

    /// An owned [`WgCookieReply`] packet.
    CookieReply(Packet<WgCookieReply>),

    /// An owned [`WgData`] packet.
    Data(Packet<WgData>),
}

impl Debug for WgKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HandshakeInit(_) => f.debug_tuple("HandshakeInit").finish(),
            Self::HandshakeResp(_) => f.debug_tuple("HandshakeResp").finish(),
            Self::CookieReply(_) => f.debug_tuple("CookieReply").finish(),
            Self::Data(_) => f.debug_tuple("Data").finish(),
        }
    }
}

impl From<Packet<WgHandshakeInit>> for WgKind {
    fn from(p: Packet<WgHandshakeInit>) -> Self {
        WgKind::HandshakeInit(p)
    }
}

impl From<Packet<WgHandshakeResp>> for WgKind {
    fn from(p: Packet<WgHandshakeResp>) -> Self {
        WgKind::HandshakeResp(p)
    }
}

impl From<Packet<WgCookieReply>> for WgKind {
    fn from(p: Packet<WgCookieReply>) -> Self {
        WgKind::CookieReply(p)
    }
}

impl From<Packet<WgData>> for WgKind {
    fn from(p: Packet<WgData>) -> Self {
        WgKind::Data(p)
    }
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

/// The first byte of a WireGuard packet. This indentifies its type.
#[derive(FromBytes, IntoBytes, KnownLayout, Unaligned, Immutable, PartialEq, Eq, Clone, Copy)]
#[repr(transparent)]
pub struct WgPacketType(pub u8);

impl WgPacketType {
    #![allow(non_upper_case_globals)]

    /// The type discriminant of a [`WgHandshakeInit`] packet.
    pub const HandshakeInit: WgPacketType = WgPacketType(1);

    /// The type discriminant of a [`WgHandshakeResp`] packet.
    pub const HandshakeResp: WgPacketType = WgPacketType(2);

    /// The type discriminant of a [`WgCookieReply`] packet.
    pub const CookieReply: WgPacketType = WgPacketType(3);

    /// The type discriminant of a [`WgData`] packet.
    pub const Data: WgPacketType = WgPacketType(4);
}

/// Header of [`WgData`].
#[derive(FromBytes, IntoBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C)]
pub struct WgDataHeader {
    // INVARIANT: Must be WgPacketType::Data
    // TODO: make private
    pub packet_type: WgPacketType,
    _reserved_zeros: [u8; 4 - size_of::<WgPacketType>()],

    /// See [whitepaper](https://www.wireguard.com/papers/wireguard.pdf).
    pub receiver_idx: little_endian::U32,

    /// See [whitepaper](https://www.wireguard.com/papers/wireguard.pdf).
    pub counter: little_endian::U64,
}

impl WgDataHeader {
    /// Header length
    pub const LEN: usize = size_must_be::<Self>(16);
}

/// WireGuard data packet.
/// See [whitepaper](https://www.wireguard.com/papers/wireguard.pdf).
#[derive(FromBytes, IntoBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
pub struct WgData {
    /// Data packet header.
    pub header: WgDataHeader,

    /// Data packet payload and tag.
    pub encrypted_encapsulated_packet_and_tag: WgDataAndTag,
}

/// WireGuard data payload with a trailing tag.
///
/// This is essentially a byte slice that is at least [`WgData::TAG_LEN`] long.
#[derive(FromBytes, IntoBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C)]
pub struct WgDataAndTag {
    // Don't access these field directly. The tag is actually at the end of the struct.
    _tag_size: [u8; WgData::TAG_LEN],
    _extra: [u8],
}

impl WgData {
    /// Data packet overhead: header and tag (16 bytes)
    pub const OVERHEAD: usize = WgDataHeader::LEN + WgData::TAG_LEN;

    /// Length of the trailing `tag` field, in bytes.
    pub const TAG_LEN: usize = 16;

    /// Strip the tag from the encapsulated packet.
    fn split_encapsulated_packet_and_tag(&mut self) -> (&mut [u8], &mut [u8; WgData::TAG_LEN]) {
        self.encrypted_encapsulated_packet_and_tag
            .split_last_chunk_mut::<{ WgData::TAG_LEN }>()
            .expect("WgDataAndTag is at least TAG_LEN bytes long")
    }

    /// Get a reference to the encapsulated packet, without the trailing tag.
    pub fn encrypted_encapsulated_packet_mut(&mut self) -> &mut [u8] {
        let (encrypted_encapsulated_packet, _) = self.split_encapsulated_packet_and_tag();
        encrypted_encapsulated_packet
    }

    /// Get a reference to the tag of the encapsulated packet.
    ///
    /// Returns None if if the encapsulated packet + tag is less than 16 bytes.
    pub fn tag_mut(&mut self) -> &mut [u8; WgData::TAG_LEN] {
        let (_, tag) = self.split_encapsulated_packet_and_tag();
        tag
    }

    /// Returns true if the payload is empty.
    pub const fn is_empty(&self) -> bool {
        self.encrypted_encapsulated_packet_and_tag._extra.is_empty()
    }

    /// [`Self::is_empty`]. Keepalive packets are just data packets with no payload.
    pub const fn is_keepalive(&self) -> bool {
        self.is_empty()
    }
}

impl Deref for WgDataAndTag {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.as_bytes()
    }
}

impl std::ops::DerefMut for WgDataAndTag {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.as_mut_bytes()
    }
}

/// Trait for fields common to both [`WgHandshakeInit`] and [`WgHandshakeResp`].
pub trait WgHandshakeBase:
    FromBytes + IntoBytes + KnownLayout + Unaligned + Immutable + CheckedPayload
{
    /// Length of the handshake packet, in bytes.
    const LEN: usize;

    /// Offset of the `mac1` field.
    /// This is used for getting a byte slice up until `mac1`, i.e. `&packet[..MAC1_OFF]`.
    const MAC1_OFF: usize;

    /// Offset of the `mac2` field.
    /// This is used for getting a byte slice up until `mac2`, i.e. `&packet[..MAC2_OFF]`.
    const MAC2_OFF: usize;

    /// Get `sender_id`.
    fn sender_idx(&self) -> u32;

    /// Get a mutable reference to `mac1`.
    fn mac1_mut(&mut self) -> &mut [u8; 16];

    /// Get a mutable reference to `mac2`.
    fn mac2_mut(&mut self) -> &mut [u8; 16];

    /// Get `mac1`.
    fn mac1(&self) -> &[u8; 16];

    /// Get `mac2`.
    fn mac2(&self) -> &[u8; 16];

    /// Get packet until MAC1. Precisely equivalent to `packet[0..offsetof(packet.mac1)]`.
    #[inline(always)]
    fn until_mac1(&self) -> &[u8] {
        &self.as_bytes()[..Self::MAC1_OFF]
    }

    /// Get packet until MAC2. Precisely equivalent to `packet[0..offsetof(packet.mac2)]`.
    #[inline(always)]
    fn until_mac2(&self) -> &[u8] {
        &self.as_bytes()[..Self::MAC2_OFF]
    }
}

/// WireGuard handshake initialization packet.
/// See [whitepaper](https://www.wireguard.com/papers/wireguard.pdf).
#[derive(FromBytes, IntoBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
pub struct WgHandshakeInit {
    // INVARIANT: Must be WgPacketType::HandshakeInit
    packet_type: WgPacketType,
    _reserved_zeros: [u8; 4 - size_of::<WgPacketType>()],

    /// See [whitepaper](https://www.wireguard.com/papers/wireguard.pdf).
    pub sender_idx: little_endian::U32,

    /// See [whitepaper](https://www.wireguard.com/papers/wireguard.pdf).
    pub unencrypted_ephemeral: [u8; 32],

    /// See [whitepaper](https://www.wireguard.com/papers/wireguard.pdf).
    pub encrypted_static: [u8; 48],

    /// See [whitepaper](https://www.wireguard.com/papers/wireguard.pdf).
    pub encrypted_timestamp: [u8; 28],

    /// See [whitepaper](https://www.wireguard.com/papers/wireguard.pdf).
    pub mac1: [u8; 16],

    /// See [whitepaper](https://www.wireguard.com/papers/wireguard.pdf).
    pub mac2: [u8; 16],
}

impl WgHandshakeInit {
    /// Length of the packet, in bytes.
    pub const LEN: usize = size_must_be::<Self>(148);

    /// Construct a [`WgHandshakeInit`] where all fields except `packet_type` are zeroed.
    pub fn new() -> Self {
        Self {
            packet_type: WgPacketType::HandshakeInit,
            ..WgHandshakeInit::new_zeroed()
        }
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

/// WireGuard handshake response packet.
/// See [whitepaper](https://www.wireguard.com/papers/wireguard.pdf).
#[derive(FromBytes, IntoBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
pub struct WgHandshakeResp {
    // INVARIANT: Must be WgPacketType::HandshakeResp
    packet_type: WgPacketType,
    _reserved_zeros: [u8; 4 - size_of::<WgPacketType>()],

    /// See [whitepaper](https://www.wireguard.com/papers/wireguard.pdf).
    pub sender_idx: little_endian::U32,

    /// See [whitepaper](https://www.wireguard.com/papers/wireguard.pdf).
    pub receiver_idx: little_endian::U32,

    /// See [whitepaper](https://www.wireguard.com/papers/wireguard.pdf).
    pub unencrypted_ephemeral: [u8; 32],

    /// See [whitepaper](https://www.wireguard.com/papers/wireguard.pdf).
    pub encrypted_nothing: [u8; 16],

    /// See [whitepaper](https://www.wireguard.com/papers/wireguard.pdf).
    pub mac1: [u8; 16],

    /// See [whitepaper](https://www.wireguard.com/papers/wireguard.pdf).
    pub mac2: [u8; 16],
}

impl WgHandshakeResp {
    /// Length of the packet, in bytes.
    pub const LEN: usize = size_must_be::<Self>(92);

    /// Construct a [`WgHandshakeResp`].
    pub fn new(sender_idx: u32, receiver_idx: u32, unencrypted_ephemeral: [u8; 32]) -> Self {
        Self {
            packet_type: WgPacketType::HandshakeResp,
            _reserved_zeros: [0; 3],
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

/// WireGuard cookie reply packet.
/// See [whitepaper](https://www.wireguard.com/papers/wireguard.pdf).
#[derive(FromBytes, IntoBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
pub struct WgCookieReply {
    // INVARIANT: Must be WgPacketType::CookieReply
    packet_type: WgPacketType,
    _reserved_zeros: [u8; 4 - size_of::<WgPacketType>()],

    /// See [whitepaper](https://www.wireguard.com/papers/wireguard.pdf).
    pub receiver_idx: little_endian::U32,

    /// See [whitepaper](https://www.wireguard.com/papers/wireguard.pdf).
    pub nonce: [u8; 24],

    /// See [whitepaper](https://www.wireguard.com/papers/wireguard.pdf).
    pub encrypted_cookie: [u8; 32],
}

impl WgCookieReply {
    /// Length of the packet, in bytes.
    pub const LEN: usize = size_must_be::<Self>(64);

    /// Construct a [`WgCookieReply`] where all fields except `packet_type` are zeroed.
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
    /// Try to cast to a WireGuard packet while sanity-checking packet type and size.
    pub fn try_into_wg(self) -> eyre::Result<WgKind> {
        let wg = Wg::ref_from_bytes(self.as_bytes())
            .map_err(|_| eyre!("Not a wireguard packet, too small."))?;

        let len = wg.as_bytes().len();
        match (wg.packet_type, len) {
            (WgPacketType::HandshakeInit, WgHandshakeInit::LEN) => {
                Ok(WgKind::HandshakeInit(self.cast()))
            }
            (WgPacketType::HandshakeResp, WgHandshakeResp::LEN) => {
                Ok(WgKind::HandshakeResp(self.cast()))
            }
            (WgPacketType::CookieReply, WgCookieReply::LEN) => Ok(WgKind::CookieReply(self.cast())),
            (WgPacketType::Data, WgData::OVERHEAD..) => Ok(WgKind::Data(self.cast())),
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
