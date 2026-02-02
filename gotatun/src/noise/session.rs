// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
//
// Modified by Mullvad VPN.
// Copyright (c) 2025 Mullvad VPN.
//
// SPDX-License-Identifier: BSD-3-Clause

use crate::{
    noise::errors::WireGuardError,
    packet::{Packet, WgData, WgDataHeader, WgKind},
};
use bytes::{Buf, BytesMut};
use parking_lot::Mutex;
use ring::aead::{Aad, CHACHA20_POLY1305, LessSafeKey, Nonce, UnboundKey};
use std::sync::atomic::{AtomicUsize, Ordering};
use zerocopy::FromBytes;

pub struct Session {
    pub(crate) receiving_index: u32,
    sending_index: u32,
    receiver: LessSafeKey,
    sender: LessSafeKey,
    sending_key_counter: AtomicUsize,
    receiving_key_counter: Mutex<ReceivingKeyCounterValidator>,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "Session: {}<- ->{}",
            self.receiving_index, self.sending_index
        )
    }
}

// Receiving buffer constants
const WORD_SIZE: u64 = 64;
const N_WORDS: u64 = 16; // Suffice to reorder 64*16 = 1024 packets; can be increased at will
const N_BITS: u64 = WORD_SIZE * N_WORDS;

#[derive(Debug, Clone, Default)]
struct ReceivingKeyCounterValidator {
    /// In order to avoid replays while allowing for some reordering of the packets, we keep a
    /// bitmap of received packets, and the value of the highest counter
    next: u64,
    /// Used to estimate packet loss
    receive_cnt: u64,
    bitmap: [u64; N_WORDS as usize],
}

impl ReceivingKeyCounterValidator {
    #[inline(always)]
    fn set_bit(&mut self, idx: u64) {
        let bit_idx = idx % N_BITS;
        let word = (bit_idx / WORD_SIZE) as usize;
        let bit = (bit_idx % WORD_SIZE) as usize;
        self.bitmap[word] |= 1 << bit;
    }

    #[inline(always)]
    fn clear_bit(&mut self, idx: u64) {
        let bit_idx = idx % N_BITS;
        let word = (bit_idx / WORD_SIZE) as usize;
        let bit = (bit_idx % WORD_SIZE) as usize;
        self.bitmap[word] &= !(1u64 << bit);
    }

    /// Clear the word that contains idx
    #[inline(always)]
    fn clear_word(&mut self, idx: u64) {
        let bit_idx = idx % N_BITS;
        let word = (bit_idx / WORD_SIZE) as usize;
        self.bitmap[word] = 0;
    }

    /// Returns true if bit is set, false otherwise
    #[inline(always)]
    fn check_bit(&self, idx: u64) -> bool {
        let bit_idx = idx % N_BITS;
        let word = (bit_idx / WORD_SIZE) as usize;
        let bit = (bit_idx % WORD_SIZE) as usize;
        ((self.bitmap[word] >> bit) & 1) == 1
    }

    /// Returns true if the counter was not yet received, and is not too far back
    #[inline(always)]
    fn will_accept(&self, counter: u64) -> Result<(), WireGuardError> {
        if counter >= self.next {
            // As long as the counter is growing no replay took place for sure
            return Ok(());
        }
        if counter + N_BITS < self.next {
            // Drop if too far back
            return Err(WireGuardError::InvalidCounter);
        }
        if self.check_bit(counter) {
            Err(WireGuardError::DuplicateCounter)
        } else {
            Ok(())
        }
    }

    /// Marks the counter as received, and returns true if it is still good (in case during
    /// decryption something changed)
    #[inline(always)]
    fn mark_did_receive(&mut self, counter: u64) -> Result<(), WireGuardError> {
        if counter + N_BITS < self.next {
            // Drop if too far back
            return Err(WireGuardError::InvalidCounter);
        }
        if counter == self.next {
            // Usually the packets arrive in order, in that case we simply mark the bit and
            // increment the counter
            self.set_bit(counter);
            self.next += 1;
            return Ok(());
        }
        if counter < self.next {
            // A packet arrived out of order, check if it is valid, and mark
            if self.check_bit(counter) {
                return Err(WireGuardError::InvalidCounter);
            }
            self.set_bit(counter);
            return Ok(());
        }
        // Packets where dropped, or maybe reordered, skip them and mark unused
        if counter - self.next >= N_BITS {
            // Too far ahead, clear all the bits
            for c in self.bitmap.iter_mut() {
                *c = 0;
            }
        } else {
            let mut i = self.next;
            while !i.is_multiple_of(WORD_SIZE) && i < counter {
                // Clear until i aligned to word size
                self.clear_bit(i);
                i += 1;
            }
            while i + WORD_SIZE < counter {
                // Clear whole word at a time
                self.clear_word(i);
                i = (i + WORD_SIZE) & 0u64.wrapping_sub(WORD_SIZE);
            }
            while i < counter {
                // Clear any remaining bits
                self.clear_bit(i);
                i += 1;
            }
        }
        self.set_bit(counter);
        self.next = counter + 1;
        Ok(())
    }
}

impl Session {
    pub(super) fn new(
        local_index: u32,
        peer_index: u32,
        receiving_key: [u8; 32],
        sending_key: [u8; 32],
    ) -> Session {
        Session {
            receiving_index: local_index,
            sending_index: peer_index,
            receiver: LessSafeKey::new(
                UnboundKey::new(&CHACHA20_POLY1305, &receiving_key).unwrap(),
            ),
            sender: LessSafeKey::new(UnboundKey::new(&CHACHA20_POLY1305, &sending_key).unwrap()),
            sending_key_counter: AtomicUsize::new(0),
            receiving_key_counter: Mutex::new(Default::default()),
        }
    }

    pub(super) fn local_index(&self) -> usize {
        self.receiving_index as usize
    }

    /// Returns true if receiving counter is good to use
    fn receiving_counter_quick_check(&self, counter: u64) -> Result<(), WireGuardError> {
        let counter_validator = self.receiving_key_counter.lock();
        counter_validator.will_accept(counter)
    }

    /// Returns true if receiving counter is good to use, and marks it as used {
    fn receiving_counter_mark(&self, counter: u64) -> Result<(), WireGuardError> {
        let mut counter_validator = self.receiving_key_counter.lock();
        let ret = counter_validator.mark_did_receive(counter);
        if ret.is_ok() {
            counter_validator.receive_cnt += 1;
        }
        ret
    }

    /// Encapsulate `packet` into a [`WgData`].
    pub(super) fn format_packet_data(&self, packet: Packet) -> Packet<WgData> {
        let sending_key_counter = self.sending_key_counter.fetch_add(1, Ordering::Relaxed) as u64;

        let len = WgData::OVERHEAD + packet.len();

        // TODO: we can remove this allocation by pre-allocating some extra
        // space at the beginning of `packet`s allocation, and using that.
        let mut buf = Packet::from_bytes(BytesMut::zeroed(len));

        let data = WgData::mut_from_bytes(buf.buf_mut())
            .expect("buffer size is at least WgData::OVERHEAD");

        data.header = WgDataHeader::new()
            .with_receiver_idx(self.sending_index)
            .with_counter(sending_key_counter);

        // TODO: spec requires padding to 16 bytes, but actually works fine without it
        let mut nonce = [0u8; 12];
        nonce[4..12].copy_from_slice(&sending_key_counter.to_le_bytes());
        data.encrypted_encapsulated_packet_mut()
            .copy_from_slice(&packet);
        self.sender
            .seal_in_place_separate_tag(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(&[]),
                data.encrypted_encapsulated_packet_mut(),
            )
            .map(|tag| {
                data.tag_mut().copy_from_slice(tag.as_ref());
                packet.len() + WgData::TAG_LEN
            })
            .expect("encryption must succeed");

        // this won't panic since we've correctly initialized a WgData packet
        let packet = buf.try_into_wg().expect("is a wireguard packet");
        let WgKind::Data(packet) = packet else {
            unreachable!("is a wireguard data packet");
        };

        packet
    }

    /// Decapsulate `packet` and return the decrypted data.
    pub(super) fn receive_packet_data(
        &self,
        mut packet: Packet<WgData>,
    ) -> Result<Packet, WireGuardError> {
        if packet.header.receiver_idx != self.receiving_index {
            return Err(WireGuardError::WrongIndex);
        }

        let counter = packet.header.counter.get();

        // Don't reuse counters, in case this is a replay attack we want to quickly check the counter without running expensive decryption
        self.receiving_counter_quick_check(counter)?;

        let mut nonce = [0u8; 12];
        nonce[4..12].copy_from_slice(&packet.header.counter.to_bytes());

        // decrypt the data in-place
        let decrypted_len = self
            .receiver
            .open_in_place(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(&[]),
                &mut packet.encrypted_encapsulated_packet_and_tag,
            )
            .map_err(|_| WireGuardError::InvalidAeadTag)?
            .len();

        // shift the packet buffer slice onto the decrypted data
        let mut packet = packet.into_bytes();
        let buf = packet.buf_mut();
        buf.advance(WgDataHeader::LEN);
        buf.truncate(decrypted_len);

        // After decryption is done, check counter again, and mark as received
        self.receiving_counter_mark(counter)?;
        Ok(packet)
    }

    /// Returns the estimated downstream packet loss for this session
    pub(super) fn current_packet_cnt(&self) -> (u64, u64) {
        let counter_validator = self.receiving_key_counter.lock();
        (counter_validator.next, counter_validator.receive_cnt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_replay_counter() {
        let mut c: ReceivingKeyCounterValidator = Default::default();

        assert!(c.mark_did_receive(0).is_ok());
        assert!(c.mark_did_receive(0).is_err());
        assert!(c.mark_did_receive(1).is_ok());
        assert!(c.mark_did_receive(1).is_err());
        assert!(c.mark_did_receive(63).is_ok());
        assert!(c.mark_did_receive(63).is_err());
        assert!(c.mark_did_receive(15).is_ok());
        assert!(c.mark_did_receive(15).is_err());

        for i in 64..N_BITS + 128 {
            assert!(c.mark_did_receive(i).is_ok());
            assert!(c.mark_did_receive(i).is_err());
        }

        assert!(c.mark_did_receive(N_BITS * 3).is_ok());
        for i in 0..=N_BITS * 2 {
            assert!(matches!(
                c.will_accept(i),
                Err(WireGuardError::InvalidCounter)
            ));
            assert!(c.mark_did_receive(i).is_err());
        }
        for i in N_BITS * 2 + 1..N_BITS * 3 {
            assert!(c.will_accept(i).is_ok());
        }
        assert!(matches!(
            c.will_accept(N_BITS * 3),
            Err(WireGuardError::DuplicateCounter)
        ));

        for i in (N_BITS * 2 + 1..N_BITS * 3).rev() {
            assert!(c.mark_did_receive(i).is_ok());
            assert!(c.mark_did_receive(i).is_err());
        }

        assert!(c.mark_did_receive(N_BITS * 3 + 70).is_ok());
        assert!(c.mark_did_receive(N_BITS * 3 + 71).is_ok());
        assert!(c.mark_did_receive(N_BITS * 3 + 72).is_ok());
        assert!(c.mark_did_receive(N_BITS * 3 + 72 + 125).is_ok());
        assert!(c.mark_did_receive(N_BITS * 3 + 63).is_ok());

        assert!(c.mark_did_receive(N_BITS * 3 + 70).is_err());
        assert!(c.mark_did_receive(N_BITS * 3 + 71).is_err());
        assert!(c.mark_did_receive(N_BITS * 3 + 72).is_err());
    }
}
