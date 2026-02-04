// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

/// Errors that can occur during WireGuard protocol operations.
#[derive(Debug)]
pub enum WireGuardError {
    /// The destination buffer is too small for the operation.
    DestinationBufferTooSmall,
    /// The packet length is incorrect for the expected packet type.
    IncorrectPacketLength,
    /// Received a packet that was not expected in the current state.
    UnexpectedPacket,
    /// The packet type does not match what was expected.
    WrongPacketType,
    /// The session index in the packet is invalid or not recognized.
    WrongIndex,
    /// The cryptographic key used is incorrect or invalid.
    WrongKey,
    /// The TAI64N timestamp format is invalid.
    InvalidTai64nTimestamp,
    /// The TAI64N timestamp is incorrect (e.g., replayed or out of order).
    WrongTai64nTimestamp,
    /// The MAC (Message Authentication Code) verification failed.
    InvalidMac,
    /// The AEAD authentication tag verification failed.
    InvalidAeadTag,
    /// The packet counter is invalid.
    InvalidCounter,
    /// Received a packet with a duplicate counter (replay attack prevention).
    DuplicateCounter,
    /// The packet format or content is invalid.
    InvalidPacket,
    /// No active session exists for this operation.
    NoCurrentSession,
    /// Failed to acquire a lock on shared state.
    LockFailed,
    /// The connection has expired and is no longer valid.
    ConnectionExpired,
}
