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

//! Receive errors that don't concern the socket itself.

use std::io;

/// Whether `error`, returned by a receive on a [`UdpSocket`](super::UdpSocket), concerns a single
/// earlier datagram, or none, rather than the socket. The socket can then receive again at once:
///
/// - `ConnectionReset` (Windows `WSAECONNRESET`) and `ConnectionRefused` (`ECONNREFUSED`): an ICMP
///   port unreachable came back for an earlier send. Windows reports it on an unconnected socket's
///   next receive. Linux does only if `IP_RECVERR` is set, and other systems only on connected
///   sockets.
/// - `WSAENETRESET` (Windows, no [`io::ErrorKind`]): the same for an ICMP time exceeded.
/// - `WSAEMSGSIZE` (Windows): a datagram was too large for the buffer. Winsock discarded the rest of
///   it, and its truncated contents must never reach the protocol.
/// - `Interrupted`: a signal arrived before any data.
///
/// The system returns each of these once, from the receive that reports it, so receiving again
/// waits for the next datagram or report rather than spinning. That only holds for a socket:
/// other [`UdpRecv`](crate::udp::UdpRecv) implementations may return these errors indefinitely.
pub(crate) fn is_stray(error: &io::Error) -> bool {
    use io::ErrorKind::*;

    if matches!(
        error.kind(),
        ConnectionReset | ConnectionRefused | Interrupted
    ) {
        return true;
    }

    #[cfg(windows)]
    {
        use windows_sys::Win32::Networking::WinSock;

        if matches!(
            error.raw_os_error(),
            Some(WinSock::WSAENETRESET | WinSock::WSAEMSGSIZE)
        ) {
            return true;
        }
    }

    false
}

/// Log a skipped error, and let other tasks run before receiving again.
pub(crate) async fn skip(error: &io::Error) {
    tracing::debug!("Skipping UDP receive error: {error}");
    tokio::task::yield_now().await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stray_errors() {
        for kind in [
            io::ErrorKind::ConnectionReset,
            io::ErrorKind::ConnectionRefused,
            io::ErrorKind::Interrupted,
        ] {
            assert!(is_stray(&kind.into()), "{kind:?}");
        }

        #[cfg(unix)]
        for code in [libc::ECONNREFUSED, libc::EINTR] {
            assert!(is_stray(&io::Error::from_raw_os_error(code)), "{code}");
        }

        // TTL expiry can't be produced on loopback, so WSAENETRESET is only tested here.
        #[cfg(windows)]
        {
            use windows_sys::Win32::Networking::WinSock;

            for code in [
                WinSock::WSAECONNRESET,
                WinSock::WSAENETRESET,
                WinSock::WSAEMSGSIZE,
            ] {
                assert!(is_stray(&io::Error::from_raw_os_error(code)), "{code}");
            }
        }
    }

    #[test]
    fn errors_about_the_socket_are_not_stray() {
        for kind in [
            io::ErrorKind::PermissionDenied,
            io::ErrorKind::NotConnected,
            io::ErrorKind::InvalidInput,
            io::ErrorKind::BrokenPipe,
            io::ErrorKind::OutOfMemory,
            io::ErrorKind::NetworkDown,
            io::ErrorKind::Other,
        ] {
            assert!(!is_stray(&kind.into()), "{kind:?}");
        }

        #[cfg(unix)]
        for code in [libc::EBADF, libc::ENOTSOCK, libc::EFAULT, libc::ENOBUFS] {
            assert!(!is_stray(&io::Error::from_raw_os_error(code)), "{code}");
        }

        #[cfg(windows)]
        {
            use windows_sys::Win32::Networking::WinSock;

            for code in [
                WinSock::WSAENOTSOCK,
                WinSock::WSAEINVAL,
                WinSock::WSAENOBUFS,
                WinSock::WSAENETDOWN,
                WinSock::WSAESHUTDOWN,
            ] {
                assert!(!is_stray(&io::Error::from_raw_os_error(code)), "{code}");
            }
        }
    }
}
