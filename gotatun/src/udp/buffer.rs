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

//! Generic buffered `UdpTransport` implementation.

use std::{net::SocketAddr, sync::Arc, time::Duration};

use futures::{FutureExt, select};
use tokio::{io, sync::mpsc};

use crate::packet::{Packet, PacketBufPool};
use crate::task::Task;
use crate::udp::{UdpRecv, UdpSend};

/// Delay before retrying a temporary receive error. It doubles with each retry in a row.
const FIRST_RETRY_DELAY: Duration = Duration::from_millis(1);

/// Longest delay between retries.
const MAX_RETRY_DELAY: Duration = Duration::from_secs(1);

/// Temporary receive errors in a row after which reception ends: about a second's worth.
const MAX_RETRIES: u32 = 10;

/// A [`UdpSend`] that wraps another [`UdpSend`] to provide buffering.
///
/// Packets sent on this [`UdpSend::send_to`] will be buffered on a channel, and asynchronously
/// processed on another task. This means [`UdpSend::send_to`] won't block unless the channel is
/// full.
#[derive(Clone)]
pub struct BufferedUdpSend {
    _send_task: Arc<Task>,

    /// Channel where IPv4 packets are sent to `_send_task`
    send_tx_v4: mpsc::Sender<(Packet, SocketAddr)>,

    /// Channel where IPv6 packets are sent to `_send_task`
    send_tx_v6: mpsc::Sender<(Packet, SocketAddr)>,
}

impl BufferedUdpSend {
    /// Wrap a [`UdpSend`] into a [`BufferedUdpSend`] with `capacity`.
    pub fn new(capacity: usize, udp_tx: impl UdpSend + 'static) -> Self {
        let (send_tx_v4, mut send_rx_v4) = mpsc::channel::<(Packet, SocketAddr)>(capacity);
        let (send_tx_v6, mut send_rx_v6) = mpsc::channel::<(Packet, SocketAddr)>(capacity);

        let send_task = Task::spawn("buffered UDP send", async move {
            let mut buf_v4 = vec![];
            let mut buf_v6 = vec![];
            let max_packet_count = udp_tx.max_number_of_packets_to_send();
            let mut send_many_buf = Default::default();

            loop {
                // use separate channels because we musn't call `send_many_to` with mixed IPv4/IPv6.
                let (count, buf) = select! {
                    // recv_many is cancel-safe
                    n = send_rx_v4.recv_many(&mut buf_v4, max_packet_count).fuse() => (n, &mut buf_v4),
                    n = send_rx_v6.recv_many(&mut buf_v6, max_packet_count).fuse() => (n, &mut buf_v6),
                };
                match count {
                    0 => break,
                    1 => {
                        let (packet, addr) =
                            buf.pop().expect("recv_many received 1 packet into buf");
                        let _ = udp_tx
                            .send_to(packet, addr)
                            .await
                            .inspect_err(|e| tracing::trace!("send_to_err: {e:#}"));
                    }
                    2.. => {
                        // send all packets at once
                        if let Err(e) = udp_tx.send_many_to(&mut send_many_buf, buf).await {
                            tracing::trace!("send_to_many_err: {e:#}");
                            if !buf.is_empty() {
                                tracing::trace!(
                                    "send_to_many dropping {} packets due to error.",
                                    buf.len()
                                );
                                buf.clear(); // give up, drop the packets we meant to send
                            }
                        }
                    }
                }
            }
        });

        Self {
            _send_task: Arc::new(send_task),
            send_tx_v4,
            send_tx_v6,
        }
    }
}

impl UdpSend for BufferedUdpSend {
    type SendManyBuf = ();

    async fn send_to(&self, packet: Packet, destination: SocketAddr) -> io::Result<()> {
        let tx = match destination {
            SocketAddr::V4(..) => &self.send_tx_v4,
            SocketAddr::V6(..) => &self.send_tx_v6,
        };
        tx.send((packet, destination))
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::BrokenPipe, e))?;
        Ok(())
    }

    fn max_number_of_packets_to_send(&self) -> usize {
        debug_assert_eq!(
            self.send_tx_v4.max_capacity(),
            self.send_tx_v6.max_capacity(),
        );
        self.send_tx_v4.max_capacity()
    }
}

/// A [`UdpRecv`] that wraps another [`UdpRecv`] to provide buffering.
///
/// This will spawn a background task that continuously calls [`UdpRecv::recv_from`] until the
/// buffer is full. Any call to [`UdpRecv::recv_from`] on _this_ object will not block unless the
/// buffer is empty.
///
/// The task retries a temporary receive error (see [`is_temporary`]) after a delay that doubles
/// each time, up to [`MAX_RETRIES`] times in a row. Any other error, or one that keeps coming back,
/// is passed on, and the task stops.
pub struct BufferedUdpReceive {
    _recv_task: Arc<Task>,
    recv_rx: mpsc::Receiver<io::Result<(Packet, SocketAddr)>>,
}

impl BufferedUdpReceive {
    /// Wrap a [`UdpRecv`] into a [`BufferedUdpReceive`] with `capacity`.
    pub fn new(
        capacity: usize,
        mut udp_rx: impl UdpRecv + 'static,
        mut recv_pool: PacketBufPool,
    ) -> Self {
        let (recv_tx, recv_rx) = mpsc::channel(capacity);

        let recv_task = Task::spawn("buffered UDP receive", async move {
            let mut recv_many_buf = Default::default();
            let mut packet_bufs = vec![];
            let mut retries = 0;

            loop {
                // Read packets from the socket.
                if let Err(err) = udp_rx
                    .recv_many_from(&mut recv_many_buf, &mut recv_pool, &mut packet_bufs)
                    .await
                {
                    if is_temporary(&err) && retries < MAX_RETRIES {
                        let delay = FIRST_RETRY_DELAY
                            .saturating_mul(1 << retries)
                            .min(MAX_RETRY_DELAY);
                        retries += 1;
                        tracing::debug!("UDP receive failed, retrying in {delay:?}: {err}");
                        tokio::time::sleep(delay).await;
                        continue;
                    }
                    let _ = recv_tx.send(Err(err)).await;
                    return;
                }
                retries = 0;

                for (packet_buf, src) in packet_bufs.drain(..) {
                    match recv_tx.try_send(Ok((packet_buf, src))) {
                        Ok(()) => (),
                        Err(mpsc::error::TrySendError::Full(packet)) => {
                            if recv_tx.send(packet).await.is_err() {
                                // Buffer dropped
                                return;
                            }
                        }
                        Err(mpsc::error::TrySendError::Closed(_)) => return,
                    }
                }
            }
        });

        Self {
            _recv_task: Arc::new(recv_task),
            recv_rx,
        }
    }
}

/// Whether `error`, returned by a receive, is a temporary shortage worth retrying after a delay:
/// out of memory or buffer space, the network being down, or an interrupted call.
///
/// Errors that a socket gets once per stray ICMP report aren't included: `UdpSocket` skips those
/// itself, and from another [`UdpRecv`] they may repeat indefinitely.
fn is_temporary(error: &io::Error) -> bool {
    use io::ErrorKind::*;

    if matches!(error.kind(), OutOfMemory | NetworkDown | Interrupted) {
        return true;
    }

    let no_buffers = cfg_select! {
        unix => Some(libc::ENOBUFS),
        windows => Some(windows_sys::Win32::Networking::WinSock::WSAENOBUFS),
        _ => None,
    };
    no_buffers.is_some() && error.raw_os_error() == no_buffers
}

impl UdpRecv for BufferedUdpReceive {
    type RecvManyBuf = ();

    async fn recv_from(&mut self, _pool: &mut PacketBufPool) -> io::Result<(Packet, SocketAddr)> {
        let Some(packet) = self.recv_rx.recv().await else {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "UDP receive task stopped",
            ));
        };
        packet
    }
}

/// How [`BufferedUdpReceive`] handles errors from the [`UdpRecv`] it wraps.
#[cfg(test)]
mod recv_errors {
    use std::collections::VecDeque;
    use std::net::{Ipv4Addr, SocketAddr};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use tokio::time::Instant;

    use super::*;

    const FROM: SocketAddr = SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::LOCALHOST), 51820);

    /// A [`UdpRecv`] that returns scripted results, then `then` forever (or nothing, if `None`).
    /// `attempts` counts the receives that returned.
    struct Scripted {
        script: VecDeque<io::Result<&'static [u8]>>,
        then: Option<io::ErrorKind>,
        attempts: Arc<AtomicUsize>,
    }

    impl UdpRecv for Scripted {
        type RecvManyBuf = ();

        async fn recv_from(
            &mut self,
            _pool: &mut PacketBufPool,
        ) -> io::Result<(Packet, SocketAddr)> {
            let result = match self.script.pop_front() {
                Some(result) => result.map(|data| (Packet::copy_from(data), FROM)),
                None => match self.then {
                    Some(kind) => Err(kind.into()),
                    None => std::future::pending().await,
                },
            };
            self.attempts.fetch_add(1, Ordering::SeqCst);
            result
        }
    }

    /// Wrap a scripted source in a [`BufferedUdpReceive`]. Returns it and the attempt count.
    fn receiver(
        script: impl IntoIterator<Item = io::Result<&'static [u8]>>,
        then: Option<io::ErrorKind>,
    ) -> (BufferedUdpReceive, Arc<AtomicUsize>) {
        let attempts = Arc::new(AtomicUsize::new(0));
        let source = Scripted {
            script: script.into_iter().collect(),
            then,
            attempts: attempts.clone(),
        };
        let receiver = BufferedUdpReceive::new(16, source, PacketBufPool::new(16));
        (receiver, attempts)
    }

    fn err(kind: io::ErrorKind) -> io::Result<&'static [u8]> {
        Err(kind.into())
    }

    async fn recv(receiver: &mut BufferedUdpReceive) -> io::Result<Vec<u8>> {
        tokio::time::timeout(
            Duration::from_secs(60),
            receiver.recv_from(&mut PacketBufPool::new(1)),
        )
        .await
        .expect("the receive must not hang")
        .map(|(packet, _)| packet.to_vec())
    }

    /// Every kind of temporary error is retried.
    #[tokio::test(start_paused = true)]
    async fn temporary_errors_are_retried() {
        #[cfg(unix)]
        let no_buffers = io::Error::from_raw_os_error(libc::ENOBUFS);
        #[cfg(windows)]
        let no_buffers =
            io::Error::from_raw_os_error(windows_sys::Win32::Networking::WinSock::WSAENOBUFS);
        let script = [
            err(io::ErrorKind::Interrupted),
            err(io::ErrorKind::NetworkDown),
            err(io::ErrorKind::OutOfMemory),
            Err(no_buffers),
            Ok(&b"marker"[..]),
        ];
        let (mut receiver, attempts) = receiver(script, None);

        assert_eq!(recv(&mut receiver).await.unwrap(), b"marker");
        assert_eq!(attempts.load(Ordering::SeqCst), 5);
    }

    /// The wrapped transport may not be a socket, and may keep failing with an error that a
    /// socket gets once per stray ICMP report. Receiving again at once would then spin, so
    /// reception ends. `UdpSocket` skips such errors itself, where each is a single report.
    #[tokio::test(start_paused = true)]
    async fn errors_a_socket_skips_end_reception_here() {
        let (mut receiver, attempts) = receiver([], Some(io::ErrorKind::ConnectionReset));

        let start = Instant::now();
        let error = recv(&mut receiver).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::ConnectionReset);
        assert_eq!(start.elapsed(), Duration::ZERO);
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
    }

    /// A temporary shortage is retried after a delay that doubles each time.
    #[tokio::test(start_paused = true)]
    async fn transient_errors_are_retried_with_back_off() {
        let script = [
            err(io::ErrorKind::OutOfMemory),
            err(io::ErrorKind::OutOfMemory),
            err(io::ErrorKind::OutOfMemory),
            Ok(&b"marker"[..]),
        ];
        let (mut receiver, attempts) = receiver(script, None);

        let start = Instant::now();
        assert_eq!(recv(&mut receiver).await.unwrap(), b"marker");
        let elapsed = start.elapsed();
        // 1 + 2 + 4 ms, plus timer rounding.
        assert!(
            (Duration::from_millis(7)..Duration::from_millis(20)).contains(&elapsed),
            "{elapsed:?}"
        );
        assert_eq!(attempts.load(Ordering::SeqCst), 4);
    }

    /// An error that keeps coming back ends reception after a bounded number of retries,
    /// spread over about a second, rather than spinning.
    #[tokio::test(start_paused = true)]
    async fn transient_errors_give_up_after_ten_retries() {
        let (mut receiver, attempts) = receiver([], Some(io::ErrorKind::OutOfMemory));

        let start = Instant::now();
        let error = recv(&mut receiver).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::OutOfMemory);
        let elapsed = start.elapsed();
        // 1 + 2 + … + 512 ms = 1023 ms, plus timer rounding.
        assert!(
            (Duration::from_millis(1023)..Duration::from_millis(1100)).contains(&elapsed),
            "{elapsed:?}"
        );
        assert_eq!(attempts.load(Ordering::SeqCst), 11);

        let error = recv(&mut receiver).await.unwrap_err();
        assert_eq!(
            error.kind(),
            io::ErrorKind::BrokenPipe,
            "the task must have ended"
        );
        assert_eq!(attempts.load(Ordering::SeqCst), 11);
    }

    /// A datagram in between resets the count of consecutive failures.
    #[tokio::test(start_paused = true)]
    async fn a_datagram_resets_the_retry_count() {
        let failures = || std::iter::repeat_with(|| err(io::ErrorKind::OutOfMemory)).take(10);
        let script = failures()
            .chain([Ok(&b"first"[..])])
            .chain(failures())
            .chain([Ok(&b"second"[..])]);
        let (mut receiver, _) = receiver(script, None);

        assert_eq!(recv(&mut receiver).await.unwrap(), b"first");
        assert_eq!(recv(&mut receiver).await.unwrap(), b"second");
    }

    /// Any other error ends reception at once, and is reported.
    #[tokio::test(start_paused = true)]
    async fn fatal_errors_end_reception_at_once() {
        let (mut receiver, attempts) = receiver(
            [err(io::ErrorKind::PermissionDenied), Ok(&b"marker"[..])],
            None,
        );

        let start = Instant::now();
        let error = recv(&mut receiver).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(start.elapsed(), Duration::ZERO);

        let error = recv(&mut receiver).await.unwrap_err();
        assert_eq!(
            error.kind(),
            io::ErrorKind::BrokenPipe,
            "the task must have ended"
        );
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
    }
}

#[cfg(all(test, target_os = "linux"))]
mod test {
    use super::*;
    use crate::udp::socket::{SockOpt, UdpSocket};

    #[tokio::test]
    /// Regression test for security advisory GHSA-6gxq-8xp9-742r.
    async fn empty_loopback_datagram_mustnt_stop_buffered_udp_receive() {
        let socket = UdpSocket::bind("127.0.0.1:0".parse().unwrap(), SockOpt::default()).unwrap();
        let addr = socket.local_addr().unwrap();
        let mut receiver = BufferedUdpReceive::new(16, socket, PacketBufPool::new(16));
        let sender = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();

        sender.send_to(&[], addr).unwrap();
        sender.send_to(b"after-empty", addr).unwrap();

        tokio::time::timeout(
            std::time::Duration::from_secs(3),
            receiver.recv_from(&mut PacketBufPool::new(1)),
        )
        .await
        .expect("the receive task must stop promptly")
        .expect("the panicked receive task must not close its channel");
    }
}
