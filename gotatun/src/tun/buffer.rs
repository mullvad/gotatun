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

//! Generic buffered IP send and receive implementations.

use std::{
    io::{self, ErrorKind},
    sync::Arc,
    time::Duration,
};

use crate::{
    packet::{Ip, Packet, PacketBufPool},
    task::Task,
    tun::{IpRecv, IpSend, MtuWatcher},
};
use tokio::{
    sync::{Mutex, mpsc},
    time::timeout,
};

/// An [`IpSend`] that wraps another [`IpSend`] to provide buffering.
///
/// Packets sent on this [`IpSend::send`] will be buffered on a channel, and asynchronously
/// processed on another task. This means [`IpSend::send`] won't block unless the channel is full.
#[derive(Clone)]
pub struct BufferedIpSend {
    tx: mpsc::Sender<Packet<Ip>>,
    _task: Arc<Task>,
}

impl BufferedIpSend {
    /// Create a [`BufferedIpSend`] with `capacity`.
    ///
    /// This takes an `Arc<Mutex<I>>` because the inner `I` will be re-used after [Self] is
    /// dropped. We will take the mutex lock when this function is called, and hold onto it for the
    /// lifetime of [Self].
    ///
    /// # Panics
    /// Panics if the lock is already taken.
    pub fn new<I: IpSend>(capacity: usize, inner: Arc<Mutex<I>>) -> Self {
        let (tx, mut rx) = mpsc::channel::<Packet<Ip>>(capacity);

        let task = Task::spawn("buffered IP send", async move {
            let mut inner = timeout(Duration::from_secs(5), inner.lock())
                .await
                .expect("Deadlock on IpSend. There must be no more than one IpSend active at any given time.");

            while let Some(packet) = rx.recv().await {
                if let Err(e) = inner.send(packet).await {
                    log::error!("Error sending IP packet: {e}");
                }
            }
        });

        Self {
            tx,
            _task: Arc::new(task),
        }
    }
}

impl IpSend for BufferedIpSend {
    async fn send(&mut self, packet: Packet<Ip>) -> io::Result<()> {
        self.tx
            .send(packet)
            .await
            .expect("receiver dropped after senders");
        Ok(())
    }
}

/// An [`IpRecv`] that wraps another [`IpRecv`] to provide buffering.
///
/// This will spawn a background task that continuously calls [`IpRecv::recv`] until the buffer is
/// full. Any call to [`IpRecv::recv`] on _this_ object will not block unless the buffer is empty.
pub struct BufferedIpRecv<I> {
    rx: mpsc::Receiver<Packet<Ip>>,
    rx_packet_buf: Vec<Packet<Ip>>,
    _task: Arc<Task>,
    _phantom: std::marker::PhantomData<I>,
    mtu: MtuWatcher,
}

impl<I: IpRecv> BufferedIpRecv<I> {
    /// Create a new [`BufferedIpRecv`] with `capacity`.
    ///
    /// This takes an `Arc<Mutex<I>>` because the inner `I` will be re-used after [Self] is
    /// dropped. We will take the mutex lock when this function is called, and hold onto it for the
    /// lifetime of [Self]. Will panic if the lock is already taken.
    pub async fn new(capacity: usize, mut pool: PacketBufPool, inner: Arc<Mutex<I>>) -> Self {
        let (tx, rx) = mpsc::channel::<Packet<Ip>>(capacity);

        // We use a timeout instead of a try_lock().expect() because there may still be an old
        // BufferedIpRecv that is in the process of being dropped. Otherwise, there would be a
        // race condition between the old `task` dropping, and us taking the lock again.
        let mut inner = timeout(Duration::from_secs(5), inner.lock_owned())
            .await
            .expect("Deadlock on IpRecv. There must be no more than one IpRecv active at any given time.");

        let mtu = inner.mtu();

        let task = Task::spawn("buffered IP recv", async move {
            loop {
                match inner.recv(&mut pool).await {
                    Ok(packets) => {
                        for packet in packets {
                            if tx.send(packet).await.is_err() {
                                return;
                            }
                        }
                    }
                    Err(e) => {
                        log::error!("Error receiving IP packet: {e}");
                        match e.kind() {
                            ErrorKind::UnexpectedEof | ErrorKind::BrokenPipe => return,
                            _ => (),
                        }
                    }
                }
            }
        });

        Self {
            rx,
            rx_packet_buf: vec![],
            _task: Arc::new(task),
            _phantom: std::marker::PhantomData,
            mtu,
        }
    }
}

impl<I: IpRecv> IpRecv for BufferedIpRecv<I> {
    async fn recv<'a>(
        &'a mut self,
        _pool: &mut PacketBufPool,
    ) -> io::Result<impl Iterator<Item = Packet<Ip>> + 'a> {
        let max_n = self.rx.max_capacity();
        let n = self.rx.recv_many(&mut self.rx_packet_buf, max_n).await;
        if n == 0 {
            // Channel is closed
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "channel closed",
            ));
        }
        Ok(self.rx_packet_buf.drain(..n))
    }

    fn mtu(&self) -> MtuWatcher {
        self.mtu.clone()
    }
}
