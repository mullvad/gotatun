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

//! Implementations of [`IpSend`] and [`IpRecv`] for the [`tun`] crate.

use io_uring::{IoUring, opcode, types};
use tokio::{
    sync::{mpsc, watch},
    time::sleep,
};
use tun::AbstractDevice;
use zerocopy::IntoBytes;

use crate::{
    packet::{Ip, Packet, PacketBufPool},
    task::Task,
    tun::{IpRecv, IpSend, MtuWatcher},
};

use std::{
    cell::UnsafeCell, convert::Infallible, io, iter, os::fd::AsRawFd, sync::Arc, time::Duration,
};

/// Error from [`TunDevice`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Failed to open TUN device
    #[error("Failed to open TUN device: {0}")]
    OpenTun(#[source] tun::Error),

    /// Failed to get TUN device name
    #[error("Failed to get TUN device name: {0}")]
    GetTunName(#[source] tun::Error),

    /// Unsupported TUN feature
    #[error("Unsupported TUN feature: {0}")]
    UnsupportedFeature(String),

    /// Failed to get TUN device MTU
    #[error("Failed to get TUN device MTU: {0}")]
    GetMtu(#[source] tun::Error),
}

/// A kernel virtual network device; a TUN device.
///
/// Implements [`IpSend`] and [`IpRecv`].
#[derive(Clone)]
pub struct TunDevice {
    tun: Arc<tun::AsyncDevice>,
    state: Arc<TunDeviceState>,
    write_tx: mpsc::Sender<Packet<Ip>>,
}

struct TunDeviceState {
    mtu: MtuWatcher,

    /// Task which monitors TUN device MTU. Aborted when dropped.
    _mtu_monitor: Task,
}

impl TunDevice {
    /// Construct from a name.
    ///
    /// # Warning
    ///
    /// If this is used on Windows, you are recommended to enable the `verify_binary_signature`
    /// feature for the `tun` crate. By default, `tun` will load `wintun.dll` using the
    /// [default search order], which includes the `PATH` environment variable.
    ///
    /// [default search order]: <https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order>
    pub fn from_name(name: &str) -> Result<Self, Error> {
        let mut tun_config = tun::Configuration::default();
        if cfg!(not(target_os = "macos")) || name != "utun" {
            // If the name is 'utun', automatically assign a name
            tun_config.tun_name(name);
        }
        #[cfg(target_os = "macos")]
        tun_config.platform_config(|p| {
            p.enable_routing(false);
        });
        // TODO: for wintun, must set path or enable signature check
        // we should upstream to `tun`
        let tun = tun::create_as_async(&tun_config).map_err(Error::OpenTun)?;
        let tun = TunDevice::from_tun_device(tun)?;
        Ok(tun)
    }

    /// Construct from a name with an explicit path to `wintun.dll`.
    ///
    /// Use this on Windows when `wintun.dll` is not on `PATH` or in the executable directory.
    #[cfg(windows)]
    pub fn from_name_with_wintun_path(
        name: &str,
        wintun_path: &std::path::Path,
    ) -> Result<Self, Error> {
        let mut tun_config = tun::Configuration::default();
        tun_config.tun_name(name);
        tun_config.platform_config(|p| {
            p.wintun_file(wintun_path.as_os_str());
        });
        let tun = tun::create_as_async(&tun_config).map_err(Error::OpenTun)?;
        TunDevice::from_tun_device(tun)
    }

    /// Construct from a [`tun::AsyncDevice`].
    pub fn from_tun_device(tun: tun::AsyncDevice) -> Result<Self, Error> {
        #[cfg(target_os = "linux")]
        if tun.packet_information() {
            return Err(Error::UnsupportedFeature("packet_information".to_string()));
        }

        let mtu = tun.mtu().map_err(Error::GetMtu)?;
        let (tx, rx) = watch::channel(mtu);

        let tun = Arc::new(tun);
        let tun_weak = Arc::downgrade(&tun);

        // Poll for changes to the MTU of the TUN device.
        // TODO: use the OS-specific event-driven patterns that exist instead of polling
        let watch_task = async move || -> Option<Infallible> {
            let mut mtu = mtu;
            loop {
                sleep(Duration::from_secs(3)).await;
                let tun = tun_weak.upgrade()?;
                let new = tun.mtu().ok()?;
                if new != mtu {
                    mtu = new;
                    tx.send(mtu).ok()?;
                }
            }
        };

        let mtu_monitor = Task::spawn("tun_mtu_monitor", async move {
            watch_task().await;
        });

        let (write_tx, write_rx) = mpsc::channel(URING_SLOTS);
        let write_task = WriteTask {
            tun: tun.clone(),
            write_rx,
        };
        tokio::task::spawn_blocking(move || write_task.run());

        Ok(Self {
            write_tx,
            tun,
            state: Arc::new(TunDeviceState {
                mtu: rx.into(),
                _mtu_monitor: mtu_monitor,
            }),
        })
    }

    /// Get the name of the TUN device.
    pub fn name(&self) -> Result<String, Error> {
        self.tun.tun_name().map_err(Error::GetTunName)
    }
}

impl IpSend for TunDevice {
    async fn send(&mut self, packet: Packet<Ip>) -> io::Result<()> {
        self.write_tx
            .send(packet)
            .await
            .map_err(|_| io::ErrorKind::BrokenPipe)?;
        // self.tun.send(&packet.into_bytes()).await?;
        Ok(())
    }
}

impl IpRecv for TunDevice {
    async fn recv<'a>(
        &'a mut self,
        pool: &mut PacketBufPool,
    ) -> io::Result<impl Iterator<Item = Packet<Ip>> + 'a> {
        let mut packet = pool.get();
        let n = self.tun.recv(&mut packet).await?;
        packet.truncate(n);
        match packet.try_into_ip() {
            Ok(packet) => Ok(iter::once(packet)),
            Err(e) => Err(io::Error::other(e.to_string())),
        }
    }

    fn mtu(&self) -> MtuWatcher {
        self.state.mtu.clone()
    }
}

struct WriteTask {
    tun: Arc<tun::AsyncDevice>,
    write_rx: mpsc::Receiver<Packet<Ip>>,
}

// Must be power of 2.
// TODO: tune for best performance
const URING_SLOTS: usize = 1024;

impl WriteTask {
    pub fn run(self) {
        let WriteTask { tun, mut write_rx } = self;

        let mut slots: [Option<UnsafeCell<Packet<Ip>>>; URING_SLOTS] =
            [const { None }; URING_SLOTS];
        let mut bufs = Vec::with_capacity(URING_SLOTS);

        // TODO: dont unwrap
        let mut uring = IoUring::new(URING_SLOTS as u32).unwrap();

        let mut free_slots = URING_SLOTS;
        let mut next_slot = 0;

        loop {
            let num_to_submit = write_rx.blocking_recv_many(&mut bufs, free_slots);

            debug_assert!(num_to_submit <= free_slots);
            debug_assert!(num_to_submit > 0);

            // Move packets into `slots` and submit them to the uring.
            for packet in bufs.drain(..) {
                let packet_len = packet.as_bytes().len();

                // Find the first free slot. This will always find a slot, as we never recv
                // more packets than we have space for
                let slot_i = loop {
                    let slot_i = next_slot;
                    next_slot = (next_slot + 1) % URING_SLOTS;
                    if slots[slot_i].is_none() {
                        break slot_i;
                    }
                };

                // Wrap the packet in an UnsafeCell so we can safely have the kernel mutate it
                // while we mutate other things in `slots`.
                // TODO: is this true? is there a point to using UnsafeCell here?
                let cell = slots[slot_i].insert(UnsafeCell::new(packet));
                let ptr = cell.get_mut().as_mut_bytes().as_mut_ptr();
                free_slots -= 1;

                let write_op =
                    opcode::Write::new(types::Fd(tun.as_raw_fd()), ptr, packet_len as u32)
                        .build()
                        .user_data(slot_i as u64);

                // SAFETY: `ptr` points into `slots`, the slot is valid for the duration of the
                // operation. Buffers aren't removed from `slots` until the corresponding
                // io-operation completes.
                unsafe { uring.submission().push(&write_op) }.expect("uring is not full");
            }

            // let ongoing_operations = URING_SLOTS - free_slots;
            // if num_to_submit != ongoing_operations {
            //     tracing::info!("submitting {num_to_submit} ops (total={ongoing_operations})");
            //     tracing::info!("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!1");
            // }

            // Wait for one operation to complete
            // TODO: is it better to wait for ALL operations, or SOME operations?
            let num_completed = uring.submit_and_wait(1).unwrap();

            // Free buffers for completed operations
            for completion in uring.completion().take(num_completed) {
                let slot_i = completion.user_data() as usize;
                debug_assert!(slot_i < URING_SLOTS);

                // Free the slot and the packet buffer.
                // TODO: don't panic
                let cell = slots[slot_i].take().expect("slot is some");
                let buf = cell.into_inner();
                drop(buf);

                free_slots += 1;
            }
        }
    }
}
