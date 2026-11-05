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

//! Implementations of [`IpSend`] and [`IpRecv`] for the [`tun_rs`] crate.

use tokio::{sync::watch, time::sleep};
use tun_rs::AsyncDevice;

use crate::{
    packet::{Ip, Packet, PacketBufPool},
    task::Task,
    tun::{IpRecv, IpSend, MtuWatcher},
};

use std::{convert::Infallible, io, sync::Arc, time::Duration};

/// Fallback interface MTU used when querying the MTU fails.
#[cfg(target_os = "linux")]
const DEFAULT_TUN_MTU: u16 = 1500;

/// Headroom added on top of the interface MTU when sizing TUN packet buffers.
///
/// Each GSO segment produced by [`tun_rs`] repeats the IP and transport headers of the
/// original packet, which may make a segment slightly larger than the MTU.
#[cfg(target_os = "linux")]
const GRO_SEGMENT_HEADROOM: usize = 128;

/// Error from [`TunDevice`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Failed to open TUN device
    #[error("Failed to open TUN device: {0}")]
    OpenTun(#[source] io::Error),

    /// Failed to get TUN device name
    #[error("Failed to get TUN device name: {0}")]
    GetTunName(#[source] io::Error),

    /// Unsupported TUN feature
    #[error("Unsupported TUN feature: {0}")]
    UnsupportedFeature(String),

    /// Failed to get TUN device MTU
    #[error("Failed to get TUN device MTU: {0}")]
    GetMtu(#[source] io::Error),
}

/// A kernel virtual network device; a TUN device.
///
/// Implements [`IpSend`] and [`IpRecv`].
#[derive(Clone)]
pub struct TunDevice {
    tun: Arc<AsyncDevice>,
    state: Arc<TunDeviceState>,
}

#[cfg(target_os = "linux")]
struct RxState {
    original_buffer: Vec<u8>,
    bufs: Vec<Vec<u8>>,
    sizes: Vec<usize>,
}

#[cfg(target_os = "linux")]
struct TxState {
    gro_table: tun_rs::GROTable,
    /// Batch buffers, each with room for the virtio header followed by one MTU-sized packet.
    /// GRO coalescing may grow a buffer beyond this; tun-rs then reallocates it.
    bufs: Vec<Vec<u8>>,
}

struct TunDeviceState {
    mtu: MtuWatcher,

    /// Task which monitors TUN device MTU. Aborted when dropped.
    _mtu_monitor: Task,
}

pub struct TunDeviceTx {
    tun: Arc<AsyncDevice>,
    #[cfg(target_os = "linux")]
    tx_state: TxState,
}

pub struct TunDeviceRx {
    tun: Arc<AsyncDevice>,
    state: Arc<TunDeviceState>,
    #[cfg(target_os = "linux")]
    rx_state: RxState,
}

impl TunDevice {
    /// Split TunDevice into a read and a write half.
    pub fn split(self) -> (TunDeviceTx, TunDeviceRx) {
        #[cfg(target_os = "linux")]
        // Packets are at most MTU-sized, but each GSO segment repeats the IP (and possibly
        // extension/transport) headers of the original packet.
        let buf_size = tun_rs::VIRTIO_NET_HDR_LEN
            + usize::from(self.tun.mtu().unwrap_or(DEFAULT_TUN_MTU))
            + GRO_SEGMENT_HEADROOM;

        #[cfg(target_os = "linux")]
        let tx_state = TxState {
            gro_table: tun_rs::GROTable::default(),
            bufs: vec![vec![0u8; buf_size]; tun_rs::IDEAL_BATCH_SIZE],
        };

        #[cfg(target_os = "linux")]
        let rx_state = RxState {
            original_buffer: vec![0u8; tun_rs::VIRTIO_NET_HDR_LEN + 65535],
            bufs: vec![vec![0u8; buf_size]; tun_rs::IDEAL_BATCH_SIZE],
            sizes: vec![0; tun_rs::IDEAL_BATCH_SIZE],
        };

        (
            TunDeviceTx {
                tun: Arc::clone(&self.tun),
                #[cfg(target_os = "linux")]
                tx_state,
            },
            TunDeviceRx {
                tun: Arc::clone(&self.tun),
                state: Arc::clone(&self.state),
                #[cfg(target_os = "linux")]
                rx_state,
            },
        )
    }
    /// Construct from a name.
    ///
    /// # Warning
    ///
    /// On Windows, `tun-rs` will load `wintun.dll` using the [default search order],
    /// which includes the `PATH` environment variable.
    ///
    /// [default search order]: <https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order>
    pub fn from_name(name: &str) -> Result<Self, Error> {
        let tun_config = tun_rs::DeviceBuilder::new();

        let tun_config = if cfg!(not(target_os = "macos")) || name != "utun" {
            // If the name is 'utun', automatically assign a name
            tun_config.name(name)
        } else {
            tun_config
        };
        #[cfg(target_os = "macos")]
        let tun_config = tun_config.associate_route(false);

        #[cfg(target_os = "linux")]
        let tun_config = tun_config.offload(true);
        #[cfg(target_os = "linux")]
        let tun_config = tun_config.multi_queue(true);

        // TODO: for wintun, consider using `from_name_with_wintun_path` or setting an explicit
        // path via `DeviceBuilder::wintun_file` to avoid relying on the DLL search order.
        let tun = tun_config.build_async().map_err(Error::OpenTun)?;
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
        let tun_config = tun_rs::DeviceBuilder::new()
            .name(name)
            .wintun_file(wintun_path.to_string_lossy().into_owned());
        let tun = tun_config.build_async().map_err(Error::OpenTun)?;
        TunDevice::from_tun_device(tun)
    }

    /// Construct from a [`AsyncDevice`].
    pub fn from_tun_device(tun: AsyncDevice) -> Result<Self, Error> {
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

        Ok(Self {
            tun,
            state: Arc::new(TunDeviceState {
                mtu: rx.into(),
                _mtu_monitor: mtu_monitor,
            }),
        })
    }

    /// Get the name of the TUN device.
    pub fn name(&self) -> Result<String, Error> {
        self.tun.name().map_err(Error::GetTunName)
    }
}

impl IpSend for TunDevice {
    async fn send(&mut self, packet: Packet<Ip>) -> io::Result<()> {
        self.tun.send(&packet.into_bytes()).await?;
        Ok(())
    }
}

impl IpRecv for TunDevice {
    async fn recv<'a>(
        &'a mut self,
        pool: &mut PacketBufPool,
    ) -> io::Result<impl Iterator<Item = Packet<Ip>> + 'a> {
        use std::iter::once;
        let mut packet = pool.get();
        let n = self.tun.recv(&mut packet).await?;
        packet.truncate(n);
        match packet.try_into_ip() {
            Ok(packet) => Ok(once(packet)),
            Err(e) => Err(io::Error::other(e.to_string())),
        }
    }

    fn mtu(&self) -> MtuWatcher {
        self.state.mtu.clone()
    }
}

impl IpSend for TunDeviceTx {
    async fn send(&mut self, packet: Packet<Ip>) -> io::Result<()> {
        self.tun.send(&packet.into_bytes()).await?;
        Ok(())
    }

    #[cfg(target_os = "linux")]
    async fn send_many(&mut self, packets: Vec<Packet<Ip>>) -> io::Result<()> {
        use zerocopy::IntoBytes;
        let offset = tun_rs::VIRTIO_NET_HDR_LEN;
        let TxState {
            gro_table, bufs, ..
        } = &mut self.tx_state;

        // Send in chunks that fit within the pre-allocated buffers.
        for chunk in packets.chunks(bufs.len()) {
            for (i, packet) in chunk.iter().enumerate() {
                let buf = &mut bufs[i];
                let bytes = packet.as_bytes();
                // TODO: Get rid of resize
                buf.resize(offset + bytes.len(), 0);
                buf[offset..offset + bytes.len()].copy_from_slice(bytes);
            }

            self.tun
                .send_multiple(gro_table, &mut bufs[..chunk.len()], offset)
                .await?;
        }
        Ok(())
    }
}

impl IpRecv for TunDeviceRx {
    #[cfg(target_os = "linux")]
    // TODO: For now, it is assumed that the tun device has offloading enabled.
    async fn recv<'a>(
        &'a mut self,
        pool: &mut PacketBufPool,
    ) -> io::Result<impl Iterator<Item = Packet<Ip>> + 'a> {
        let offset = 0;

        let RxState {
            original_buffer,
            bufs,
            sizes,
        } = &mut self.rx_state;

        let num = self
            .tun
            .recv_multiple(original_buffer, bufs, sizes, offset)
            .await?;

        // Collect ALL segmented packets into a Vec, then return its iterator.
        let mut out = Vec::with_capacity(num);
        for i in 0..num {
            let packet_size = sizes[i];
            let raw_packet = &bufs[i][offset..offset + packet_size];
            let mut packet = pool.get();
            if packet_size > packet.len() {
                // The packet can't fit in a pooled buffer. This should never happen with a
                // sane MTU; drop the packet instead of panicking.
                tracing::warn!("Dropping oversized IP packet: {packet_size} bytes");
                continue;
            }
            packet.truncate(packet_size);
            // copy the segmented packet data in
            packet.copy_from_slice(raw_packet);

            match packet.try_into_ip() {
                Ok(packet) => out.push(packet),
                Err(e) => {
                    // A malformed packet must not make us drop the rest of the batch.
                    tracing::warn!("Dropping malformed IP packet: {e}");
                }
            }
        }

        Ok(out.into_iter())
    }

    #[cfg(not(target_os = "linux"))]
    async fn recv<'a>(
        &'a mut self,
        pool: &mut PacketBufPool,
    ) -> io::Result<impl Iterator<Item = Packet<Ip>> + 'a> {
        use std::iter::once;
        let mut packet = pool.get();
        let n = self.tun.recv(&mut packet).await?;
        packet.truncate(n);
        match packet.try_into_ip() {
            Ok(packet) => Ok(once(packet)),
            Err(e) => Err(io::Error::other(e.to_string())),
        }
    }

    fn mtu(&self) -> MtuWatcher {
        self.state.mtu.clone()
    }
}
