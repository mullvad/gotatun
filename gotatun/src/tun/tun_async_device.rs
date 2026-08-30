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

use tokio::{sync::watch, time::sleep};
use tun_rs::AsyncDevice;

use crate::{
    packet::{Ip, Packet, PacketBufPool},
    task::Task,
    tun::{IpRecv, IpSend, MtuWatcher},
};

use std::{convert::Infallible, io, sync::Arc, time::Duration};

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
pub struct TunDevice {
    tun: Arc<AsyncDevice>,
    state: Arc<TunDeviceState>,
    #[cfg(target_os = "linux")]
    rx_state: RxState,
    #[cfg(target_os = "linux")]
    tx_state: TxState,
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
    // each buffer reserves the first TX_OFFSET bytes for the virtio header
    // and has room for one MTU-sized packet after it
    bufs: Vec<Vec<u8>>, // BATCH buffers, each len TX_OFFSET + MTU
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
        //let tun_config = tun_config.offload(false); // TODO: Enable.

        // TODO: for wintun, must set path or enable signature check
        // we should upstream to `tun`
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
        let mut tun_config = tun::Configuration::default();
        tun_config.tun_name(name);
        tun_config.platform_config(|p| {
            p.wintun_file(wintun_path.as_os_str());
        });
        let tun = tun::create_as_async(&tun_config).map_err(Error::OpenTun)?;
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

        #[cfg(target_os = "linux")]
        let rx_state = RxState {
            original_buffer: vec![0u8; tun_rs::VIRTIO_NET_HDR_LEN + 65535],
            bufs: vec![vec![0u8; 1500]; tun_rs::IDEAL_BATCH_SIZE],
            sizes: vec![0; tun_rs::IDEAL_BATCH_SIZE],
        };

        #[cfg(target_os = "linux")]
        let tx_state = TxState {
            gro_table: tun_rs::GROTable::default(),
            // BATCH buffers, each sized to hold the virtio header + one MTU packet,
            // pre-zeroed (ZEROED_BUFFER pattern) so uninitialized regions are clean.
            bufs: vec![vec![0u8; tun_rs::VIRTIO_NET_HDR_LEN + 1500]; tun_rs::IDEAL_BATCH_SIZE],
        };

        Ok(Self {
            tun,
            state: Arc::new(TunDeviceState {
                mtu: rx.into(),
                _mtu_monitor: mtu_monitor,
            }),
            #[cfg(target_os = "linux")]
            rx_state,
            #[cfg(target_os = "linux")]
            tx_state,
        })
    }

    /// Get the name of the TUN device.
    pub fn name(&self) -> Result<String, Error> {
        self.tun.name().map_err(Error::GetTunName)
    }
}

impl IpSend for TunDevice {
    #[cfg(target_os = "linux")]
    async fn send(&mut self, packet: Packet<Ip>) -> io::Result<()> {
        use zerocopy::IntoBytes;
        let offset = tun_rs::VIRTIO_NET_HDR_LEN;
        let TxState {
            gro_table, bufs, ..
        } = &mut self.tx_state;

        {
            let buf = &mut bufs[0];
            let bytes = packet.as_bytes();
            buf.resize(offset + bytes.len(), 0);
            buf[offset..offset + bytes.len()].copy_from_slice(bytes);
        }

        let _bytes_sent = self
            .tun
            .send_multiple(gro_table, &mut bufs[..1], offset)
            .await?;
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    async fn send(&mut self, packet: Packet<Ip>) -> io::Result<()> {
        self.tun.send(&packet.into_bytes()).await?;
        Ok(())
    }
}

impl IpRecv for TunDevice {
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
            packet.truncate(packet_size);
            // copy the segmented packet data in
            packet.copy_from_slice(raw_packet);

            match packet.try_into_ip() {
                Ok(packet) => out.push(packet),
                Err(e) => return Err(io::Error::other(e.to_string())),
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
