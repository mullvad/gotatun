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

use clap::Parser;
use eyre::{Context, Result};
use gotatun::device::uapi::UapiServer;
use gotatun::device::{DefaultDeviceTransports, Device, DeviceBuilder};
use gotatun::tun::tun_async_device::TunDevice;
use std::fs::File;
use std::path::PathBuf;
use std::process::exit;
use tracing::{Level, info};

/// GotaTun - A userspace WireGuard implementation
#[derive(Parser)]
#[clap(version, author = "Mullvad VPN <https://github.com/mullvad/gotatun>")]
struct Args {
    /// Interface name to use for the TUN interface
    interface_name: String,

    /// Log verbosity
    #[clap(short, long, env = "WG_LOG_LEVEL", possible_values = ["error", "info", "debug", "trace"], default_value = "info")]
    verbosity: Level,

    /// Log file (default: stdout)
    #[clap(short, long, env = "WG_LOG_FILE")]
    log: Option<PathBuf>,

    /// Path to wintun.dll. If omitted, wintun.dll is searched using the default DLL search order
    /// (which includes the executable directory and PATH).
    #[clap(long, env = "WINTUN_PATH")]
    wintun: Option<PathBuf>,
}

pub fn main() {
    if let Err(e) = run() {
        eprintln!("GotaTun failed: {e:?}");
        exit(1);
    }
}

fn run() -> Result<()> {
    let args = Args::parse();
    // Keep the logging guard alive for the duration of the program.
    let _logging_guard = setup_logging(&args)?;
    tokio::runtime::Runtime::new()
        .context("Failed to create tokio runtime")?
        .block_on(async {
            let device = setup_device(&args)
                .await
                .context("Failed to start tunnel")?;
            info!("GotaTun started successfully");
            tokio::signal::ctrl_c()
                .await
                .context("Failed to listen for Ctrl+C")?;
            info!("GotaTun is shutting down");
            device.stop().await;
            Ok(())
        })
}

fn setup_logging(args: &Args) -> Result<Option<tracing_appender::non_blocking::WorkerGuard>> {
    match &args.log {
        Some(log_file) => {
            let file = File::create(log_file)
                .with_context(|| format!("Could not create log file {}", log_file.display()))?;
            let (non_blocking, guard) = tracing_appender::non_blocking(file);
            tracing_subscriber::fmt()
                .with_max_level(args.verbosity)
                .with_writer(non_blocking)
                .with_ansi(false)
                .init();
            Ok(Some(guard))
        }
        None => {
            tracing_subscriber::fmt()
                .pretty()
                .with_max_level(args.verbosity)
                .init();
            Ok(None)
        }
    }
}

/// Create and configure the WireGuard tunnel device.
async fn setup_device(args: &Args) -> eyre::Result<Device<DefaultDeviceTransports>> {
    let tun = match &args.wintun {
        Some(wintun_path) => {
            TunDevice::from_name_with_wintun_path(&args.interface_name, wintun_path)
                .context("Failed to create TUN device")?
        }
        None => {
            TunDevice::from_name(&args.interface_name).context("Failed to create TUN device")?
        }
    };

    let tun_name = tun.name().context("Failed to get TUN device name")?;
    info!("Tunnel interface: {tun_name}");

    let uapi =
        UapiServer::default_named_pipe(&tun_name).context("Failed to create UAPI named pipe")?;

    let dev = DeviceBuilder::new()
        .with_uapi(uapi)
        .with_default_udp()
        .with_ip(tun)
        .build()
        .await
        .context("Failed to start WireGuard device")?;

    Ok(dev)
}
