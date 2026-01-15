// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
//
// Modified by Mullvad VPN.
// Copyright (c) 2026 Mullvad VPN.
//
// SPDX-License-Identifier: BSD-3-Clause

use clap::Parser;
use daemonize::Daemonize;
use eyre::{Context, Result, bail};
use gotatun::device::uapi::UapiServer;
use gotatun::device::{DefaultDeviceTransports, Device, DeviceBuilder};
use gotatun::tun::tun_async_device::TunDevice;
use std::fs::File;
use std::future::Future;
use std::os::unix::net::UnixDatagram;
use std::path::{Path, PathBuf};
use std::process::exit;
use tokio::signal::unix::{SignalKind, signal};
use tracing::{Level, info};

mod drop_privileges;

// Status messages sent between forked processes
const CHILD_OK: &[u8] = &[1];
const CHILD_ERR: &[u8] = &[0];

/// GotaTun - A userspace WireGuard implementation
#[derive(Parser)]
#[clap(version, author = "Mullvad VPN <https://github.com/mullvad/gotatun>")]
struct Args {
    /// Interface name to use for the TUN interface
    #[clap(validator = check_tun_name)]
    interface_name: String,

    /// Run and log in the foreground
    #[clap(short, long)]
    foreground: bool,

    /// Log verbosity
    #[clap(short, long, env = "WG_LOG_LEVEL", possible_values = ["error", "info", "debug", "trace"], default_value = "info")]
    verbosity: Level,

    /// Log file
    #[clap(short, long, env = "WG_LOG_FILE", default_value = "/tmp/gotatun.out")]
    log: PathBuf,

    /// Do not drop sudo privileges. This has no effect if the UID is root
    #[clap(long, env = "WG_SUDO")]
    disable_drop_privileges: bool,

    /// File that stores the TUN interface name
    #[cfg(target_os = "macos")]
    #[clap(long, env = "WG_TUN_NAME_FILE")]
    tun_name_file: Option<String>,
}

pub fn main() {
    if let Err(e) = run() {
        eprintln!("GotaTun failed: {e:?}");
        exit(1);
    }
}

fn run() -> Result<()> {
    let args = Args::parse();

    if args.foreground {
        run_foreground(args)
    } else {
        run_daemon(args)
    }
}

fn run_foreground(args: Args) -> Result<()> {
    setup_console_logging(args.verbosity);

    with_tokio_runtime(async {
        let device = setup_device(args).await.context("Failed to start tunnel")?;
        info!("GotaTun started successfully");
        wait_for_shutdown(device).await;
        Ok(())
    })
}

fn run_daemon(args: Args) -> Result<()> {
    // Create IPC channel for parent and child
    let (child_sock, parent_sock) = UnixDatagram::pair().context("Failed to create socket pair")?;
    child_sock
        .set_nonblocking(true)
        .context("Failed to set socket non-blocking")?;

    match Daemonize::new().working_directory("/tmp").execute() {
        daemonize::Outcome::Parent(result) => {
            result?;
            wait_for_child(parent_sock)?;
            println!("GotaTun started successfully");
            Ok(())
        }
        daemonize::Outcome::Child(result) => {
            result?;
            run_daemon_child(args, child_sock)
        }
    }
}

fn run_daemon_child(args: Args, child_sock: UnixDatagram) -> Result<()> {
    let _guard = setup_file_logging(&args.log, args.verbosity)?;

    with_tokio_runtime(async {
        match setup_device(args).await {
            Ok(device) => {
                let _ = child_sock.send(CHILD_OK);
                drop(child_sock);
                info!("GotaTun started successfully");
                wait_for_shutdown(device).await;
                Ok(())
            }
            Err(e) => {
                let _ = child_sock.send(CHILD_ERR);
                Err(e)
            }
        }
    })
}

fn wait_for_child(sock: UnixDatagram) -> Result<()> {
    let mut buf = [0u8; 1];
    if sock.recv(&mut buf).is_ok() && buf == CHILD_OK {
        Ok(())
    } else {
        bail!("Child process failed to initialize")
    }
}

fn setup_file_logging(
    log_file: &Path,
    level: Level,
) -> Result<tracing_appender::non_blocking::WorkerGuard> {
    let file = File::create(log_file)
        .with_context(|| format!("Could not create log file {}", log_file.display()))?;

    let (non_blocking, guard) = tracing_appender::non_blocking(file);

    tracing_subscriber::fmt()
        .with_max_level(level)
        .with_writer(non_blocking)
        .with_ansi(false)
        .init();

    Ok(guard)
}

fn setup_console_logging(level: Level) {
    tracing_subscriber::fmt()
        .pretty()
        .with_max_level(level)
        .init();
}

/// Create a tokio runtime and run the given future on it
fn with_tokio_runtime(f: impl Future<Output = Result<()>>) -> Result<()> {
    // Note: We must spawn the tokio runtime after forking the process.
    // Otherwise, we see issues with file descriptors being bad, etc.
    let rt = tokio::runtime::Runtime::new().context("Failed to create tokio runtime")?;
    rt.block_on(f)
}

async fn wait_for_shutdown(device: Device<DefaultDeviceTransports>) {
    let mut sigint = signal(SignalKind::interrupt()).expect("Failed to set up SIGINT handler");
    let mut sigterm = signal(SignalKind::terminate()).expect("Failed to set up SIGTERM handler");

    tokio::select! {
        _ = sigint.recv() => info!("SIGINT received"),
        _ = sigterm.recv() => info!("SIGTERM received"),
    }

    info!("GotaTun is shutting down");
    device.stop().await;
}

/// Create and configure wireguard tunnel
async fn setup_device(args: Args) -> eyre::Result<Device<DefaultDeviceTransports>> {
    let (socket_uid, socket_gid) = drop_privileges::get_saved_ids()?;

    // We must create the tun device first because its name will change on macOS
    // if "utun" is passed.
    let tun = TunDevice::from_name(&args.interface_name).context("Failed to create TUN device")?;
    let tun_name = tun.name()?; // get the actual tun name
    info!("Tunnel interface: {tun_name}");

    // wg-quick uses this to find the interface
    #[cfg(target_os = "macos")]
    if let Some(tun_name_file) = args.tun_name_file {
        tokio::fs::write(tun_name_file, &tun_name)
            .await
            .context("Failed to write to tun-name-file")?;
    }

    let uapi = UapiServer::default_unix_socket(&tun_name, Some(socket_uid), Some(socket_gid))
        .context("Failed to create UAPI unix socket")?;

    let dev = DeviceBuilder::new()
        .with_uapi(uapi)
        .with_default_udp()
        .with_ip(tun)
        .build()
        .await
        .context("Failed to start WireGuard device")?;

    if !args.disable_drop_privileges {
        drop_privileges::drop_privileges().context("Failed to drop privileges")?;
    }

    Ok(dev)
}

fn check_tun_name(_v: &str) -> eyre::Result<()> {
    #[cfg(any(target_os = "macos", target_os = "ios", target_os = "tvos"))]
    {
        use eyre::{ContextCompat, bail};

        const ERROR_MSG: &str =
            "Tunnel name must have the format 'utun[0-9]+'. Use 'utun' for automatic assignment";

        let suffix = _v.strip_prefix("utun").context(ERROR_MSG)?;

        if suffix.is_empty() {
            // "utun" alone automatically assigns a number
            return Ok(());
        }

        if suffix.chars().all(|c| c.is_ascii_digit()) {
            Ok(())
        } else {
            bail!(ERROR_MSG)
        }
    }
    #[cfg(not(any(target_os = "macos", target_os = "ios", target_os = "tvos")))]
    {
        Ok(())
    }
}

#[cfg(test)]
mod test {
    #[cfg(any(target_os = "macos", target_os = "ios", target_os = "tvos"))]
    use super::*;

    #[test]
    #[cfg(any(target_os = "macos", target_os = "ios", target_os = "tvos"))]
    fn test_check_tun_name() {
        assert!(check_tun_name("utun").is_ok());
        assert!(check_tun_name("utun0").is_ok());
        assert!(check_tun_name("utun123").is_ok());
        assert!(check_tun_name("mytun").is_err());
        assert!(check_tun_name("utunX").is_err());
        assert!(check_tun_name("utun-1").is_err());
        assert!(check_tun_name("utun123abc").is_err());
    }
}
