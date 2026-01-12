use clap::{Arg, Command};
use daemonize::Daemonize;
use eyre::Context;
use gotatun::device::uapi::UapiServer;
use gotatun::device::{DefaultDeviceTransports, Device, DeviceBuilder};
use gotatun::tun::tun_async_device::TunDevice;
use std::fs::File;
use std::os::unix::net::UnixDatagram;
use std::process::exit;
use tokio::signal::unix::{SignalKind, signal};
use tracing::Level;

mod drop_privileges;

pub async fn main() {
    let matches = Command::new("gotatun")
        .version(env!("CARGO_PKG_VERSION"))
        .author("Mullvad VPN <https://github.com/mullvad/gotatun>")
        .args(&[
            Arg::new("INTERFACE_NAME")
                .required(true)
                .takes_value(true)
                .validator(check_tun_name)
                .help("The name of the created interface"),
            Arg::new("foreground")
                .long("foreground")
                .short('f')
                .help("Run and log in the foreground"),
            Arg::new("threads")
                .takes_value(true)
                .long("threads")
                .short('t')
                .env("WG_THREADS")
                .help("Number of OS threads to use")
                .default_value("4"),
            Arg::new("verbosity")
                .takes_value(true)
                .long("verbosity")
                .short('v')
                .env("WG_LOG_LEVEL")
                .possible_values(["error", "info", "debug", "trace"])
                .help("Log verbosity")
                .default_value("error"),
            Arg::new("log")
                .takes_value(true)
                .long("log")
                .short('l')
                .env("WG_LOG_FILE")
                .help("Log file")
                .default_value("/tmp/gotatun.out"),
            Arg::new("disable-drop-privileges")
                .long("disable-drop-privileges")
                .env("WG_SUDO")
                .help("Do not drop sudo privileges. This has no effect if the UID is root"),
        ])
        .get_matches();

    let background = !matches.is_present("foreground");
    let tun_name = matches.value_of("INTERFACE_NAME").unwrap();
    let log_level: Level = matches.value_of_t("verbosity").unwrap_or_else(|e| e.exit());
    let do_drop_privileges = !matches.is_present("disable-drop-privileges");

    // Create a socketpair to communicate between forked processes
    let (sock1, sock2) = UnixDatagram::pair().unwrap();
    let _ = sock1.set_nonblocking(true);
    let send_child_result = |result: &[u8]| {
        sock1.send(result).unwrap();
        drop(sock1);
    };

    // Status messages sent between forked processes
    const CHILD_OK: &[u8] = &[1];
    const CHILD_ERR: &[u8] = &[0];

    // tracing_appender worker guard
    let _guard;

    if background {
        let log = matches.value_of("log").unwrap();

        let log_file =
            File::create(log).unwrap_or_else(|_| panic!("Could not create log file {log}"));

        let daemonize = Daemonize::new().working_directory("/tmp");

        let child_result = match daemonize.execute() {
            daemonize::Outcome::Parent(Err(e)) => {
                eprintln!("GotaTun failed to start");
                eprintln!("{e:?}");
                exit(1);
            }
            daemonize::Outcome::Parent(Ok(_parent)) => {
                let mut b = [0u8; 1];
                if sock2.recv(&mut b).is_ok() && b == CHILD_OK {
                    println!("GotaTun started successfully");
                    return;
                } else {
                    eprintln!("GotaTun failed to start");
                    exit(1);
                }
            }
            daemonize::Outcome::Child(child) => child,
        };

        let (non_blocking, guard) = tracing_appender::non_blocking(log_file);
        _guard = guard;

        tracing_subscriber::fmt()
            .with_max_level(log_level)
            .with_writer(non_blocking)
            .with_ansi(false)
            .init();

        if let Err(e) = child_result {
            log::error!("{e:?}");
            send_child_result(CHILD_ERR);
            exit(1);
        }
    } else {
        tracing_subscriber::fmt()
            .pretty()
            .with_max_level(log_level)
            .init();
    }

    let device = match start(tun_name, do_drop_privileges).await {
        Ok(device) => device,
        Err(e) => {
            log::error!("{e:?}");
            send_child_result(CHILD_ERR);
            exit(1);
        }
    };

    // Notify parent that tunnel initialization succeeded
    send_child_result(CHILD_OK);

    log::info!("GotaTun started successfully");

    let mut sigint = signal(SignalKind::interrupt()).expect("set up SIGINT handler");
    let mut sigterm = signal(SignalKind::terminate()).expect("set up SIGTERM handler");
    tokio::select! {
        _ = sigint.recv() => log::info!("SIGINT received"),
        _ = sigterm.recv() => log::info!("SIGTERM received"),
    }

    log::info!("GotaTun is shutting down");
    device.stop().await;
}

async fn start(
    tun_name: &str,
    do_drop_privileges: bool,
) -> eyre::Result<Device<DefaultDeviceTransports>> {
    let (socket_uid, socket_gid) = drop_privileges::get_saved_ids()?;

    let tun = TunDevice::from_name(tun_name).context("Failed to create TUN device")?;

    let uapi = UapiServer::default_unix_socket(&tun.name()?, Some(socket_uid), Some(socket_gid))
        .context("Failed to create UAPI unix socket")?;

    let device: Device<_> = DeviceBuilder::new()
        .with_uapi(uapi)
        .with_default_udp()
        .with_ip(tun)
        .build()
        .await
        .context("Failed to start WireGuard device")?;

    if do_drop_privileges {
        drop_privileges::drop_privileges().context("Failed to drop privileges")?;
    }

    Ok(device)
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
        assert!(check_tun_name("utun").is_err());
        assert!(check_tun_name("utun0").is_ok());
        assert!(check_tun_name("utun123").is_ok());
        assert!(check_tun_name("mytun").is_err());
        assert!(check_tun_name("utunX").is_err());
        assert!(check_tun_name("utun-1").is_err());
        assert!(check_tun_name("utun123abc").is_err());
    }
}
