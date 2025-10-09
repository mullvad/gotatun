// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

// Common imports that are used on both platforms

// Unix implementation in a module
#[cfg(unix)]
mod unix {
    use clap::{Arg, Command};
    use daemonize::Daemonize;
    use gotatun::device::drop_privileges::drop_privileges;
    use gotatun::device::{DefaultDeviceTransports, DeviceConfig, DeviceHandle};
    use gotatun::udp::socket::UdpSocketFactory;
    use std::fs::File;
    use std::os::unix::net::UnixDatagram;
    use std::process::exit;
    use tracing::Level;

    fn check_tun_name(_v: String) -> Result<(), String> {
        #[cfg(any(target_os = "macos", target_os = "ios", target_os = "tvos"))]
        {
            // TODO: fix validation
            /*
            if gotatun::device::tun::parse_utun_name(&_v).is_ok() {
                Ok(())
            } else {
                Err("Tunnel name must have the format 'utun[0-9]+', use 'utun' for automatic assignment".to_owned())
            }
            */
            Ok(())
        }
        #[cfg(not(any(target_os = "macos", target_os = "ios", target_os = "tvos")))]
        {
            Ok(())
        }
    }

    pub async fn main() {
        let matches = Command::new("gotatun")
            .version(env!("CARGO_PKG_VERSION"))
            .author("Mullvad VPN") // TODO: Add an email address?
            .args(&[
                Arg::new("INTERFACE_NAME")
                    .required(true)
                    .takes_value(true)
                    .validator(|tunname| check_tun_name(tunname.to_string()))
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
                    .help("Do not drop sudo privileges"),
                //Arg::new("disable-connected-udp")
                //    .long("disable-connected-udp")
                //    .help("Disable connected UDP sockets to each peer"),
            ])
            .get_matches();

        let background = !matches.is_present("foreground");
        let tun_name = matches.value_of("INTERFACE_NAME").unwrap();
        let log_level: Level = matches.value_of_t("verbosity").unwrap_or_else(|e| e.exit());

        // Create a socketpair to communicate between forked processes
        let (sock1, sock2) = UnixDatagram::pair().unwrap();
        let _ = sock1.set_nonblocking(true);

        let _guard;

        if background {
            let log = matches.value_of("log").unwrap();

            let log_file =
                File::create(log).unwrap_or_else(|_| panic!("Could not create log file {log}"));

            let (non_blocking, guard) = tracing_appender::non_blocking(log_file);

            _guard = guard;

            tracing_subscriber::fmt()
                .with_max_level(log_level)
                .with_writer(non_blocking)
                .with_ansi(false)
                .init();

            let daemonize = Daemonize::new()
                .working_directory("/tmp")
                .exit_action(move || {
                    let mut b = [0u8; 1];
                    if sock2.recv(&mut b).is_ok() && b[0] == 1 {
                        println!("GotaTun started successfully");
                    } else {
                        eprintln!("GotaTun failed to start");
                        exit(1);
                    };
                });

            match daemonize.start() {
                Ok(_) => log::info!("GotaTun started successfully"),
                Err(e) => {
                    log::error!("error = {e:?}");
                    exit(1);
                }
            }
        } else {
            tracing_subscriber::fmt()
                .pretty()
                .with_max_level(log_level)
                .init();
        }

        let api = gotatun::device::api::ApiServer::default_unix_socket(tun_name).unwrap();

        let config = DeviceConfig { api: Some(api) };

        let _device_handle: DeviceHandle<DefaultDeviceTransports> =
            match DeviceHandle::from_tun_name(UdpSocketFactory, tun_name, config).await {
                Ok(d) => d,
                Err(e) => {
                    // Notify parent that tunnel initialization failed
                    log::error!("Failed to initialize tunnel: {e:?}");
                    sock1.send(&[0]).unwrap();
                    exit(1);
                }
            };

        if !matches.is_present("disable-drop-privileges")
            && let Err(e) = drop_privileges()
        {
            log::error!("Failed to drop privileges: {e:?}");
            sock1.send(&[0]).unwrap();
            exit(1);
        }

        // Notify parent that tunnel initialization succeeded
        sock1.send(&[1]).unwrap();
        drop(sock1);

        log::info!("GotaTun started successfully"); // TODO: abort somehow
        tokio::time::sleep(tokio::time::Duration::from_secs(1000)).await;
    }
}

#[cfg(unix)]
#[tokio::main]
async fn main() {
    unix::main().await;
}

#[cfg(not(unix))]
fn main() {
    // Empty main function for Windows
    unimplemented!("GotaTun CLI is not supported on Windows");
}
