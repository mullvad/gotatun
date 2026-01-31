//! Tunnel-in-tunnel multihop example with router.
//!
//! Chains two WireGuard devices: an **inner** device whose encrypted traffic
//! is routed through an **outer** device before reaching the network.
//!
//! ```text
//!     Real TUN
//!        |
//!   TunRouter ── inner IPs ──> Inner Device (channel UDP)
//!        |                          |
//!     other IPs              encrypted WG packets
//!        |                          |
//!        v                          v
//!   MergingIpRecv  <────────────────┘
//!        |
//!   Outer Device (real UDP)
//!        |
//!     network
//! ```
//!
//! Run (requires root for TUN creation):
//! ```sh
//! cargo run --example multihop-router --features tun,device -- \
//!     --inner-endpoint relay.example.com:51820 \
//!     --outer-tun-ip 10.0.0.1 \
//!     --inner-tun-ip 172.16.0.1 \
//!     --inner-private-key <base64> \
//!     --outer-private-key <base64> \
//!     --exit-pubkey <base64> \
//!     --relay-pubkey <base64> \
//!     --relay-endpoint 1.2.3.4:51820
//! ```

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use clap::Parser;
use eyre::{Context, ContextCompat};
#[cfg(feature = "pcap")]
use gotatun::tun::pcap::{PcapSniffer, PcapStream};
use gotatun::{
    device::{DeviceBuilder, Peer},
    packet::{Ipv4Header, Ipv6Header, PacketBufPool, UdpHeader, WgData},
    tun::{
        IpRecv, demux::DemuxIpSend, merge::MergingIpRecv, router::tun_router,
        tun_async_device::TunDevice,
    },
    udp::channel::new_udp_tun_channel,
};

/// Tunnel-in-tunnel multihop with a TUN router.
#[derive(Parser)]
struct Args {
    /// Inner tunnel endpoint (hostname:port, will be DNS-resolved).
    #[arg(long)]
    inner_endpoint: String,

    /// Outer tunnel IP address assigned to the TUN device.
    #[arg(long)]
    outer_tun_ip: Ipv4Addr,

    /// Inner tunnel IP address.
    #[arg(long)]
    inner_tun_ip: Ipv4Addr,

    /// Inner device private key (base64-encoded).
    #[arg(long)]
    inner_private_key: String,

    /// Outer device private key (base64-encoded).
    #[arg(long)]
    outer_private_key: String,

    /// Exit server public key (base64-encoded).
    #[arg(long)]
    exit_pubkey: String,

    /// Relay server public key (base64-encoded).
    #[arg(long)]
    relay_pubkey: String,

    /// Relay server endpoint (ip:port).
    #[arg(long)]
    relay_endpoint: SocketAddr,

    /// Inner tunnel allowed IP range (CIDR notation).
    #[arg(long, default_value = "172.16.10.0/24")]
    inner_allowed_ip: String,

    /// Outer tunnel allowed IP range (CIDR notation).
    #[arg(long, default_value = "0.0.0.0/0")]
    outer_allowed_ip: String,

    /// TUN device name.
    #[arg(long, default_value = "wg-router")]
    tun_name: String,

    /// Kernel-side MTU for the TUN device.
    #[arg(long, default_value = "1380")]
    mtu: u16,

    /// Additional routes to add through the TUN device (CIDR notation, repeatable).
    #[arg(long = "route")]
    routes: Vec<String>,

    /// PCAP unix socket path for Wireshark (requires `--features pcap`).
    #[cfg(feature = "pcap")]
    #[arg(long, default_value = "/tmp/multihop.pcap")]
    pcap_socket: String,
}

async fn run_ip(args: &[&str]) -> eyre::Result<()> {
    let status = tokio::process::Command::new("ip")
        .args(args)
        .status()
        .await
        .with_context(|| format!("failed to run: ip {}", args.join(" ")))?;
    eyre::ensure!(
        status.success(),
        "ip {} failed with {status}",
        args.join(" ")
    );
    Ok(())
}

async fn setup_tun_device(
    name: &str,
    addr: Ipv4Addr,
    mtu: u16,
    routes: &[String],
) -> eyre::Result<()> {
    let addr_cidr = format!("{addr}/32");
    let mtu_str = mtu.to_string();

    run_ip(&["addr", "add", "dev", name, &addr_cidr]).await?;
    run_ip(&["link", "set", "dev", name, "up"]).await?;
    run_ip(&["link", "set", "dev", name, "mtu", &mtu_str]).await?;

    for route in routes {
        run_ip(&["route", "add", "dev", name, route]).await?;
    }

    Ok(())
}

fn parse_key<T: From<[u8; 32]>>(b64: &str) -> eyre::Result<T> {
    let bytes = base64::decode(b64).context("invalid base64 for key")?;
    let array: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .context("key must be 32 bytes")?;
    Ok(T::from(array))
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    tracing_subscriber::fmt().pretty().init();

    let args = Args::parse();

    let inner_tun_endpoint = tokio::net::lookup_host(&args.inner_endpoint)
        .await
        .context("Failed to resolve inner endpoint")?
        .next()
        .context("No addresses found for inner endpoint")?;

    let inner_private =
        parse_key(&args.inner_private_key).context("Failed to parse inner private key")?;
    let outer_private =
        parse_key(&args.outer_private_key).context("Failed to parse outer private key")?;
    let exit_server_pubkey =
        parse_key(&args.exit_pubkey).context("Failed to parse exit server public key")?;
    let relay_server_pubkey =
        parse_key(&args.relay_pubkey).context("Failed to parse relay server public key")?;

    let inner_allowed_ip: ipnetwork::IpNetwork = args
        .inner_allowed_ip
        .parse()
        .context("invalid CIDR for --inner-allowed-ip")?;
    let outer_allowed_ip: ipnetwork::IpNetwork = args
        .outer_allowed_ip
        .parse()
        .context("invalid CIDR for --outer-allowed-ip")?;

    // Create actual TUN device
    let tun = TunDevice::from_name(&args.tun_name)?;

    // Configure the TUN interface (addr, link up, mtu, routes)
    let mut routes: Vec<String> = vec![args.inner_allowed_ip.clone()];
    routes.extend(args.routes.iter().cloned());
    setup_tun_device(&args.tun_name, args.outer_tun_ip, args.mtu, &routes).await?;

    let multihop_overhead = match inner_tun_endpoint.ip() {
        IpAddr::V4(..) => Ipv4Header::LEN + UdpHeader::LEN + WgData::OVERHEAD,
        IpAddr::V6(..) => Ipv6Header::LEN + UdpHeader::LEN + WgData::OVERHEAD,
    };
    let mtu = tun.mtu().increase(multihop_overhead as u16).unwrap();

    // Channel bridge (inner device UDP <-> outer device TUN)
    let (bridge_tun_tx, bridge_tun_rx, inner_udp) =
        new_udp_tun_channel(4000, args.outer_tun_ip, Ipv6Addr::UNSPECIFIED, mtu);

    // TUN router (split real TUN reads by dest IP)
    let (router_task, alt_output, default_output) = tun_router(tun.clone(), inner_allowed_ip, 4000);

    // Outer device IpRecv: merge direct + inner encrypted
    let outer_ip_recv = MergingIpRecv::new(default_output, bridge_tun_rx, PacketBufPool::new(100));

    // Outer device IpSend: demux decrypted packets
    let outer_ip_send = DemuxIpSend::new(bridge_tun_tx, tun.clone(), inner_tun_endpoint);

    // NAT: rewrite src/dst IPs between inner and outer tunnel addresses
    let tun_send =
        gotatun::tun::nat::NatIpSend::new(tun.clone(), args.inner_tun_ip, args.outer_tun_ip);
    let alt_recv =
        gotatun::tun::nat::NatIpRecv::new(alt_output, args.outer_tun_ip, args.inner_tun_ip);

    // Inner device
    let inner_device = DeviceBuilder::new()
        .with_udp(inner_udp)
        .with_ip_pair(tun_send, alt_recv)
        .with_private_key(inner_private)
        .with_peer(
            Peer::new(exit_server_pubkey)
                .with_endpoint(inner_tun_endpoint)
                .with_allowed_ip(inner_allowed_ip),
        )
        .build()
        .await?;

    #[cfg(feature = "pcap")]
    let (outer_ip_send, outer_ip_recv) =
        wrap_in_pcap_sniffer(outer_ip_send, outer_ip_recv, &args.pcap_socket);

    // Outer device
    let outer_device = DeviceBuilder::new()
        .with_default_udp()
        .with_ip_pair(outer_ip_send, outer_ip_recv)
        .with_private_key(outer_private)
        .with_peer(
            Peer::new(relay_server_pubkey)
                .with_endpoint(args.relay_endpoint)
                .with_allowed_ip(outer_allowed_ip),
        )
        .build()
        .await?;

    println!("Multihop tunnel running. Press Ctrl-C to stop.");

    tokio::signal::ctrl_c().await?;

    drop(inner_device);
    drop(outer_device);
    drop(router_task);

    Ok(())
}

/// Wrap `ip_send` and `ip_recv` in [`PcapSniffer`]s for use with Wireshark.
///
/// With userspace multihop, the exit device communicates with the network through the
/// entry device, without going through the kernel. That means there is no network interface
/// for Wireshark to sniff. By interposing [`PcapSniffer`]s, any packets that are sent or
/// received will _also_ be written to a unix socket, encoded using the pcap file format.
///
/// The unix socket can be opened in Wireshark:
/// ```sh
/// wireshark -k -i /tmp/multihop.pcap
/// ```
#[cfg(feature = "pcap")]
fn wrap_in_pcap_sniffer<S, R>(
    ip_send: S,
    ip_recv: R,
    socket_path: &str,
) -> (PcapSniffer<S>, PcapSniffer<R>)
where
    S: gotatun::tun::IpSend,
    R: gotatun::tun::IpRecv,
{
    use std::{
        fs,
        os::unix::{fs::PermissionsExt, net::UnixListener},
        time::Instant,
    };

    eprintln!("Binding pcap socket to {socket_path:?}");
    let _ = fs::remove_file(socket_path);
    let listener = UnixListener::bind(socket_path).unwrap();
    let _ = fs::set_permissions(socket_path, fs::Permissions::from_mode(0o777));

    eprintln!("Waiting for Wireshark connection...");
    eprintln!("    wireshark -k -i {socket_path}");
    let (stream, _) = listener
        .accept()
        .expect("Error while waiting for pcap listener");

    let writer = PcapStream::new(Box::new(stream));
    let start_time = Instant::now();

    let ip_send = PcapSniffer::new(ip_send, writer.clone(), start_time);
    let ip_recv = PcapSniffer::new(ip_recv, writer, start_time);

    (ip_send, ip_recv)
}
