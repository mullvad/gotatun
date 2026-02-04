// Copyright (c) 2025 Mullvad VPN AB. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

#![allow(dead_code)]

use std::{
    fmt::{self, Display},
    iter::Peekable,
    net::SocketAddr,
    num::NonZero,
    str::FromStr,
};

use eyre::{WrapErr, bail, ensure, eyre};
use ipnetwork::IpNetwork;
use typed_builder::TypedBuilder;

use crate::serialization::KeyBytes;

#[cfg(feature = "daita-uapi")]
use crate::device::daita::DaitaSettings;

#[derive(Debug)]
pub enum Request {
    Get(Get),
    Set(Set),
}

#[derive(Debug)]
pub enum Response {
    Get(GetResponse),
    Set(SetResponse),
}

#[derive(Default, Debug)]
#[non_exhaustive]
pub struct Get;

#[derive(Debug, TypedBuilder)]
#[non_exhaustive]
pub struct GetPeer {
    pub peer: Peer,

    /// This and [`Self::last_handshake_time_nsec`] indicate in the number of seconds and
    /// nano-seconds of the most recent handshake for the previously added peer entry, expressed
    /// relative to the Unix epoch.
    #[builder(default, setter(strip_option, into))]
    pub last_handshake_time_sec: Option<u64>,

    /// See [`Self::last_handshake_time_sec`].
    #[builder(default, setter(strip_option, into))]
    pub last_handshake_time_nsec: Option<u32>,

    /// Indicates the number of received bytes for the previously added peer entry.
    #[builder(default, setter(strip_option, into))]
    pub rx_bytes: Option<u64>,

    /// Indicates the number of transmitted bytes for the previously added peer entry.
    #[builder(default, setter(strip_option, into))]
    pub tx_bytes: Option<u64>,

    /// Extra bytes added due to constant-size padding of data packets for the previously added peer entry.
    #[builder(default, setter(strip_option, into))]
    pub tx_padding_bytes: Option<u64>,

    /// Bytes of decoy packets transmitted for the previously added peer entry.
    #[builder(default, setter(strip_option, into))]
    pub tx_decoy_packet_bytes: Option<u64>,

    /// Total extra bytes removed due to constant-size padding of data packets for the previously added peer entry.
    #[builder(default, setter(strip_option, into))]
    pub rx_padding_bytes: Option<u64>,

    /// Bytes of decoy packets received for the previously added peer entry.
    #[builder(default, setter(strip_option, into))]
    pub rx_decoy_packet_bytes: Option<u64>,
}

#[derive(TypedBuilder, Default, Debug)]
#[non_exhaustive]
pub struct GetResponse {
    /// The private key of the interface
    #[builder(default, setter(strip_option, into))]
    pub private_key: Option<KeyBytes>,

    /// The listening port of the interface.
    #[builder(default, setter(strip_option, into))]
    pub listen_port: Option<u16>,

    /// The fwmark of the interface.
    #[builder(default, setter(strip_option, into))]
    pub fwmark: Option<u32>,

    #[builder(default, setter(skip))]
    pub peers: Vec<GetPeer>,

    pub errno: i32,
}

#[derive(TypedBuilder, Default, Debug)]
#[non_exhaustive]
pub struct Set {
    /// The private key of the interface. If this key is all zero, it indicates that the private key
    /// should be removed.
    #[builder(default, setter(strip_option, into))]
    pub private_key: Option<KeyBytes>,

    /// The listening port of the interface.
    #[builder(default, setter(strip_option, into))]
    pub listen_port: Option<u16>,

    /// The fwmark of the interface. The value may 0, in which case it indicates that the fwmark
    /// should be removed.
    #[builder(default, setter(strip_option, into))]
    pub fwmark: Option<SetUnset<NonZero<u32>>>,

    /// This indicates that the subsequent peers (perhaps an empty list) should replace any
    /// existing peers, rather than append to the existing peer list.
    #[builder(setter(strip_bool))]
    pub replace_peers: bool,

    /// This value should not be used or set by most users of this API. If unset, the corresponding
    /// peer will use the latest available protocol version. Otherwise this value must be "1".
    #[builder(default, setter(strip_option, into))]
    pub protocol_version: Option<String>,

    #[builder(default, setter(skip))]
    pub peers: Vec<SetPeer>,
}

#[derive(TypedBuilder, Debug)]
#[non_exhaustive]
pub struct SetPeer {
    pub peer: Peer,

    /// Remove the peer instead of adding it.
    #[builder(setter(strip_bool))]
    pub remove: bool,

    /// Only perform the operation if the peer already exists as part of the interface.
    #[builder(setter(strip_bool))]
    pub update_only: bool,

    /// This key/value combo indicates that the allowed IPs (perhaps an empty list) should replace any existing ones of the previously added peer entry, rather than append to the existing allowed IPs list.
    #[builder(setter(strip_bool))]
    pub replace_allowed_ips: bool,
}

#[derive(Debug)]
#[non_exhaustive]
pub struct SetResponse {
    pub errno: i32,
}

#[derive(Debug)]
/// A config value which may be either set to something, or to nothing.
pub enum SetUnset<T> {
    /// Set the value to `T`
    Set(T),

    /// Set the value to nothing.
    Unset,
}

#[derive(TypedBuilder, Debug)]
#[non_exhaustive]
pub struct Peer {
    /// The public key of a peer entry.
    #[builder(setter(into))]
    pub public_key: KeyBytes,

    /// The preshared-key of the previously added peer entry. The value may be all zero in the case
    /// of a set operation, in which case it indicates that the preshared-key should be removed.
    #[builder(default, setter(strip_option, into))]
    pub preshared_key: Option<SetUnset<KeyBytes>>,

    /// The value for this key is either `IP:port` for IPv4 or `[IP]:port` for IPv6, indicating the
    /// endpoint of the previously added peer entry.
    #[builder(default, setter(strip_option, into))]
    pub endpoint: Option<SocketAddr>,

    /// The persistent keepalive interval of the previously added peer entry. The value 0 disables it.
    #[builder(default, setter(strip_option, into))]
    pub persistent_keepalive_interval: Option<u16>,

    /// The value for this is IP/cidr, indicating a new added allowed IP entry for the previously
    /// added peer entry. If an identical value already exists as part of a prior peer, the allowed
    /// IP entry will be removed from that peer and added to this peer.
    #[builder(default)]
    pub allowed_ip: Vec<IpNetwork>,

    #[cfg(feature = "daita-uapi")]
    #[builder(default, setter(strip_option, into))]
    pub daita_settings: Option<SetUnset<DaitaSettings>>,
}

impl From<Set> for Request {
    fn from(set: Set) -> Self {
        Self::Set(set)
    }
}

impl From<Get> for Request {
    fn from(get: Get) -> Self {
        Self::Get(get)
    }
}

impl Set {
    pub fn peer(mut self, peer: SetPeer) -> Self {
        self.peers.push(peer);
        self
    }
}

impl Peer {
    /// Create a new [Peer] with only `public_key` set.
    pub fn new(public_key: impl Into<KeyBytes>) -> Self {
        Self {
            public_key: public_key.into(),
            preshared_key: None,
            endpoint: None,
            persistent_keepalive_interval: None,
            allowed_ip: vec![],
            #[cfg(feature = "daita-uapi")]
            daita_settings: None,
        }
    }

    pub fn with_endpoint(mut self, endpoint: impl Into<SocketAddr>) -> Self {
        self.endpoint = Some(endpoint.into());
        self
    }
}

impl SetPeer {
    /// Create a new [`SetPeer`] with only `public_key` set.
    pub fn new(public_key: impl Into<KeyBytes>) -> Self {
        Self {
            peer: Peer::new(public_key),
            remove: false,
            update_only: false,
            replace_allowed_ips: false,
        }
    }

    pub fn with_endpoint(mut self, endpoint: impl Into<SocketAddr>) -> Self {
        self.peer.endpoint = Some(endpoint.into());
        self
    }
}

impl GetPeer {
    /// Create a new [`GetPeer`] with only `public_key` set.
    pub fn new(public_key: impl Into<KeyBytes>) -> Self {
        Self {
            peer: Peer::new(public_key),
            last_handshake_time_sec: None,
            last_handshake_time_nsec: None,
            rx_bytes: None,
            tx_bytes: None,
            tx_padding_bytes: None,
            tx_decoy_packet_bytes: None,
            rx_padding_bytes: None,
            rx_decoy_packet_bytes: None,
        }
    }
}

impl GetResponse {
    pub fn peer(mut self, peer: GetPeer) -> Self {
        self.peers.push(peer);
        self
    }
}

impl Display for Response {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Response::Get(get) => get.fmt(f),
            Response::Set(set) => set.fmt(f),
        }
    }
}

/// Convert an &Option<T> to Option<(&str, &dyn Display)>, turning the variable name into the str.
macro_rules! opt_to_key_and_display {
    ($i:ident) => {
        $i.as_ref().map(|r| (stringify!($i), r as &dyn Display))
    };
}

impl Display for GetResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let GetResponse {
            private_key,
            listen_port,
            fwmark,
            peers,
            errno,
        } = self;

        let fields = [
            opt_to_key_and_display!(private_key),
            opt_to_key_and_display!(listen_port),
            opt_to_key_and_display!(fwmark),
        ]
        .into_iter()
        .flatten();

        for (key, value) in fields {
            writeln!(f, "{key}={value}")?;
        }

        for peer in peers {
            // TODO: make sure number of newlines is correct.
            write!(f, "{peer}")?;
        }

        writeln!(f, "errno={errno}")?;

        Ok(())
    }
}

impl Display for GetPeer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let GetPeer {
            peer:
                Peer {
                    public_key,
                    preshared_key,
                    endpoint,
                    persistent_keepalive_interval,
                    allowed_ip,
                    #[cfg(feature = "daita-uapi")]
                    daita_settings,
                },
            last_handshake_time_sec,
            last_handshake_time_nsec,
            rx_bytes,
            tx_bytes,
            tx_padding_bytes: daita_tx_padding_bytes,
            tx_decoy_packet_bytes: daita_tx_decoy_packet_bytes,
            rx_padding_bytes: daita_rx_padding_bytes,
            rx_decoy_packet_bytes: daita_rx_decoy_packet_bytes,
        } = self;

        let public_key = Some(&public_key);

        let fields = [
            opt_to_key_and_display!(public_key),
            opt_to_key_and_display!(preshared_key),
            opt_to_key_and_display!(endpoint),
            opt_to_key_and_display!(persistent_keepalive_interval),
            opt_to_key_and_display!(last_handshake_time_sec),
            opt_to_key_and_display!(last_handshake_time_nsec),
            opt_to_key_and_display!(rx_bytes),
            opt_to_key_and_display!(tx_bytes),
        ]
        .into_iter()
        .flatten();

        for (key, value) in fields {
            writeln!(f, "{key}={value}")?;
        }

        #[cfg(not(feature = "daita-uapi"))]
        let _ = (
            daita_tx_padding_bytes,
            daita_tx_decoy_packet_bytes,
            daita_rx_padding_bytes,
            daita_rx_decoy_packet_bytes,
        );

        #[cfg(feature = "daita-uapi")]
        if let Some(SetUnset::Set(daita)) = daita_settings {
            let DaitaSettings {
                maybenot_machines,
                max_decoy_frac: daita_max_decoy_frac,
                max_delay_frac: daita_max_delay_frac,
                max_delayed_packets: daita_max_delayed_packets,
                min_delay_capacity: daita_min_delay_capacity,
            } = daita;

            writeln!(f, "daita_enable=1")?;

            for machine in maybenot_machines {
                writeln!(f, "daita_machine={}", machine.serialize())?;
            }

            writeln!(f, "daita_max_delayed_packets={daita_max_delayed_packets}")?;
            writeln!(f, "daita_min_delay_capacity={daita_min_delay_capacity}")?;
            writeln!(f, "daita_max_decoy_frac={daita_max_decoy_frac}")?;
            writeln!(f, "daita_max_delay_frac={daita_max_delay_frac}")?;

            if let Some(daita_rx_padding_bytes) = daita_rx_padding_bytes {
                writeln!(f, "daita_rx_padding_bytes={daita_rx_padding_bytes}")?;
            }
            if let Some(daita_tx_padding_bytes) = daita_tx_padding_bytes {
                writeln!(f, "daita_tx_padding_bytes={daita_tx_padding_bytes}")?;
            }
            if let Some(daita_rx_decoy_packet_bytes) = daita_rx_decoy_packet_bytes {
                writeln!(
                    f,
                    "daita_rx_decoy_packet_bytes={daita_rx_decoy_packet_bytes}"
                )?;
            }
            if let Some(daita_tx_decoy_packet_bytes) = daita_tx_decoy_packet_bytes {
                writeln!(
                    f,
                    "daita_tx_decoy_packet_bytes={daita_tx_decoy_packet_bytes}"
                )?;
            }
        }

        for allowed_ip in allowed_ip {
            writeln!(f, "allowed_ip={}/{}", allowed_ip.ip(), allowed_ip.prefix())?;
        }

        Ok(())
    }
}

impl Display for SetResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "errno={}", self.errno)
    }
}

impl<T: Display> Display for SetUnset<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SetUnset::Set(t) => Display::fmt(t, f),
            SetUnset::Unset => Ok(()),
        }
    }
}

impl Display for KeyBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in &self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

macro_rules! parse_opt {
    ($key:expr, $value:expr, $field:ident) => {{
        ensure!(
            $field.is_none(),
            "Key {:?} may not be specified twice",
            $key
        );
        *$field = Some(
            $value
                .parse()
                .map_err(|e| eyre!("Failed to parse {:?}: {e}", $key))?,
        );
    }};
}

macro_rules! parse_bool {
    ($key:expr, $value:expr, $field:ident) => {{
        ensure!(
            $value == "true",
            "The only valid value for key {:?} is \"true\"",
            $key
        );
        *$field = true;
    }};
}

impl FromStr for Get {
    type Err = eyre::Report;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s != "get=1\n" {
            bail!("Not a valid `get` command. Expected `get=1\\n`");
        }

        Ok(Get {})
    }
}

impl FromStr for Set {
    type Err = eyre::Report;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut lines = s.lines().peekable();
        ensure!(
            lines.next() == Some("set=1"),
            "Set commands must start with 'set=1'"
        );

        let mut set = Set::default();
        let Set {
            private_key,
            listen_port,
            fwmark,
            replace_peers,
            protocol_version,
            peers,
        } = &mut set;

        while let Some(line) = lines.next() {
            if line.is_empty() {
                break;
            }

            let (k, v) = to_key_value(line)?;

            match k {
                "private_key" => parse_opt!(k, v, private_key),
                "listen_port" => parse_opt!(k, v, listen_port),
                "replace_peers" => parse_bool!(k, v, replace_peers),
                "protocol_version" => parse_opt!(k, v, protocol_version),
                "public_key" => {
                    let public_key = KeyBytes::from_str(v).map_err(|err| eyre!("{err}"))?;
                    peers.push(SetPeer::from_lines(public_key, &mut lines)?);
                }

                "fwmark" => {
                    ensure!(fwmark.is_none(), "Key {k:?} may not be specified twice");
                    *fwmark = Some(if v.is_empty() {
                        SetUnset::Unset
                    } else {
                        let number: u32 = v.parse().wrap_err(r#"Failed to parse "fwmark""#)?;
                        match NonZero::new(number) {
                            Some(number) => SetUnset::Set(number),
                            None => SetUnset::Unset,
                        }
                    })
                }

                _ => bail!("Key {k:?} in {line:?} is not allowed in command set"),
            }
        }

        Ok(set)
    }
}

impl SetPeer {
    fn from_lines<'a>(
        public_key: impl Into<KeyBytes>,
        lines: &mut Peekable<impl Iterator<Item = &'a str>>,
    ) -> eyre::Result<Self> {
        let mut set_peer = SetPeer::new(public_key);
        let SetPeer {
            peer:
                Peer {
                    public_key: _,
                    preshared_key,
                    endpoint,
                    persistent_keepalive_interval,
                    allowed_ip,
                    #[cfg(feature = "daita-uapi")]
                    daita_settings,
                },
            remove,
            update_only,
            replace_allowed_ips,
        } = &mut set_peer;

        loop {
            // loop until we peek an empty line or end-of-string
            let Some(line) = lines.peek() else {
                break;
            };
            if line.is_empty() {
                break;
            }

            let (k, v) = to_key_value(line)?;

            match k {
                // This key indicates the start of a new peer
                "public_key" => break,

                "preshared_key" => {
                    ensure!(
                        preshared_key.is_none(),
                        "Key {k:?} may not be specified twice",
                    );
                    *preshared_key = Some(if v.is_empty() {
                        SetUnset::Unset
                    } else {
                        let key_bytes: KeyBytes =
                            v.parse().map_err(|e| eyre!("Failed to parse {k:?}: {e}"))?;
                        if key_bytes.0.iter().all(|&b| b == 0) {
                            SetUnset::Unset
                        } else {
                            SetUnset::Set(key_bytes)
                        }
                    });
                }
                "endpoint" => parse_opt!(k, v, endpoint),
                "persistent_keepalive_interval" => parse_opt!(k, v, persistent_keepalive_interval),
                "remove" => parse_bool!(k, v, remove),
                "update_only" => parse_bool!(k, v, update_only),
                "replace_allowed_ips" => parse_bool!(k, v, replace_allowed_ips),
                "allowed_ip" => allowed_ip.push(v.parse().map_err(|err| eyre!("{err}"))?),

                #[cfg(feature = "daita-uapi")]
                _ if matches!(try_process_daita_line(daita_settings, k, v), Ok(true)) => (),

                _ => bail!("Key {k:?} in {line:?} is not allowed in command set/peer"),
            }

            // advance the iterator *after* we make sure we want to consume the line
            // i.e. after we check for an empty line, or a public_key
            lines.next();
        }

        Ok(set_peer)
    }
}

/// Update `daita_settings` based on the key-value pair. If the key is not recognized,
/// `Ok(false)` is returned. If anything was updated, `Ok(true)` is returned. If the key is
/// recognized but anything at all fails, an error is returned.
#[cfg(feature = "daita-uapi")]
fn try_process_daita_line(
    daita_settings: &mut Option<SetUnset<DaitaSettings>>,
    k: &str,
    v: &str,
) -> eyre::Result<bool> {
    fn daita_or_bail(
        daita_settings: &mut Option<SetUnset<DaitaSettings>>,
    ) -> eyre::Result<&mut DaitaSettings> {
        let Some(SetUnset::Set(daita_settings)) = daita_settings else {
            bail!("DAITA must be enabled with daita_enable=1");
        };
        Ok(daita_settings)
    }
    match k {
        "daita_enable" => {
            ensure!(
                v == "1" || v == "0",
                "The only valid value for key {:?} is \"1\" and \"0\"",
                k
            );

            if v == "0" {
                *daita_settings = Some(SetUnset::Unset);
            } else {
                *daita_settings = Some(SetUnset::Set(DaitaSettings::default()));
            }
        }
        "daita_machine" => {
            let daita_settings = daita_or_bail(daita_settings)?;
            let machine = v
                .parse()
                .map_err(|err| eyre!("invalid daita machine {:?}: {err}", v))?;
            daita_settings.maybenot_machines.push(machine);
        }
        "daita_max_decoy_frac" => {
            let daita_settings = daita_or_bail(daita_settings)?;
            daita_settings.max_decoy_frac = v
                .parse()
                .map_err(|err| eyre!("invalid padding frac: {err}"))?;
        }
        "daita_max_delay_frac" => {
            let daita_settings = daita_or_bail(daita_settings)?;
            daita_settings.max_delay_frac = v
                .parse()
                .map_err(|err| eyre!("invalid delay frac: {err}"))?;
        }
        "daita_max_delayed_packets" => {
            let daita_settings = daita_or_bail(daita_settings)?;
            daita_settings.max_delayed_packets = v
                .parse()
                .map_err(|err| eyre!("invalid delayed packets: {err}"))?;
        }
        "daita_min_delay_capacity" => {
            let daita_settings = daita_or_bail(daita_settings)?;
            daita_settings.min_delay_capacity = v
                .parse()
                .map_err(|err| eyre!("invalid min delay capacity: {err}"))?;
        }
        _ => return Ok(false),
    }
    Ok(true)
}

impl FromStr for Request {
    type Err = eyre::Report;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        //let s = s.trim();

        let Some((first_line, ..)) = s.split_once('\n') else {
            bail!("Missing newline: {s:?}");
        };

        Ok(match first_line {
            "set=1" => Set::from_str(s)?.into(),
            "get=1" => Get::from_str(s)?.into(),
            _ => bail!("Unknown command: {s:?}"),
        })
    }
}

fn to_key_value(line: &str) -> eyre::Result<(&str, &str)> {
    line.split_once('=')
        .ok_or(eyre!("expected {line:?} to be `<key>=<value>`"))
}
