use tokio::sync::watch;

use crate::packet::{Ip, Packet, PacketBufPool};
use std::future::{Future, pending};
use std::io;

pub mod buffer;
pub mod channel;

#[cfg(feature = "pcap")]
pub mod pcap;

#[cfg(feature = "tun")]
pub mod tun_async_device;

/// A type that let's you send an IP packet.
///
/// This is used as an abstraction of the TUN device used by wireguard,
/// and enables us to, for example, swap it out with a channel.
pub trait IpSend: Send + Sync + 'static {
    /// Send a complete IP packet.
    // TODO: consider refactoring trait with methods that take `Packet<Ipv4>` and `Packet<Ipv6>`
    fn send(&mut self, packet: Packet<Ip>) -> impl Future<Output = io::Result<()>> + Send;
}

/// A type that let's you receive an IP packet.
///
/// This is used as an abstraction of the TUN device used by wireguard,
/// and enables us to, for example, swap it out with a channel.
pub trait IpRecv: Send + Sync + 'static {
    /// Receive a complete IP packet.
    // TODO: consider refactoring trait with methods that return `Packet<Ipv4>` and `Packet<Ipv6>`
    fn recv<'a>(
        &'a mut self,
        pool: &mut PacketBufPool,
    ) -> impl Future<Output = io::Result<impl Iterator<Item = Packet<Ip>> + Send + 'a>> + Send;

    /// The largest allowed MTU for this device
    fn mtu(&self) -> LinkMtuWatcher;
}

#[derive(Clone)]
pub struct LinkMtuWatcher {
    mtu_source: MtuSource,
    modifier: i32,
}

#[derive(Clone)]
enum MtuSource {
    Constant(u16),
    Watch(watch::Receiver<u16>),
}

impl LinkMtuWatcher {
    /// Create an MTU watcher which always returns `mtu`.
    pub const fn new(mtu: u16) -> Self {
        Self {
            mtu_source: MtuSource::Constant(mtu),
            modifier: 0,
        }
    }

    /// Get the current link-MTU.
    pub fn get(&mut self) -> u16 {
        let mtu = match &mut self.mtu_source {
            MtuSource::Constant(mtu) => *mtu,
            MtuSource::Watch(mtu_rx) => *mtu_rx.borrow_and_update(),
        };

        i32::from(mtu)
            .checked_add(self.modifier)
            .and_then(|int| u16::try_from(int).ok())
            .expect("MTU over/underflow")
    }

    /// Wait for the link-MTU to change and return the new value.
    pub async fn wait(&mut self) -> u16 {
        match &mut self.mtu_source {
            MtuSource::Constant(_) => return pending().await,
            MtuSource::Watch(mtu_rx) => {
                if mtu_rx.changed().await.is_err() {
                    return pending().await;
                }
            }
        }

        self.get()
    }

    /// Raise the MTU value returned by [Self] by `value`.
    ///
    /// Any downstream (cloned) [Self] will inherit this change, but any upstream [Self] won't.
    pub fn add(self, value: u16) -> Option<Self> {
        Some(Self {
            modifier: self.modifier.checked_add(i32::from(value))?,
            ..self
        })
    }

    /// Lower the MTU value returned by [Self] by `value`.
    ///
    /// Any downstream (cloned) [Self] will inherit this change, but any upstream [Self] won't.
    pub fn sub(self, value: u16) -> Option<Self> {
        Some(Self {
            modifier: self.modifier.checked_sub(i32::from(value))?,
            ..self
        })
    }
}

impl From<watch::Receiver<u16>> for LinkMtuWatcher {
    fn from(mtu_rx: watch::Receiver<u16>) -> Self {
        Self {
            mtu_source: MtuSource::Watch(mtu_rx),
            modifier: 0,
        }
    }
}
