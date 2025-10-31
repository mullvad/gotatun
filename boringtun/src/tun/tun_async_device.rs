//! Implementations of [IpSend] and [IpRecv] for the [tun] crate.

use tokio::{sync::watch, time::sleep};
use tun::AbstractDevice;

use crate::{
    packet::{Ip, Packet, PacketBufPool},
    task::Task,
    tun::{IpRecv, IpSend, MtuWatcher},
};

use std::{convert::Infallible, io, iter, sync::Arc, time::Duration};

/// A kernel virtual network device; a TUN device.
///
/// Implements [IpSend] and [IpRecv].
#[derive(Clone)]
pub struct TunDevice {
    tun: Arc<tun::AsyncDevice>,
    state: Arc<TunDeviceState>,
}

struct TunDeviceState {
    mtu: MtuWatcher,

    /// Task which monitors TUN device MTU. Aborted when dropped.
    _mtu_monitor: Task,
}

impl TunDevice {
    /// Construct from a [tun::AsyncDevice].
    pub fn from_tun_device(tun: tun::AsyncDevice) -> io::Result<Self> {
        if !tun.packet_information() {
            return Err(io::Error::other("packet_information is not supported"));
        };

        #[cfg(not(target_os = "ios"))]
        let mtu = tun.mtu()?;
        #[cfg(target_os = "ios")]
        let mtu: u16 = 1280;

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
