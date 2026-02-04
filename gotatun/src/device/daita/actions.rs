// Copyright (c) 2025 Mullvad VPN AB. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use super::types::{Action, DecoyHeader, DelayState, ErrorAction, PacketCount, Result};
use crate::{
    device::{
        daita::types::{DelayWatcher, IgnoreReason},
        peer_state::PeerState,
    },
    packet::{self, Packet, WgData},
    tun::MtuWatcher,
    udp::UdpSend,
};
use futures::FutureExt;
use maybenot::{MachineId, TriggerEvent};
use std::{
    net::{IpAddr, SocketAddr},
    sync::{
        Arc, Weak,
        atomic::{self, AtomicUsize},
    },
    time::Duration,
};
use tokio::{
    sync::{
        Mutex,
        mpsc::{self, error::TryRecvError},
    },
    time::Instant,
};
use typed_builder::TypedBuilder;
use zerocopy::IntoBytes;

#[derive(TypedBuilder)]
pub struct ActionHandler<US>
where
    US: UdpSend + Clone + 'static,
{
    packet_count: Arc<PacketCount>,
    delay_queue_rx: mpsc::Receiver<Packet<WgData>>,
    delay_watcher: DelayWatcher,
    peer: Weak<Mutex<PeerState>>,
    packet_pool: packet::PacketBufPool,
    udp_send_v4: US,
    udp_send_v6: US,
    mtu: MtuWatcher,
    tx_decoy_packet_bytes: Arc<AtomicUsize>,
    event_tx: mpsc::WeakUnboundedSender<TriggerEvent>,
}

impl<US> ActionHandler<US>
where
    US: UdpSend + Clone + 'static,
{
    pub(crate) async fn handle_actions(
        mut self,
        mut actions: mpsc::UnboundedReceiver<(Action, MachineId)>,
    ) {
        let mut delayed_packets_buf = Vec::new();

        loop {
            let res = futures::select! {
                () = self.delay_watcher.wait_delay_ended().fuse() => {
                    // Flush delayed packets
                    self.end_delay(&mut delayed_packets_buf).await
                }
                res = actions.recv().fuse() => {
                    let Some((action, machine)) = res else {
                        log::trace!("DAITA: actions channel closed, exiting handle_actions");
                        let _ = self.end_delay(&mut delayed_packets_buf).await;
                        break;
                    };
                    match action {
                        Action::Decoy { replace, bypass } => {
                            self.handle_decoy(machine, replace, bypass).await
                        }
                        Action::Delay { replace, bypass, duration } => {
                            self.handle_delay(machine, replace, bypass, duration).await
                        }
                    }
                }
            };
            match res {
                Err(ErrorAction::Close) => return,
                Err(ErrorAction::Ignore(reason)) => {
                    log::trace!("Ignoring DAITA action error: {reason}")
                }
                Ok(()) => {}
            }
        }
    }

    /// Start or extend packet delay according to [`maybenot::TriggerAction::BlockOutgoing`].
    ///
    /// Note that we use the term "delay" to refer to what `maybenot` calls "blocking".
    async fn handle_delay(
        &mut self,
        machine: MachineId,
        replace: bool,
        bypass: bool,
        duration: Duration,
    ) -> Result<()> {
        self.send_event(TriggerEvent::BlockingBegin { machine })?;
        let mut delay = self.delay_watcher.delay_state.write().await;
        let new_expiry = Instant::now() + duration;
        match *delay {
            DelayState::Active { expires_at, .. } if !replace && new_expiry <= expires_at => {}
            _ => {
                *delay = DelayState::Active {
                    bypass,
                    expires_at: new_expiry,
                };
            }
        }
        Ok(())
    }

    /// Send a decoy packet according to [`maybenot::TriggerAction::SendPadding`].
    ///
    /// Note that we use the term "decoy packet" to refer to what `maybenot` calls "padding packets".
    async fn handle_decoy(
        &mut self,
        machine: MachineId,
        replace: bool,
        decoy_bypass: bool,
    ) -> Result<()> {
        self.send_event(TriggerEvent::PaddingSent { machine })?;

        let delay_state = { *self.delay_watcher.delay_state.read().await };
        match delay_state {
            DelayState::Active { bypass: true, .. } if replace && decoy_bypass => {
                if let Ok(packet) = self.delay_queue_rx.try_recv() {
                    // Replace decoy with a delayed packet
                    let peer = self.get_peer().await?;
                    self.send(packet, peer).await
                } else {
                    // No delayed packet to replace, just send decoy
                    self.send_decoy().await
                }
            }
            // Allow decoy to bypass delay
            DelayState::Active { bypass: true, .. } if !replace && decoy_bypass => {
                self.send_decoy().await
            }
            DelayState::Active { .. }
                if replace
                    && (self.packet_count.outbound() > 0 || !self.delay_queue_rx.is_empty()) =>
            {
                // Replace decoy with any queued packet
                Ok(())
            }
            // Add packet to delay queue if it shouldn't or cannot be replaced
            DelayState::Active { .. } => {
                let mut peer = self.get_peer().await?;
                let mtu = self.mtu.get();
                let decoy_packet = self.encapsulate_decoy(&mut peer, mtu)?;
                //  Drop the decoy packet if the delay queue is full
                let _ = self.delay_watcher.delay_queue_tx.try_send(decoy_packet);
                Ok(())
            }
            // Replace decoy packet with in-flight packet
            DelayState::Inactive if replace && self.packet_count.outbound() > 0 => Ok(()),
            DelayState::Inactive => self.send_decoy().await,
        }
    }

    /// Flush all packets from the delay queue and end the delay state.
    pub(crate) async fn end_delay(
        &mut self,
        packets: &mut Vec<(Packet, SocketAddr)>,
    ) -> Result<()> {
        let Some(addr) = self.get_peer().await?.endpoint().addr else {
            log::trace!("No endpoint");
            return Err(ErrorAction::Close);
        };

        let udp_send = match addr.ip() {
            IpAddr::V4(..) => &self.udp_send_v4,
            IpAddr::V6(..) => &self.udp_send_v6,
        };

        let mut send_many_bufs = US::SendManyBuf::default();
        let mut delay = true;
        let limit = udp_send.max_number_of_packets_to_send();
        loop {
            while packets.len() <= limit {
                match self.delay_queue_rx.try_recv() {
                    Ok(packet) => packets.push((packet.into(), addr)),
                    Err(TryRecvError::Empty) => {
                        // When the packet queue is empty, we can end the delay state.
                        // To prevent new packets from sneaking into the queue before we set the state to Inactive,
                        // we loop once more and flush any new packets that might have arrived.
                        if delay {
                            *self.delay_watcher.delay_state.write().await = DelayState::Inactive;
                            self.send_event(TriggerEvent::BlockingEnd)?;
                            delay = false;
                        } else {
                            return Ok(());
                        }
                    }
                    Err(TryRecvError::Disconnected) => {
                        return Err(ErrorAction::Close); // channel closed,
                    }
                }
            }
            let count = packets.len();
            if let Ok(()) = udp_send.send_many_to(&mut send_many_bufs, packets).await {
                // In case not all packets are drained from `packets`, we count remaining items
                let sent = count - packets.len();
                self.packet_count.dec(sent as u32);
                let event_tx = self.event_tx.upgrade().ok_or(ErrorAction::Close)?;
                // Trigger a TunnelSent for each packet sent
                for _ in 0..sent {
                    event_tx
                        .send(TriggerEvent::TunnelSent)
                        .map_err(|_| ErrorAction::Close)?;
                }
            }
        }
    }

    pub(crate) fn encapsulate_decoy(
        &self,
        peer: &mut tokio::sync::OwnedMutexGuard<PeerState>,
        mtu: u16,
    ) -> Result<Packet<WgData>> {
        self.tx_decoy_packet_bytes
            .fetch_add(mtu as usize, atomic::Ordering::SeqCst);
        peer.tunnel
            .encapsulate_with_session(self.create_decoy_packet(mtu))
            // Encapsulate can only fail when there is no session, just drop the decoy packet in that case
            .map_err(|_| ErrorAction::Ignore(IgnoreReason::NoSession))
    }

    pub(crate) fn create_decoy_packet(&self, mtu: u16) -> Packet {
        let decoy_packet_header = DecoyHeader::new(mtu.into());
        let mut decoy_packet_buf = self.packet_pool.get();
        decoy_packet_buf.buf_mut().clear();
        decoy_packet_buf
            .buf_mut()
            .extend_from_slice(decoy_packet_header.as_bytes());
        decoy_packet_buf.buf_mut().resize(mtu.into(), 0);
        decoy_packet_buf
    }

    pub(crate) async fn send_decoy(&mut self) -> Result<()> {
        let mtu = self.mtu.get();
        let mut peer = self.get_peer().await?;

        let packet = self.encapsulate_decoy(&mut peer, mtu)?;
        self.send(packet, peer).await?;
        Ok(())
    }

    pub(crate) async fn send(
        &self,
        packet: Packet<WgData>,
        peer: tokio::sync::OwnedMutexGuard<PeerState>,
    ) -> Result<()> {
        let endpoint_addr = peer.endpoint().addr;
        let Some(addr) = endpoint_addr else {
            return Err(ErrorAction::Ignore(IgnoreReason::NoEndpoint));
        };

        let udp_send = match addr.ip() {
            IpAddr::V4(..) => &self.udp_send_v4,
            IpAddr::V6(..) => &self.udp_send_v6,
        };

        self.send_event(TriggerEvent::TunnelSent)?;

        udp_send
            .send_to(packet.into_bytes(), addr)
            .await
            .map_err(|_| ErrorAction::Close)?;

        Ok(())
    }

    pub(crate) async fn get_peer(&self) -> Result<tokio::sync::OwnedMutexGuard<PeerState>> {
        let Some(peer) = self.peer.upgrade() else {
            return Err(ErrorAction::Close);
        };
        let peer = peer.lock_owned().await;
        Ok(peer)
    }

    pub(crate) fn send_event(&self, event: TriggerEvent) -> Result<()> {
        self.event_tx
            .upgrade()
            .ok_or(ErrorAction::Close)?
            .send(event)
            .map_err(|_| ErrorAction::Close)
    }
}
