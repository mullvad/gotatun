use super::types::{Action, BlockingState, ErrorAction, PacketCount, PaddingHeader, Result};
use crate::{
    device::{daita::types::BlockingWatcher, peer::Peer},
    packet::{self, Packet, Wg},
    tun::LinkMtuWatcher,
    udp::UdpSend,
};
use futures::FutureExt;
use maybenot::{MachineId, TriggerEvent};
use std::sync::{Arc, Weak, atomic::AtomicUsize};
use tokio::{
    sync::{Mutex, mpsc},
    time::Instant,
};
use zerocopy::IntoBytes;

pub struct ActionHandler<US>
where
    US: UdpSend + Clone + 'static,
{
    pub(super) packet_count: Arc<PacketCount>,
    pub(super) blocking_queue_rx: mpsc::Receiver<Packet<Wg>>,
    pub(super) blocking_watcher: BlockingWatcher,
    pub(super) peer: Weak<Mutex<Peer>>,
    pub(super) packet_pool: packet::PacketBufPool,
    pub(super) udp_send: US,
    pub(super) mtu: LinkMtuWatcher,
    pub(super) tx_padding_packet_bytes: Arc<AtomicUsize>,
    pub(super) event_tx: mpsc::WeakUnboundedSender<TriggerEvent>,
}

impl<US> ActionHandler<US>
where
    US: UdpSend + Clone + 'static,
{
    pub(crate) async fn handle_actions(
        mut self,
        mut actions: mpsc::UnboundedReceiver<(Action, MachineId)>,
    ) {
        let mut blocked_packets_buf = Vec::new();

        loop {
            let res = futures::select! {
                _ = self.blocking_watcher.wait_blocking_ended().fuse() => {
                    log::debug!("DAITA: Blocking ended, flushing blocked packets");
                    self.end_blocking(&mut blocked_packets_buf).await
                }
                res = actions.recv().fuse() => {
                    let Some((action, machine)) = res else {
                        log::debug!("DAITA: actions channel closed, exiting handle_actions");
                        break; // TODO: flush blocked packets?
                    };
                    match action {
                        Action::Padding { replace, bypass } => {
                            self.handle_padding(machine, replace, bypass).await
                        }
                        Action::Block { replace, bypass, duration } => {
                            self.handle_blocking(machine, replace, bypass, duration).await
                        }
                    }
                }
            };
            match res {
                Err(ErrorAction::Close) => return,
                Err(ErrorAction::Ignore) => {}
                Ok(()) => {}
            }
        }
    }

    /// Start or extend blocking according to [`maybenot::TriggerAction::BlockOutgoing`].
    async fn handle_blocking(
        &mut self,
        machine: MachineId,
        replace: bool,
        bypass: bool,
        duration: std::time::Duration,
    ) -> Result<()> {
        self.send_event(TriggerEvent::BlockingBegin { machine })?;
        let mut blocking = self.blocking_watcher.blocking_state.write().await;
        let new_expiry = Instant::now() + duration;
        match &mut *blocking {
            BlockingState::Active { expires_at, .. } if !replace && new_expiry <= *expires_at => {
                log::debug!("Current blocking was not replaced");
            }
            _ => {
                *blocking = BlockingState::Active {
                    bypass,
                    expires_at: new_expiry,
                };
                log::debug!("Blocking started");
            }
        };
        Ok(())
    }

    /// Send a padding packet according to [`maybenot::TriggerAction::SendPadding`].
    async fn handle_padding(
        &mut self,
        machine: MachineId,
        replace: bool,
        padding_bypass: bool,
    ) -> Result<()> {
        self.send_event(TriggerEvent::PaddingSent { machine })?;

        let blocking_with_bypass = match &*self.blocking_watcher.blocking_state.read().await {
            BlockingState::Inactive => None,
            BlockingState::Active {
                bypass: blocking_bypass,
                ..
            } => Some(*blocking_bypass && padding_bypass), // Both must be true to bypass
        };

        match (blocking_with_bypass, replace) {
            (Some(true), true) => {
                if let Ok(packet) = self.blocking_queue_rx.try_recv() {
                    // self.send_event(TriggerEvent::NormalSent)?; // TODO: Already sent when queued, unclear spec
                    log::debug!("Padding packet was replaced by blocked packet which was sent");
                    let peer = self.get_peer().await?;
                    self.send(packet, peer).await?;
                }
                log::debug!("Padding packet could not be replaced by blocked packet and was sent");
                self.send_padding().await
            }
            (Some(true), false) => {
                log::debug!("Padding packet was sent bypassing blocking");
                self.send_padding().await
            }
            (Some(false), true)
                if self.packet_count.replaced()
                    < self.packet_count.outbound() + self.blocking_queue_rx.len() as u32 =>
            {
                log::debug!("Padding packet was replaced by blocked data packet and dropped");
                self.packet_count.inc_replaced(1);
                Ok(())
            }
            // Padding packet should or cannot be replaced by a blocked packet, so we must added it to the blocking queue
            (Some(false), _) => {
                log::debug!("Padding packet was added to blocking queue");
                let mut peer = self.get_peer().await?;
                let mtu = self.mtu.get();
                let padding_packet = self.encapsulate_padding(&mut peer, mtu).await?;
                //  Drop the padding packet if blocking queue is full
                let _ = self
                    .blocking_watcher
                    .blocking_queue_tx
                    .try_send(padding_packet);
                Ok(())
            }
            (None, true) if self.packet_count.replaced() < self.packet_count.outbound() => {
                log::debug!("Padding packet was replaced by in-flight data packet and dropped");
                self.packet_count.inc_replaced(1);
                Ok(())
            }
            (None, _) => {
                log::debug!("Padding packet was sent");
                self.send_padding().await
            }
        }
    }

    /// Flush all blocked packets and end blocking.
    pub(crate) async fn end_blocking(&mut self, packets: &mut Vec<Packet<Wg>>) -> Result<()> {
        let Some(addr) = self.get_peer().await?.endpoint().addr else {
            log::error!("No endpoint");
            return Err(ErrorAction::Close);
        };

        let mut send_many_bufs = US::SendManyBuf::default();
        let mut blocking = true;
        loop {
            let limit = self.udp_send.max_number_of_packets_to_send();
            futures::select! {
                count = self.blocking_queue_rx.recv_many(packets, limit - packets.len()).fuse() => {
                    if count == 0 {
                        break Err(ErrorAction::Close); // channel closed
                    }
                },
                // Packet queue is empty
                default => {
                    // When the packet queue is empty, we can end blocking.
                    // To prevent new packets from sneaking into the queue before we set the state to Inactive,
                    // we loop once more and flush any new packets that might have arrived.
                    if blocking {
                        *self.blocking_watcher.blocking_state.write().await = BlockingState::Inactive;
                        self.send_event(TriggerEvent::BlockingEnd)?;
                        blocking = false;
                    }  else {
                        return Ok(());
                    }

                },
            }

            let count = packets.len();
            if let Ok(()) = self
                .udp_send
                .send_many_to(
                    &mut send_many_bufs,
                    packets.drain(..).map(|p| (p.into_bytes(), addr)),
                )
                .await
            {
                // Trigger a TunnelSent for each packet sent
                self.packet_count.dec(count as u32);
                let event_tx = self.event_tx.upgrade().ok_or(ErrorAction::Close)?;
                for _ in 0..count {
                    event_tx
                        .send(TriggerEvent::TunnelSent)
                        .map_err(|_| ErrorAction::Close)?;
                }
            }
        }
    }

    // TODO: handle the case where handle_outgoing_packet returns a handshake
    pub(crate) async fn encapsulate_padding(
        &self,
        peer: &mut tokio::sync::OwnedMutexGuard<Peer>,
        mtu: u16,
    ) -> Result<Packet<Wg>> {
        // TODO: Reuse the same padding packet each time (unless MTU changes)?
        match peer
            .tunnel
            .handle_outgoing_packet(self.create_padding_packet(mtu))
        {
            None => Err(ErrorAction::Ignore), // TODO: error?
            Some(packet) => Ok(packet),
        }
    }

    pub(crate) fn create_padding_packet(&self, mtu: u16) -> Packet {
        let padding_packet_header = PaddingHeader {
            _daita_marker: 0xFF,
            _reserved: 0,
            length: mtu.into(),
        };
        let mut padding_packet_buf = self.packet_pool.get();
        padding_packet_buf.buf_mut().clear();
        padding_packet_buf
            .buf_mut()
            .extend_from_slice(padding_packet_header.as_bytes());
        padding_packet_buf.buf_mut().resize(mtu.into(), 0);
        padding_packet_buf
    }

    pub(crate) async fn send_padding(&mut self) -> Result<()> {
        let mtu = self.mtu.get();
        let mut peer = self.get_peer().await?;

        let packet = self.encapsulate_padding(&mut peer, mtu).await?;
        self.send(packet, peer).await?;
        Ok(())
    }

    pub(crate) async fn send(
        &self,
        packet: Packet<Wg>,
        peer: tokio::sync::OwnedMutexGuard<Peer>,
    ) -> Result<()> {
        let endpoint_addr = peer.endpoint().addr;
        let Some(addr) = endpoint_addr else {
            log::trace!("No endpoint");
            return Err(ErrorAction::Ignore);
        };
        self.udp_send
            .send_to(packet.into_bytes(), addr)
            .await
            .map_err(|_| ErrorAction::Close)?;
        // self.tx_padding_packet_bytes
        //     .fetch_add(MTU as usize, atomic::Ordering::SeqCst);
        self.send_event(TriggerEvent::TunnelSent)?;
        Ok(())
    }

    pub(crate) async fn get_peer(&self) -> Result<tokio::sync::OwnedMutexGuard<Peer>> {
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
