//! Generic buffered UdpTransport implementation.

use std::iter;
use std::{net::SocketAddr, sync::Arc};

use tokio::{io, sync::mpsc};

use crate::packet::{Packet, PacketBufPool};
use crate::task::Task;
use crate::udp::{UdpRecv, UdpSend};

#[derive(Clone)]
pub struct BufferedUdpSend {
    _send_task: Arc<Task>,
    send_tx: mpsc::Sender<(Packet, SocketAddr)>,
}

impl BufferedUdpSend {
    pub fn new(capacity: usize, udp_tx: impl UdpSend + 'static) -> Self {
        let (send_tx, mut send_rx) = mpsc::channel::<(Packet, SocketAddr)>(capacity);

        let send_task = Task::spawn("buffered UDP send", async move {
            let mut buf = vec![];
            let max_number_of_packets_to_send = udp_tx.max_number_of_packets_to_send();
            let mut send_many_buf = Default::default();

            loop {
                let count = send_rx
                    .recv_many(&mut buf, max_number_of_packets_to_send)
                    .await;
                if count == 0 {
                    break;
                }
                // send all packets at once
                let _ = udp_tx
                    .send_many_to(&mut send_many_buf, &mut buf)
                    .await
                    .inspect_err(|e| log::trace!("send_to_many_err: {e:#}"));
            }
        });

        Self {
            _send_task: Arc::new(send_task),
            send_tx,
        }
    }
}

impl UdpSend for BufferedUdpSend {
    type SendManyBuf = ();

    async fn send_to(&self, packet: Packet, destination: SocketAddr) -> io::Result<()> {
        self.send_tx.send((packet, destination)).await.unwrap();
        Ok(())
    }

    fn max_number_of_packets_to_send(&self) -> usize {
        self.send_tx.capacity()
    }
}

pub struct BufferedUdpReceive {
    _recv_task: Arc<Task>,
    recv_rx: mpsc::Receiver<(Packet, SocketAddr)>,
    capacity: usize,
}

impl BufferedUdpReceive {
    pub fn new<U: UdpRecv + 'static>(
        capacity: usize,
        mut udp_rx: impl UdpRecv + 'static,
        mut recv_pool: PacketBufPool,
    ) -> Self {
        let (recv_tx, recv_rx) = mpsc::channel::<(Packet, SocketAddr)>(capacity);

        let recv_task = Task::spawn("buffered UDP receive", async move {
            let max_number_of_packets = udp_rx.max_number_of_packets_to_recv();
            let mut recv_many_buf = Default::default();
            let mut packet_bufs = Vec::with_capacity(max_number_of_packets);

            loop {
                // Read packets from the socket.
                let Ok(()) = udp_rx
                    .recv_many_from(&mut recv_many_buf, &mut recv_pool, &mut packet_bufs)
                    .await
                else {
                    // TODO
                    return;
                };

                for (packet_buf, src) in packet_bufs.drain(..) {
                    match recv_tx.try_send((packet_buf, src)) {
                        Ok(_) => (),
                        Err(mpsc::error::TrySendError::Full((packet_buf, addr))) => {
                            if recv_tx.send((packet_buf, addr)).await.is_err() {
                                // Buffer dropped
                                return;
                            }
                        }
                        Err(mpsc::error::TrySendError::Closed(_)) => return,
                    }
                }
            }
        });

        Self {
            _recv_task: Arc::new(recv_task),
            recv_rx,
            capacity,
        }
    }
}

impl UdpRecv for BufferedUdpReceive {
    type RecvManyBuf = ();

    async fn recv_from(&mut self, _pool: &mut PacketBufPool) -> io::Result<(Packet, SocketAddr)> {
        let Some((rx_packet, src)) = self.recv_rx.recv().await else {
            return Err(io::Error::other("No packet available"));
        };
        Ok((rx_packet, src))
    }

    // TODO: implement recv_from many with mpsc::Receiver::recv_many?

    fn max_number_of_packets_to_recv(&self) -> usize {
        self.capacity
    }
}
