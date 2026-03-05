// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// This file incorporates work covered by the following copyright and
// permission notice:
//
//   Copyright (c) Mullvad VPN AB. All rights reserved.
//
// SPDX-License-Identifier: MPL-2.0

use std::{
    io::{self},
    net::SocketAddr,
};

use crate::{
    packet::{Packet, PacketBufPool},
    udp::{UdpRecv, UdpSend},
};

impl UdpSend for super::UdpSocket {
    type SendManyBuf = ();

    async fn send_to(&self, packet: Packet, target: SocketAddr) -> io::Result<()> {
        self.inner.send_to(&packet, target).await?;
        Ok(())
    }

    fn local_addr(&self) -> io::Result<Option<SocketAddr>> {
        super::UdpSocket::local_addr(self).map(Some)
    }
}

impl UdpRecv for super::UdpSocket {
    type RecvManyBuf = ();

    async fn recv_from(&mut self, pool: &mut PacketBufPool) -> io::Result<(Packet, SocketAddr)> {
        let mut buf = pool.get();
        let (n, src) = self.inner.recv_from(&mut buf).await?;
        buf.truncate(n);
        Ok((buf, src))
    }
}
