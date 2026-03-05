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

#[cfg(feature = "tun")]
use crate::{tun::tun_async_device::TunDevice, udp::socket::UdpSocketFactory};
use crate::{
    tun::{IpRecv, IpSend},
    udp::UdpTransportFactory,
};

/// By default, use a UDP socket for sending datagrams and a TUN device for IP packets.
#[cfg(feature = "tun")]
pub type DefaultDeviceTransports = (UdpSocketFactory, TunDevice, TunDevice);

/// Trait that defines the transport components for a WireGuard device.
///
/// This trait is automatically implemented for tuples of transport types.
pub trait DeviceTransports: 'static {
    /// Factory for creating UDP sockets to send and receive WireGuard packets.
    type UdpTransportFactory: UdpTransportFactory;
    /// Type for sending IP packets to the TUN interface.
    type IpSend: IpSend;
    /// Type for receiving IP packets from the TUN interface.
    type IpRecv: IpRecv;
}

impl<UF, IS, IR> DeviceTransports for (UF, IS, IR)
where
    UF: UdpTransportFactory,
    IS: IpSend,
    IR: IpRecv,
{
    type UdpTransportFactory = UF;
    type IpSend = IS;
    type IpRecv = IR;
}

impl<UF, IP> DeviceTransports for (UF, IP)
where
    UF: UdpTransportFactory,
    IP: IpSend + IpRecv + Clone,
{
    type UdpTransportFactory = UF;
    type IpSend = IP;
    type IpRecv = IP;
}
