// Copyright (c) 2026 Mullvad VPN AB. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

#[cfg(feature = "tun")]
use crate::{tun::tun_async_device::TunDevice, udp::socket::UdpSocketFactory};
use crate::{
    tun::{IpRecv, IpSend},
    udp::UdpTransportFactory,
};

/// By default, use a UDP socket for sending datagrams and a TUN device for IP packets.
#[cfg(feature = "tun")]
pub type DefaultDeviceTransports = (UdpSocketFactory, TunDevice, TunDevice);

pub trait DeviceTransports: 'static {
    type UdpTransportFactory: UdpTransportFactory;
    type IpSend: IpSend;
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
