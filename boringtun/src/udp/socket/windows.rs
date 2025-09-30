use socket2::{Domain, Socket, Type};
use std::{ffi::c_uint, os::windows::io::AsRawSocket};
use std::{io, net::SocketAddr};
use std::{mem, sync::LazyLock};
use tokio::io::Interest;
use windows_sys::Win32::Networking::WinSock::{self, CMSGHDR};
use zerocopy::{FromBytes, FromZeros, Immutable, IntoBytes, KnownLayout};

use crate::{
    packet::{Packet, PacketBufPool},
    udp::{UdpRecv, UdpSend, socket::UdpSocket},
};

pub struct SendmmsgBuf {
    buffer: Vec<u8>,
    cmsg: Box<Cmsg>,
}

impl Default for SendmmsgBuf {
    fn default() -> Self {
        Self {
            buffer: vec![],
            cmsg: Cmsg::new(
                mem::size_of::<u32>(),
                WinSock::IPPROTO_UDP,
                WinSock::UDP_SEND_MSG_SIZE,
            ),
        }
    }
}

impl UdpSend for super::UdpSocket {
    type SendManyBuf = SendmmsgBuf;

    async fn send_to(&self, packet: Packet, target: SocketAddr) -> io::Result<()> {
        tokio::net::UdpSocket::send_to(&self.inner, &packet, target).await?;
        Ok(())
    }

    async fn send_many_to(
        &self,
        buf: &mut SendmmsgBuf,
        packets: &mut Vec<(Packet, SocketAddr)>,
    ) -> io::Result<()> {
        if *MAX_GSO_SEGMENTS == 1 {
            // No GSO support
            for (pkt, dest) in packets.drain(..) {
                self.send_to(pkt, dest).await?;
            }
            return Ok(());
        }

        let n = packets.len();
        debug_assert!(n <= *MAX_GSO_SEGMENTS);

        let client_socket_ref = socket2::SockRef::from(&*self.inner);

        let mut packets_iter = packets.drain(..);
        let mut saved_packet = None;

        loop {
            // Get our first packet
            let Some((pkt, dest)) = saved_packet.take().or_else(|| packets_iter.next()) else {
                break;
            };

            // If there's only a single packet, use send_to
            if packets_iter.len() == 0 {
                self.send_to(pkt, dest).await?;
                break;
            }

            buf.buffer.clear();
            buf.buffer.extend_from_slice(&pkt);

            let segment_size = pkt.len();

            // Coalesce packets into a single buffer
            loop {
                let Some((next_packet, next_addr)) = packets_iter.next() else {
                    break;
                };

                // If destination differs, stop coalescing
                if next_addr != dest {
                    saved_packet = Some((next_packet, next_addr));
                    break;
                }

                // If this packet is larger, we are done
                if next_packet.len() > segment_size {
                    saved_packet = Some((next_packet, next_addr));
                    break;
                }

                // Otherwise, append the next packet to the bunch
                buf.buffer.extend_from_slice(&next_packet);

                // The last packet may be smaller than previous segments:
                // https://learn.microsoft.com/en-us/windows/win32/winsock/ipproto-udp-socket-options
                if next_packet.len() < segment_size {
                    break;
                }
            }

            // Single packet, so use send_to
            if buf.buffer.len() == segment_size {
                self.send_to(pkt, dest).await?;
                continue;
            }

            self.inner
                .async_io(Interest::WRITABLE, || {
                    use std::io::IoSlice;

                    // Call sendmsg with one CMSG containing the segment size.
                    // This will send all packets in `buffer`.

                    buf.cmsg.data[..].copy_from_slice(&segment_size.to_ne_bytes());

                    let io_slices = [IoSlice::new(&buf.buffer); 1];
                    let daddr = socket2::SockAddr::from(dest);
                    let msg_hdr = socket2::MsgHdr::new()
                        .with_addr(&daddr)
                        .with_buffers(&io_slices)
                        .with_control(buf.cmsg.as_slice());

                    client_socket_ref.sendmsg(&msg_hdr, 0)
                })
                .await?;
        }

        Ok(())
    }

    fn max_number_of_packets_to_send(&self) -> usize {
        *MAX_GSO_SEGMENTS
    }

    fn local_addr(&self) -> io::Result<Option<SocketAddr>> {
        UdpSocket::local_addr(self).map(Some)
    }

    #[cfg(feature = "windows-gro")]
    /// Enable receive offloading
    fn enable_udp_gro(&self) -> io::Result<()> {
        use std::ffi::c_char;

        let raw_sock = self.inner.as_raw_socket();
        // Same as msquic
        let val = u32::from(u16::MAX);

        // SAFETY: We are passing valid pointers
        let result = unsafe {
            libc::setsockopt(
                usize::try_from(raw_sock).unwrap(),
                WinSock::IPPROTO_UDP,
                WinSock::UDP_RECV_MAX_COALESCED_SIZE,
                (&val) as *const u32 as *const c_char,
                mem::size_of_val(&val) as i32,
            )
        };

        if result == 0 {
            log::debug!("Enabled UDP GRO");
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }
}

#[cfg(not(feature = "windows-gro"))]
impl UdpRecv for super::UdpSocket {
    type RecvManyBuf = ();

    async fn recv_from(&mut self, pool: &mut PacketBufPool) -> io::Result<(Packet, SocketAddr)> {
        let mut buf = pool.get();
        let (n, src) = self.inner.recv_from(&mut buf).await?;
        buf.truncate(n);
        Ok((buf, src))
    }
}

#[cfg(feature = "windows-gro")]
mod gro {
    use super::*;

    use std::ptr;

    use socket2::{Domain, SockAddr, SockAddrStorage, Type};
    use std::{mem, os::windows::io::AsRawSocket, sync::LazyLock};
    use windows_sys::Win32::Networking::WinSock::{self, SOCKADDR_INET, WSABUF, WSAMSG};

    const MAX_RECV_PACKETS: usize = 100;

    pub struct RecvManyBuf {
        // TODO: create a single packet buf and split it?
        gro_buf: Vec<u8>,
        cmsg: Box<Cmsg>,
    }

    impl Default for RecvManyBuf {
        fn default() -> Self {
            let cmsg = Cmsg::new(
                mem::size_of::<u32>(),
                WinSock::IPPROTO_UDP,
                WinSock::UDP_COALESCED_INFO as i32,
            );
            Self {
                gro_buf: vec![],
                cmsg,
            }
        }
    }

    impl UdpRecv for super::UdpSocket {
        type RecvManyBuf = RecvManyBuf;

        async fn recv_from(
            &mut self,
            pool: &mut PacketBufPool,
        ) -> io::Result<(Packet, SocketAddr)> {
            let mut buf = pool.get();
            let (n, src) = self.inner.recv_from(&mut buf).await?;
            buf.truncate(n);
            Ok((buf, src))
        }

        async fn recv_many_from(
            &mut self,
            recv_buf: &mut Self::RecvManyBuf,
            pool: &mut PacketBufPool,
            packets: &mut Vec<(Packet, SocketAddr)>,
        ) -> io::Result<()> {
            let socket = self.inner.clone();
            recv_buf.gro_buf.resize(MAX_RECV_PACKETS * 1500, 0);

            let msg = self
                .inner
                .async_io(Interest::READABLE, || {
                    recvmsg(recv_buf.gro_buf.as_mut_slice(), &mut recv_buf.cmsg, &socket)
                })
                .await?;

            recv_buf
                .gro_buf
                .truncate(usize::try_from(msg.bytes_received).unwrap());

            if msg.gro_size == 0 {
                // Single packet
                let mut buf = pool.get();
                buf.buf_mut().clear();
                buf.buf_mut().extend_from_slice(&recv_buf.gro_buf);
                packets.push((buf, msg.source_addr));
                return Ok(());
            }

            // Split into multiple packets
            // TODO: Consider reading into one big buffer and splitting it
            for segment in recv_buf
                .gro_buf
                .chunks(usize::try_from(msg.gro_size).unwrap())
            {
                let mut buf = pool.get();
                buf.buf_mut().clear();
                buf.buf_mut().extend_from_slice(segment);
                packets.push((buf, msg.source_addr));
            }

            Ok(())
        }

        fn max_number_of_packets_to_recv(&self) -> usize {
            MAX_RECV_PACKETS
        }
    }

    struct RecvMsg {
        bytes_received: u32,
        gro_size: u32,
        source_addr: SocketAddr,
    }

    /// Receive GRO segments into `buffer` using `WSARecvMsg`
    fn recvmsg(
        buffer: &mut [u8],
        cmsg: &mut Cmsg,
        socket: &tokio::net::UdpSocket,
    ) -> io::Result<RecvMsg> {
        use windows_sys::Win32::Networking::WinSock::LPFN_WSARECVMSG;

        const UDP_COALESCED_INFO: i32 = WinSock::UDP_COALESCED_INFO as i32;

        // Load WSARecvMsg
        static RECVMSG: LazyLock<LPFN_WSARECVMSG> = LazyLock::new(|| {
            let mut bytes_returned: u32 = 0;
            let mut func: LPFN_WSARECVMSG = None;

            let sock = socket2::Socket::new(Domain::IPV4, Type::DGRAM, None)
                .inspect_err(|err| {
                    log::error!("Failed to create socket: {err}");
                })
                .ok()?;

            let guid = WinSock::WSAID_WSARECVMSG;
            let result = unsafe {
                WinSock::WSAIoctl(
                    sock.as_raw_socket() as usize,
                    WinSock::SIO_GET_EXTENSION_FUNCTION_POINTER,
                    &guid as *const _ as *mut _,
                    mem::size_of_val(&guid) as u32,
                    &mut func as *mut _ as *mut _,
                    mem::size_of_val(&func) as u32,
                    &mut bytes_returned as *mut _,
                    ptr::null_mut(),
                    None,
                )
            };

            if result != 0 {
                log::error!(
                    "Failed to get WSARecvMsg function pointer: {}",
                    io::Error::last_os_error()
                );
                None
            } else {
                func
            }
        });

        if buffer.len() == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "buffer must be non-empty",
            ));
        }

        let recvmsg = RECVMSG.expect("missing WSARecvMsg");

        let ctrl = WSABUF {
            len: cmsg.len() as u32,
            // TODO: use `cmsg.as_mut_ptr()` when we can implement `IntoBytes`
            buf: cmsg.header.as_mut_bytes().as_mut_ptr(),
        };

        let mut source = SOCKADDR_INET::default();

        let mut data = WSABUF {
            len: buffer.len() as u32,
            buf: buffer.as_mut_ptr() as *mut u8,
        };

        let mut msg = WSAMSG {
            name: &mut source as *mut _ as *mut _,
            namelen: mem::size_of_val(&source) as i32,
            lpBuffers: &mut data,
            dwBufferCount: 1,
            Control: ctrl,
            dwFlags: 0,
        };

        let mut len = 0;
        // SAFETY: All pointers are valid and point to initialized data
        // The lengths are correct
        let status = unsafe {
            (recvmsg)(
                socket.as_raw_socket() as usize,
                &mut msg,
                &mut len,
                ptr::null_mut(),
                None,
            )
        };
        if status == -1 {
            return Err(io::Error::last_os_error());
        }

        let mut gro_size = 0;

        if cmsg.header.cmsg_type == UDP_COALESCED_INFO {
            let slice = &cmsg.data[..mem::size_of::<u32>()];
            gro_size = u32::from_ne_bytes(slice.try_into().expect("cmsg data too small"));
        }

        let source = try_socketaddr_from_inet_sockaddr(source)
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "invalid source address"))?;

        Ok(RecvMsg {
            bytes_received: len,
            gro_size,
            source_addr: source,
        })
    }

    /// Converts a `SOCKADDR_INET` to `SocketAddr`. Returns `None` if the family is not valid.
    pub fn try_socketaddr_from_inet_sockaddr(addr: SOCKADDR_INET) -> Option<SocketAddr> {
        // SAFETY: SOCKADDR_INET and SockAddrStorage have the same layout
        unsafe {
            let mut storage: SockAddrStorage = mem::zeroed();
            *(&mut storage as *mut _ as *mut SOCKADDR_INET) = addr;
            SockAddr::new(storage, mem::size_of_val(&addr) as i32)
        }
        .as_socket()
    }
}

/// Struct representing a CMSG
#[derive(FromBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct Cmsg {
    pub header: Hdr,
    pub data: [u8],
}

/// `CMSGHDR`
#[derive(FromBytes, Immutable, KnownLayout, IntoBytes)]
#[repr(C)]
pub struct Hdr {
    pub cmsg_len: usize,
    pub cmsg_level: i32,
    pub cmsg_type: i32,
}

impl Cmsg {
    /// Create a new with space for `space` bytes and a CMSG header
    pub fn new(space: usize, cmsg_level: i32, cmsg_type: i32) -> Box<Self> {
        let mut cmsg = Cmsg::new_box_zeroed_with_elems(cmsg_space(space) - mem::size_of::<Hdr>())
            .expect("alloc");

        cmsg.header = Hdr {
            cmsg_len: cmsg_len(space),
            cmsg_level,
            cmsg_type,
        };

        cmsg
    }

    pub fn len(&self) -> usize {
        std::mem::size_of_val(self)
    }

    pub fn as_slice(&self) -> &[u8] {
        let ptr = self as *const Cmsg as *const CMSGHDR;
        // TODO: We can make this safe when `IntoBytes` supports DSTs
        // SAFETY: ptr is aligned and valid for reads of `self.len()` bytes
        unsafe { std::slice::from_raw_parts(ptr as *const u8, self.len()) }
    }
}

/// The total size of an ancillary data object given the amount of data
/// Source: ws2def.h: CMSG_SPACE macro
pub fn cmsg_space(length: usize) -> usize {
    cmsgdata_align(mem::size_of::<CMSGHDR>() + cmsghdr_align(length))
}

/// Value to store in the `cmsg_len` of the CMSG header given an amount of data.
/// Source: ws2def.h: CMSG_LEN macro
pub fn cmsg_len(length: usize) -> usize {
    cmsgdata_align(mem::size_of::<CMSGHDR>()) + length
}

// Taken from ws2def.h: CMSGHDR_ALIGN macro
pub fn cmsghdr_align(length: usize) -> usize {
    (length + mem::align_of::<WinSock::CMSGHDR>() - 1) & !(mem::align_of::<WinSock::CMSGHDR>() - 1)
}

// Source: ws2def.h: CMSGDATA_ALIGN macro
pub fn cmsgdata_align(length: usize) -> usize {
    (length + mem::align_of::<usize>() - 1) & !(mem::align_of::<usize>() - 1)
}

/// Maximum number of segments we can send in one go using UDP GSO
pub static MAX_GSO_SEGMENTS: LazyLock<usize> = LazyLock::new(|| {
    // Detect whether UDP GSO is supported
    let Ok(socket) = Socket::new(Domain::IPV4, Type::DGRAM, None) else {
        return 1;
    };

    let mut gso_size: c_uint = 1500;

    // SAFETY: We're correctly passing an *mut c_uint specifying the size, a valid socket, and
    // its correct size.
    let result = unsafe {
        libc::setsockopt(
            socket.as_raw_socket() as libc::SOCKET,
            WinSock::IPPROTO_UDP,
            WinSock::UDP_SEND_MSG_SIZE,
            &mut gso_size as *mut _ as *mut _,
            i32::try_from(std::mem::size_of_val(&gso_size)).unwrap(),
        )
    };

    // If non-zero (error), set max segment count to 1. Otherwise, set it to 512.
    // 512 is the "empirically found" value also used by quinn
    match result {
        0 => 512,
        _ => 1,
    }
});

/// Pointer to the first byte of data in `cmsg`.
/// Source: ws2def.h: CMSG_DATA macro
#[cfg(test)]
pub unsafe fn cmsg_data(cmsg: *mut CMSGHDR) -> *mut core::ffi::c_uchar {
    (cmsg as usize + cmsgdata_align(mem::size_of::<CMSGHDR>())) as *mut core::ffi::c_uchar
}

const _: () = {
    assert!(mem::size_of::<CMSGHDR>() == mem::size_of::<Hdr>());
    assert!(mem::align_of::<CMSGHDR>() == mem::align_of::<Hdr>());
};

#[cfg(test)]
mod test {
    use super::*;

    // Ensure that `Cmsg` works as expected
    #[test]
    fn test_cmsg_layout() {
        let space = 100;
        let cmsg_len = cmsg_len(space);

        let cmsg = Cmsg::new(space, 2, 3);
        let zc_data = cmsg.data.as_ptr();
        let cmsg_ptr = cmsg.as_ref() as *const Cmsg as *const u8 as *mut CMSGHDR;

        assert_eq!(
            // SAFETY: `cmsg_ptr` points to a valid CMSGHDR
            unsafe { cmsg_data(cmsg_ptr) } as *const u8,
            zc_data,
            "unexpected CMSG data ptr"
        );

        let standard_hdr = CMSGHDR {
            cmsg_len,
            cmsg_level: 2,
            cmsg_type: 3,
        };
        let hdr = unsafe { std::ptr::read_unaligned(cmsg_ptr as *const CMSGHDR) };
        assert!(
            unsafe {
                libc::memcmp(
                    &standard_hdr as *const _ as *const _,
                    &hdr as *const _ as *const _,
                    mem::size_of::<CMSGHDR>(),
                )
            } == 0
        );
    }
}
