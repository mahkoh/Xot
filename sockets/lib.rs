#![crate_id="sockets"]
#![crate_type="lib"]
#![feature(globs)]
#![allow(visible_private_types)]

extern crate native;
extern crate libc;
extern crate sync;

use std::comm::Messages;
use std::mem;
use std::mem::{size_of, to_be16, from_be16};
use std::cast::{transmute};
use std::io::net::ip::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::io::{IoResult, IoError};
use sync::Arc;

use libc::{c_int, c_void, socklen_t, sockaddr_storage, sockaddr_in, sockaddr_in6,
           sa_family_t, sockaddr, size_t};
use libc::{socket, setsockopt, fcntl, close, bind, sendto, recvfrom, shutdown};
use libc::{SOCK_DGRAM, SOCK_STREAM, AF_INET, AF_INET6, IPPROTO_TCP};
use libc::consts::os::bsd44::{SHUT_RD};

use native::io::net::{sock_t};

use select::FdSet;

pub use options_int::options;
use options::{SocketOption};

pub mod select;
mod options_int;

pub mod consts {
    use libc::c_int;

    pub static IPPROTO_UDP: c_int = 17;
    pub static F_SETFL:     c_int = 4;
    pub static O_NONBLOCK:  c_int = 0o4000;
}

pub enum IpFamily {
    Ipv4,
    Ipv6,
}

impl IpFamily {
    fn to_c_int(&self) -> c_int {
        match *self {
            Ipv4 => AF_INET,
            Ipv6 => AF_INET6,
        }
    }

    pub fn is_ipv6(&self) -> bool {
        match *self {
            Ipv4 => false,
            Ipv6 => true,
        }
    }

    pub fn from_addr(addr: SocketAddr) -> IpFamily {
        match addr.ip {
            Ipv4Addr(..) => Ipv4,
            _ => Ipv6,
        }
    }
}

enum SockAddr {
    SockAddr4(sockaddr_storage),
    SockAddr6(sockaddr_storage),
}

impl<'a> SockAddr {
    fn new(addr: SocketAddr) -> SockAddr {
        match addr.ip {
            Ipv4Addr(a, b, c, d) => unsafe {
                let mut storage: sockaddr_storage = mem::uninit();
                let addr4: &mut sockaddr_in = transmute(&mut storage);
                addr4.sin_family = AF_INET as sa_family_t;
                addr4.sin_port = to_be16(addr.port);
                addr4.sin_addr = transmute([a,b,c,d]);
                SockAddr4(storage)
            },
            Ipv6Addr(a, b, c, d, e, f, g, h) => unsafe {
                let mut storage: sockaddr_storage = mem::uninit();
                let addr6: &mut sockaddr_in6 = transmute(&mut storage);
                addr6.sin6_family = AF_INET6 as sa_family_t;
                addr6.sin6_port = to_be16(addr.port);
                // is this the right order?
                addr6.sin6_addr = transmute([a,b,c,d,e,f,g,h]);
                addr6.sin6_flowinfo = 0;
                addr6.sin6_scope_id = 0;
                SockAddr6(storage)
            },
        }
    }

    fn parse(s: sockaddr_storage) -> Option<SockAddr> {
        match s.ss_family as c_int {
            AF_INET => Some(SockAddr4(s)),
            AF_INET6 => Some(SockAddr6(s)),
            _ => None,
        }
    }

    fn to_socket_addr(&self) -> SocketAddr {
        match self {
            &SockAddr4(ref s) => unsafe {
                let addr4: &sockaddr_in = transmute(s);
                let ip: [u8, ..4] = transmute(addr4.sin_addr);
                let ip = Ipv4Addr(ip[0],ip[1],ip[2],ip[3]);
                SocketAddr { ip: ip, port: from_be16(addr4.sin_port) }
            },
            &SockAddr6(ref s) => unsafe {
                let addr6: &sockaddr_in6 = transmute(s);
                let ip: [u16, ..8] = transmute(addr6.sin6_addr);
                let ip = Ipv6Addr(from_be16(ip[0]),from_be16(ip[1]),from_be16(ip[2]),
                                  from_be16(ip[3]),from_be16(ip[4]),from_be16(ip[5]),
                                  from_be16(ip[6]),from_be16(ip[7]));
                SocketAddr { ip: ip, port: from_be16(addr6.sin6_port) }
            },
        }
    }

    fn raw(&'a self) -> &'a sockaddr_storage {
        match self {
            &SockAddr4(ref storage) => storage,
            &SockAddr6(ref storage) => storage,
        }
    }

    fn size(&self) -> uint {
        match self {
            &SockAddr4(..) => mem::size_of::<sockaddr_in>(),
            &SockAddr6(..) => mem::size_of::<sockaddr_in6>(),
        }
    }
}

enum SocketType {
    UDP,
    TCP,
}

impl SocketType {
    fn kind(self) -> c_int {
        match self {
            UDP => SOCK_DGRAM,
            TCP => SOCK_STREAM,
        }
    }
    fn protocol(self) -> c_int {
        match self {
            UDP => consts::IPPROTO_UDP,
            TCP => IPPROTO_TCP,
        }
    }
}

struct PlainSocket(sock_t);

impl PlainSocket {
    fn new(family: IpFamily, kind: SocketType) -> IoResult<PlainSocket> {
        match unsafe { socket(family.to_c_int(), kind.kind(), kind.protocol()) } {
            -1   => Err(IoError::last_error()),
            sock => Ok(PlainSocket(sock)),
        }
    }

    unsafe fn raw(&self) -> sock_t {
        let &PlainSocket(sock) = self;
        sock
    }

    fn set_opt(&mut self, opt: &SocketOption) -> IoResult<()> {
        let &PlainSocket(sock) = self;
        let raw = opt.raw();
        let rv = unsafe {
            setsockopt(sock, raw.level(), raw.name(), raw.raw() as *c_void, raw.size())
        };
        match rv {
            0 => Ok(()),
            _ => Err(IoError::last_error()),
        }
    }

    fn set_non_blocking(&mut self) -> IoResult<()> {
        let &PlainSocket(sock) = self;
        match unsafe { fcntl(sock, consts::F_SETFL, consts::O_NONBLOCK, 1 as c_int) } {
            -1 => Err(IoError::last_error()),
            _ => Ok(()),
        }
    }

    fn bind(&mut self, addr: &SockAddr) -> IoResult<()> {
        unsafe {
            let &PlainSocket(sock) = self;
            let size = addr.size() as socklen_t;
            let storage = addr.raw();
            match bind(sock, storage as *_ as *sockaddr, size) {
                0 => Ok(()),
                _ => Err(IoError::last_error()),
            }
        }
    }
}

impl Drop for PlainSocket {
    fn drop(&mut self) {
        let &PlainSocket(s) = self;
        println!("closing socket");
        unsafe { close(s); }
    }
}

/// A UdpSocket.
pub struct UdpSocket {
    sock: PlainSocket,
}

impl UdpSocket {
    /// Create a new `UdpSocket` with family `family`.
    pub fn new(family: IpFamily) -> IoResult<UdpSocket> {
        let s = try!(PlainSocket::new(family, UDP));
        Ok(UdpSocket { sock: s })
    }

    /// Name the socket.
    pub fn bind(&mut self, addr: SocketAddr) -> IoResult<()> {
        self.sock.bind(&SockAddr::new(addr))
    }

    /// Set the socket to non-blocking.
    pub fn set_non_blocking(&mut self) -> IoResult<()> {
        self.sock.set_non_blocking()
    }

    /// Set an option on the socket.
    pub fn set_opt(&mut self, opt: &SocketOption) -> IoResult<()> {
        self.sock.set_opt(opt)
    }

    /// Start the background thread that reads messages and split the socket into reader
    /// and writer parts.
    pub fn start(self) -> (UdpWriter, UdpReader) {
        let (sender, receiver) = channel();

        let raw = unsafe { self.sock.raw() };
        native::task::spawn(proc() {
            let _ = sender;
            let mut buf = [0u8, ..(1<<16)];
            let mut addr: sockaddr_storage = unsafe { mem::uninit() };
            loop {
                let mut s = FdSet::zero();
                s.set(raw);
                if s.read().is_err() {
                    break;
                }
                let mut len = mem::size_of_val(&addr) as socklen_t;
                let rv = unsafe {
                    recvfrom(raw, buf.as_mut_ptr() as *mut c_void, buf.len() as size_t, 0,
                             &mut addr as *mut _ as *mut sockaddr,
                             &mut len as *mut socklen_t)
                };
                if rv < 0 {
                    break;
                } else if rv as uint >= buf.len() {
                    continue;
                }
                let addr = match SockAddr::parse(addr) {
                    Some(addr) => addr.to_socket_addr(),
                    None => continue,
                };
                sender.send((addr, Vec::from_slice(buf.slice_to(rv as uint))));
            }
        });

        let sock = Arc::new(self.sock);
        ( UdpWriter { sock: sock.clone() },
          UdpReader { sock: sock.clone(), output: receiver })
    }
}

/// The half of a UdpSocket that can be used to read messages.
pub struct UdpReader {
    sock: Arc<PlainSocket>,
    output: Receiver<(SocketAddr, Vec<u8>)>,
}

impl UdpReader {
    /// Get the underlying `Receiver`.
    pub fn out<'a>(&'a mut self) -> &'a Receiver<(SocketAddr, Vec<u8>)> {
        &self.output
    }

    /// Iterate over messages from the socket.
    pub fn iter<'a>(&'a mut self) -> Messages<'a, (SocketAddr, Vec<u8>)> {
        self.output.iter()
    }
}

impl Drop for UdpReader {
    fn drop(&mut self) {
        unsafe {
            shutdown(self.sock.raw(), SHUT_RD);
        }
    }
}

/// A `UdpWriter` is the half of a `UdpSocket` that can be used to write message.
pub struct UdpWriter {
    sock: Arc<PlainSocket>,
}

impl UdpWriter {
    /// Write `data` to `ipp`.
    pub fn send_to(&self, ipp: SocketAddr, data: &[u8]) -> IoResult<()> {
        let addr = SockAddr::new(ipp);
        let rv = unsafe {
            sendto(self.sock.raw(), data.as_ptr() as *_, data.len() as size_t, 0,
                   addr.raw() as *_ as *_, addr.size() as socklen_t)
        };
        match rv >= 0 && rv as u64 == data.len() as u64 {
            true => Ok(()),
            _    => Err(IoError::last_error())
        }
    }
}

#[test]
fn test_udp() {
    use options::{Broadcast, Rcvbuf, Sndbuf, SolSocket};

    let mut sock = UdpSocket::new(Ipv4).unwrap();

    sock.set_opt(&SolSocket(Broadcast(true))).unwrap();
    sock.set_opt(&SolSocket(Rcvbuf(1024*1024))).unwrap();
    sock.set_opt(&SolSocket(Sndbuf(1024*1024))).unwrap();

    let addr = SocketAddr { ip: Ipv4Addr(0,0,0,0), port: 8755 };
    sock.bind(addr).unwrap();

    let (mut writer, mut reader) = sock.start();
    for (addr, out) in reader.iter() {
        writer.send_to(addr, out.as_slice()).unwrap();
        writer.send_to(addr, "Y-you too\n".as_bytes()).unwrap();
    }
}
