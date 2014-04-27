use std::io::net::ip::{SocketAddr};
use std::io::{standard_error, OtherIoError, IoResult};
use std::{mem};
use sockets::{UdpSocket, IpFamily};
use sockets::options::{SolSocket, Rcvbuf, Sndbuf, Broadcast, IpProtoIpv6, AddMembership};
use sockets::options::structs::{Ipv6Mreq};

static PORTRANGE_FROM: u16 = 33445;
static PORTRANGE_TO:   u16 = 33545;

pub fn new(mut ipp: SocketAddr) -> IoResult<UdpSocket> {
    let family = IpFamily::from_addr(ipp);
    let mut sock = try!(UdpSocket::new(family));

    try!(sock.set_opt(&SolSocket(Rcvbuf(1024*1024*2))));
    try!(sock.set_opt(&SolSocket(Sndbuf(1024*1024*2))));
    try!(sock.set_opt(&SolSocket(Broadcast(true))));
    try!(sock.set_non_blocking());

    if family.is_ipv6() {
        let mut mreq: Ipv6Mreq = unsafe { mem::init() };
        mreq.multi_addr.s6_addr[ 0] = 0xFF;
        mreq.multi_addr.s6_addr[ 1] = 0x02;
        mreq.multi_addr.s6_addr[15] = 0x01;
        try!(sock.set_opt(&IpProtoIpv6(AddMembership(mreq))));
    }

    let mut port = ipp.port;
    if port < PORTRANGE_FROM || PORTRANGE_TO <= port {
        port = PORTRANGE_FROM;
    }
    for p in range(port, PORTRANGE_TO).chain(range(PORTRANGE_FROM, port)) {
        ipp.port = p;
        if sock.bind(ipp).is_ok() {
            return Ok(sock);
        }
    }
    return Err(standard_error(OtherIoError));
}
