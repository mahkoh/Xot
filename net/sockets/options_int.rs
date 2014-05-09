use libc::{c_int, c_void, socklen_t};
use libc::{SOL_SOCKET, SO_BROADCAST, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP};

use std::mem;
use std::cast::{transmute};

use self::options::structs::*;

static SO_RCVBUF: c_int = 8;
static SO_SNDBUF: c_int = 7;

pub mod options {
    use super::*;
    use libc::{c_int};

    pub mod structs {
        use libc::{in6_addr, c_uint};

        pub struct Ipv6Mreq{
            pub multi_addr: in6_addr,
            pub interface: c_uint,
        }
    }

    pub enum SocketOption {
        SolSocket(SolSocketOption),
        IpProtoIpv6(IpProtoIpv6Option),
    }

    pub enum SolSocketOption {
        Rcvbuf(uint),
        Sndbuf(uint),
        Broadcast(bool),
    }

    pub enum IpProtoIpv6Option {
        AddMembership(structs::Ipv6Mreq),
    }

    impl SocketOption {
        pub fn raw<'a>(&'a self) -> RawSocketOption<'a> {
            match self {
                &SolSocket(ref opt) => RawSolSocket(opt.raw()),
                &IpProtoIpv6(ref opt) => RawIpProtoIpv6(opt.raw()),
            }
        }
    }

    impl SolSocketOption {
        pub fn raw<'a>(&'a self) -> RawSolSocketOption<'a> {
            match self {
                &Rcvbuf(n)    => RawRcvbuf(n    as c_int),
                &Sndbuf(n)    => RawSndbuf(n    as c_int),
                &Broadcast(b) => RawBroadcast(b as c_int),
            }
        }
    }

    impl<'a> IpProtoIpv6Option {
        pub fn raw<'a>(&'a self) -> RawIpProtoIpv6Option<'a> {
            match self {
                &AddMembership(ref b) => RawAddMembership(b),
            }
        }
    }
}


pub enum RawSocketOption<'a> {
    RawSolSocket(RawSolSocketOption<'a>),
    RawIpProtoIpv6(RawIpProtoIpv6Option<'a>),
}

pub enum RawSolSocketOption<'a> {
    RawRcvbuf(c_int),
    RawSndbuf(c_int),
    RawBroadcast(c_int),
}

pub enum RawIpProtoIpv6Option<'a> {
    RawAddMembership(&'a Ipv6Mreq),
}

impl<'a> RawSocketOption<'a> {
    pub fn level(&self) -> c_int {
        match self {
            &RawSolSocket(..)   => SOL_SOCKET,
            &RawIpProtoIpv6(..) => IPPROTO_IPV6,
        }
    }

    pub fn name(&self) -> c_int {
        match self {
            &RawSolSocket(ref opt)   => opt.name(),
            &RawIpProtoIpv6(ref opt) => opt.name(),
        }
    }

    pub unsafe fn raw(&'a self) -> &'a c_void {
        match self {
            &RawSolSocket(ref opt)   => opt.raw(),
            &RawIpProtoIpv6(ref opt) => opt.raw(),
        }
    }

    pub fn size(&self) -> socklen_t {
        match self {
            &RawSolSocket(ref opt)   => opt.size(),
            &RawIpProtoIpv6(ref opt) => opt.size(),
        }
    }
}

impl<'a> RawSolSocketOption<'a> {
    fn name(&self) -> c_int {
        match self {
            &RawRcvbuf(..)    => SO_RCVBUF,
            &RawSndbuf(..)    => SO_SNDBUF,
            &RawBroadcast(..) => SO_BROADCAST,
        }
    }

    unsafe fn raw(&'a self) -> &'a c_void {
        match self {
            &RawRcvbuf(ref n)    => transmute::<&c_int, &c_void>(n),
            &RawSndbuf(ref n)    => transmute::<&c_int, &c_void>(n),
            &RawBroadcast(ref n) => transmute::<&c_int, &c_void>(n),
        }
    }

    fn size(&self) -> socklen_t {
        match self {
            &RawRcvbuf(x)    => mem::size_of_val::<c_int>(&x) as socklen_t,
            &RawSndbuf(x)    => mem::size_of_val::<c_int>(&x) as socklen_t,
            &RawBroadcast(x) => mem::size_of_val::<c_int>(&x) as socklen_t,
        }
    }
}

impl<'a> RawIpProtoIpv6Option<'a> {
    fn name(&self) -> c_int {
        match self {
            &RawAddMembership(..) => IPV6_ADD_MEMBERSHIP,
        }
    }

    unsafe fn raw(&'a self) -> &'a c_void {
        match self {
            &RawAddMembership(x) => transmute::<&Ipv6Mreq, &c_void>(x),
        }
    }

    fn size(&self) -> socklen_t {
        match self {
            &RawAddMembership(x) => mem::size_of_val::<Ipv6Mreq>(x) as socklen_t,
        }
    }
}
