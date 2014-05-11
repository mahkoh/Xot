use std::io::net::ip::{Ipv4Addr, Ipv6Addr, SocketAddr, IpAddr};
use std::io::{MemReader, IoResult, standard_error, OtherIoError, EndOfFile};
use utils::{Writable, Readable, StructReader, StructWriter, other_error};
use utils::bufreader::{BufReader};
use libc::{AF_INET, AF_INET6, c_int};
use net::sockets::{UdpWriter, UdpReader};
use crypt::{Key};
use std::{mem};
use std::mem::{to_be16, from_be16};
use std::cast::{transmute};

pub mod sockets;

pub struct Node {
    pub id: Key,
    pub addr: SocketAddr,
}

impl Node {
    pub fn new() -> Node {
        unsafe { mem::init() }
    }

    pub fn parse4(data: &[u8]) -> IoResult<Vec<Node>> {
        let mut data = BufReader::new(data);
        let mut nodes = Vec::new();
        while !data.eof() {
            let id: Key = try!(data.read_struct());
            let a = try!(data.read_u8());
            let b = try!(data.read_u8());
            let c = try!(data.read_u8());
            let d = try!(data.read_u8());
            let port = try!(data.read_be_u16());
            data.consume(2);
            let ip = Ipv4Addr(a, b, c, d);
            let addr = SocketAddr { ip: ip, port: port };
            let node = Node { id: id, addr: addr };
            nodes.push(node);
        }
        Ok(nodes)
    }

    pub fn parse(data: &[u8]) -> IoResult<Vec<Node>> {
        let mut data = BufReader::new(data);
        let mut nodes = Vec::new();
        while !data.eof() {
            let id: Key = try!(data.read_struct());
            let addr: SocketAddr = try!(data.read_struct());
            let node = Node { id: id, addr: addr };
            nodes.push(node);
        }
        Ok(nodes)
    }

    pub fn family(&self) -> IpFamily {
        IpFamily::from_addr(self.addr)
    }
}

impl Writable for Node {
    fn write_to(&self, w: &mut Writer) -> IoResult<()> {
        try!(self.id.write_to(w));
        self.addr.write_to(w)
    }
}

impl Writable for Vec<Node> {
    fn write_to(&self, w: &mut Writer) -> IoResult<()> {
        for node in self.iter() {
            try!(node.write_to(w));
        }
        Ok(())
    }
}

impl Readable for Node {
    fn read_from(r: &mut Reader) -> IoResult<Node> {
        let id: Key = try!(Readable::read_from(r));
        let addr: SocketAddr = try!(Readable::read_from(r));
        Ok(Node { id: id, addr: addr })
    }
}

impl Readable for Vec<Node> {
    fn read_from(r: &mut Reader) -> IoResult<Vec<Node>> {
        let mut nodes = Vec::new();
        loop {
            let node: Node = match Readable::read_from(r) {
                Ok(n) => n,
                Err(e) => match e.kind {
                    EndOfFile => break,
                    _ => return other_error(),
                },
            };
            nodes.push(node);
        }
        Ok(nodes)
    }
}

struct Ipv4Nodes<'a> {
    nodes: &'a Vec<Node>
}

impl<'a> Writable for Ipv4Nodes<'a> {
    fn write_to(&self, w: &mut Writer) -> IoResult<()> {
        for node in self.nodes.iter() {
            match node.addr.ip {
                Ipv4Addr(a, b, c, d) => {
                    try!(node.id.write_to(w));
                    try!(w.write_u8(a));
                    try!(w.write_u8(b));
                    try!(w.write_u8(c));
                    try!(w.write_u8(d));
                    try!(w.write_be_u16(node.addr.port));
                    try!(w.write([0u8, 0u8]));
                },
                _ => { }
            }
        }
        Ok(())
    }
}

struct Ipv6Nodes<'a> {
    nodes: &'a Vec<Node>
}

impl<'a> Writable for Ipv6Nodes<'a> {
    fn write_to(&self, w: &mut Writer) -> IoResult<()> {
        for node in self.nodes.iter() {
            match node.addr.ip {
                Ipv6Addr(..) => try!(node.write_to(w)),
                _ => { }
            }
        }
        Ok(())
    }
}

pub trait ToIpvNNodes {
    fn ipv4<'a>(&'a self) -> Ipv4Nodes<'a>;
    fn ipv6<'a>(&'a self) -> Ipv6Nodes<'a>;
}

impl ToIpvNNodes for Vec<Node> {
    fn ipv4<'a>(&'a self) -> Ipv4Nodes<'a> {
        Ipv4Nodes { nodes: self }
    }
    fn ipv6<'a>(&'a self) -> Ipv6Nodes<'a> {
        Ipv6Nodes { nodes: self }
    }
}

pub trait IpAddrInfo {
    fn is_lan(self) -> bool;
    fn is_ipv4(self) -> bool;
    fn is_zero(self) -> bool;
    fn is_broadcast(self) -> bool;
}

impl IpAddrInfo for IpAddr {
    fn is_lan(self) -> bool {
        match self {
            Ipv4Addr(a, b, c, d) => {
                match a {
                    127 | 10 => true,
                    172      => 16 <= b && b <= 31,
                    192      => b == 168,
                    169      => b == 254 && 0 < c && c < 255,
                    100      => b & 0xC0 == 0x40,
                    _        => false
                }
            },
            Ipv6Addr(a, b, c, d, e, f, g, h) => {
                let x: [u8, ..16] = unsafe {
                    let arr = [to_be16(a), to_be16(b), to_be16(c), to_be16(d),
                               to_be16(e), to_be16(f), to_be16(g), to_be16(h)];
                    transmute(arr)
                };
                if x[0] == 0xFF && x[1] < 3 && x[15] == 1 {
                    return true;
                }
                if x[0] == 0xFE && x[1] & 0xC0 == 0x80 {
                    return true;
                }
                if self.is_ipv4() {
                    return Ipv4Addr(x[12], x[13], x[14], x[15]).is_lan()
                }
                a == 0 && b == 0 && c == 0 && d == 0 && e == 0 && f == 0 && g == 0 &&
                    x[14] == 0 && x[15] == 1
            },
        }
    }

    fn is_ipv4(self) -> bool {
        match self {
            Ipv4Addr(..) => true,
            Ipv6Addr(a, b, c, d, e, f, _, _) =>
                a == 0 && b == 0 && c == 0 && d == 0 && e == 0 && f == 0xFFFF,
        }
    }

    fn is_zero(self) -> bool {
        match self {
            Ipv4Addr(a, b, c, d) => a == 0 && b == 0 && c == 0 && d == 0,
            Ipv6Addr(a, b, c, d, e, f, g, h) =>
                a == 0 && b == 0 && c == 0 && d == 0 && e == 0 && f == 0 && h == 0,
        }
    }

    fn is_broadcast(self) -> bool {
        // TODO this is most likely wrong
        match self {
            Ipv4Addr(a, b, c, d) => a == 255 && b == 255 && c == 255 && d == 255,
            Ipv6Addr(a, b, c, d, e, f, g, h) =>
                // all nodes multicast
                a == from_be16(0xFF02) && b == 0 && c == 0 && d == 0 && e == 0 &&
                    f == 0 && g == 0 && h == from_be16(0x0001),
        }
    }
}

#[deriving(Clone)]
pub enum IpFamily {
    IPv4,
    IPv6,
}

impl IpFamily {
    fn to_c_int(&self) -> c_int {
        match *self {
            IPv4 => AF_INET,
            IPv6 => AF_INET6,
        }
    }

    pub fn is_ipv6(&self) -> bool {
        match *self {
            IPv4 => false,
            IPv6 => true,
        }
    }

    pub fn from_addr(addr: SocketAddr) -> IpFamily {
        match addr.ip {
            Ipv4Addr(..) => IPv4,
            _ => IPv6,
        }
    }
}

impl Writable for SocketAddr {
    fn write_to(&self, writer: &mut Writer) -> IoResult<()> {
        match self.ip {
            Ipv4Addr(a, b, c, d) => {
                try!(writer.write_u8(AF_INET as u8))
                try!(writer.write([0u8, ..3]))
                try!(writer.write_u8(a))
                try!(writer.write_u8(b))
                try!(writer.write_u8(c))
                try!(writer.write_u8(d))
                try!(writer.write([0u8, ..12]))
            },
            Ipv6Addr(a, b, c, d, e, f, g, h) => {
                try!(writer.write_u8(AF_INET6 as u8))
                try!(writer.write([0u8, ..3]))
                // TODO: libtox probably uses host byte order by accident
                try!(writer.write_be_u16(a))
                try!(writer.write_be_u16(b))
                try!(writer.write_be_u16(c))
                try!(writer.write_be_u16(d))
                try!(writer.write_be_u16(e))
                try!(writer.write_be_u16(f))
                try!(writer.write_be_u16(g))
                try!(writer.write_be_u16(h))
            },
        }
        try!(writer.write_be_u16(self.port))
        writer.write([0u8, ..2])
    }
}

impl Readable for SocketAddr {
    fn read_from(reader: &mut Reader) -> IoResult<SocketAddr> {
        let kind = try!(reader.read_u8());
        try!(reader.read_exact(3));
        let ip = match kind as i32 {
            AF_INET => {
                let a = try!(reader.read_u8());
                let b = try!(reader.read_u8());
                let c = try!(reader.read_u8());
                let d = try!(reader.read_u8());
                try!(reader.read_exact(12));
                Ipv4Addr(a, b, c, d)
            },
            AF_INET6 => {
                let a = try!(reader.read_be_u16());
                let b = try!(reader.read_be_u16());
                let c = try!(reader.read_be_u16());
                let d = try!(reader.read_be_u16());
                let e = try!(reader.read_be_u16());
                let f = try!(reader.read_be_u16());
                let g = try!(reader.read_be_u16());
                let h = try!(reader.read_be_u16());
                Ipv6Addr(a, b, c, d, e, f, g, h)
            },
            _ => return Err(standard_error(OtherIoError))
        };
        let port = try!(reader.read_be_u16());
        try!(reader.read_exact(2));
        Ok(SocketAddr { ip: ip, port: port })
    }
}

struct Network;


pub mod consts {
    pub static PING_REQUEST:        u8 = 0;
    pub static PING_RESPONSE:       u8 = 1;
    pub static GET_NODES:           u8 = 2;
    pub static SEND_NODES4:         u8 = 3;
    pub static SEND_NODES6:         u8 = 4;
    pub static HANDSHAKE:           u8 = 16;
    pub static SYNC:                u8 = 17;
    pub static DATA:                u8 = 18;
    pub static CRYPTO:              u8 = 32;
    pub static GROUP:               u8 = 48;
    pub static ONION_SEND_LEVEL0:   u8 = 128;
    pub static ONION_SEND_LEVEL1:   u8 = 129;
    pub static ONION_SEND_LEVEL2:   u8 = 130;
    pub static ANNOUNCE_REQUEST:    u8 = 131;
    pub static ONION_DATA_REQUEST:  u8 = 133;
    pub static ONION_RECV_LEVEL2:   u8 = 140;
    pub static ONION_RECV_LEVEL1:   u8 = 141;
    pub static ONION_RECV_LEVEL0:   u8 = 142;
    pub static ANNOUNCE_RESPONSE:   u8 = 132;
    pub static ONION_DATA_RESPONSE: u8 = 134;
}

pub type LLRcv = Receiver<(SocketAddr, MemReader)>;
pub type LLSnd = Sender<(SocketAddr, MemReader)>;

struct LowLevelHandler {
    sender: UdpWriter,
    receiver: UdpReader,
}

impl LowLevelHandler {
    fn handle(&mut self) {
        for (src, msg) in self.receiver.iter() {
            use self::consts::*;

            let mut msg = MemReader::new(msg);
            let id = match msg.read_u8() {
                Ok(id) => id,
                Err(_) => continue,
            };
            /*
            let _ = match id {
                PING_REQUEST        => self.ping_request(src, msg),
                PING_RESPONSE       => self.ping_response(src, msg),
                GET_NODES           => self.get_nodes(src, msg),
                SEND_NODES4         => self.send_nodes4(src, msg),
                SEND_NODES6         => self.send_nodes6(src, msg),
                HANDSHAKE           => self.handshake(src, msg),
                SYNC                => self.sync(src, msg),
                DATA                => self.data(src, msg),
                CRYPTO              => self.crypto(src, msg),
                ONION_SEND_LEVEL0   => self.onion_send_level0(src, msg),
                ONION_SEND_LEVEL1   => self.onion_send_level1(src, msg),
                ONION_SEND_LEVEL2   => self.onion_send_level2(src, msg),
                ANNOUNCE_REQUEST    => self.announce_request(src, msg),
                ONION_DATA_REQUEST  => self.onion_data_request(src, msg),
                ONION_RECV_LEVEL2   => self.onion_recv_level1(src, msg),
                ONION_RECV_LEVEL1   => self.onion_recv_level1(src, msg),
                ONION_RECV_LEVEL0   => self.onion_recv_level0(src, msg),
                ANNOUNCE_RESPONSE   => self.announce_response(src, msg),
                ONION_DATA_RESPONSE => self.onion_data_response(src, msg),
                _ => continue,
            };
            */
        }
    }

}
