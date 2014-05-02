use std::io::net::ip::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::io::{MemReader, IoResult, standard_error, OtherIoError};
use utils::{Writable, Readable};
use libc::{AF_INET, AF_INET6};
use sockets::{UdpWriter, UdpReader};

mod sockets;

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
