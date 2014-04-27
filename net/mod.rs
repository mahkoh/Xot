use std::io::net::ip::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::io::{IoResult, standard_error, OtherIoError};
use utils::{Writable, Readable};
use libc::{AF_INET, AF_INET6};

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

