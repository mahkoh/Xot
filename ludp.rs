use net::consts::{HANDSHAKE, SYNC, DATA};
use std::io::{MemWriter, MemReader, IoResult};
use utils;
use utils::ringbuffer::{XBuffer, RingBuffer};
use utils::{other_error, StructReader, StructWriter, FiniteReader};
use std::io::net::ip::{SocketAddr, Ipv4Addr, Ipv6Addr};
use std::mem::{transmute};
use std::{u64};
use std::rand::{task_rng, Rng};
use net::sockets::{UdpWriter};

static DEFAULT_QUEUE_LEN: uint = 4;
static MAX_QUEUE_LEN:     uint = 1024;
static MAX_DATA_SIZE:     uint = 1024;
static CON_TIMEOUT:       f64  = 5.0;

#[deriving(PartialEq)]
enum ConnectionStatus {
    NoConnection,
    HandshakeSending,
    NotConfirmed,
    Established,
    TimedOut,
}

struct Connection<'a> {
    ludp: &'a mut LosslessUDP,
    id: Option<uint>,
    addr: SocketAddr,
}

impl<'a> Connection<'a> {
    fn send_handshake(&mut self, id1: u32, id2: u32) -> IoResult<()> {
        let mut packet = MemWriter::new();
        try!(packet.write_u8(HANDSHAKE));
        try!(packet.write_be_u32(id1));
        try!(packet.write_be_u32(id2));

        self.ludp.udp.send_to(self.addr, packet.get_ref())
    }

    fn send_data(&mut self, data: &[u8], num: u32) -> IoResult<()> {
        let mut packet = MemWriter::new();
        try!(packet.write_u8(DATA));
        try!(packet.write_be_u32(num));
        try!(packet.write(data));

        self.ludp.udp.send_to(self.addr, data)
    }

    fn handle_sync1(&mut self, other_recv: u32, other_sent: u32) -> IoResult<()> {
        if self.gen_id() != other_recv {
            return utils::other_error();
        }
        //self.create();
        let raw = self.raw_mut();
        raw.other_recv      = other_recv;
        raw.sent            = other_recv;
        raw.other_sent      = other_sent;
        raw.recv            = other_sent;
        Ok(())
    }

    fn handle_sync2(&mut self, counter: u8, other_recv: u32,
                    other_sent: u32) -> IoResult<()> {
        if other_recv == self.raw().other_recv && other_sent == self.raw().other_sent {
            {
                let raw = self.raw_mut();
                raw.status        = Established;
                raw.recv_counter  = counter;
                raw.send_counter += 1;
            }
            self.send_sync()
        } else {
            utils::other_error()
        }
    }

    fn handle_sync3(&mut self, counter: u8, other_recv: u32, other_sent: u32,
                    mut data: MemReader) -> IoResult<()> {
        let raw = self.raw_mut();

        if other_recv < raw.other_recv || other_sent < raw.other_sent {
            return utils::other_error();
        }

        let cmp_counter = counter - raw.recv_counter;
        let cmp_other_recv = (other_recv - raw.other_recv) as uint;
        let cmp_other_sent = (other_sent - raw.other_sent) as uint;

        if cmp_other_recv > raw.send_buf.len() || cmp_other_sent > MAX_QUEUE_LEN
                || cmp_counter >= 8 {
            return utils::other_error();
        }

        raw.send_buf.consume((other_recv - raw.other_recv) as uint);
        raw.other_recv    = other_recv;
        raw.other_sent    = other_sent;
        raw.last_sync     = utils::time::milli();
        raw.recv_counter  = counter;
        raw.send_counter += 1;
        raw.req_packets   = try!(data.read_struct());

        Ok(())
    }

    fn enqueue(&mut self, data: &[u8]) {
    }

    fn gen_id(&mut self) -> u32 {
        self.ludp.gen_id(self.addr)
    }

    fn status(&self) -> ConnectionStatus {
        match self.id {
            Some(id) => self.raw().status,
            None => NoConnection,
        }
    }


    fn send_sync(&self) -> IoResult<()> {
        let raw = self.raw();
        let mut packet = MemWriter::new();
        try!(packet.write_u8(SYNC));
        try!(packet.write_u8(raw.send_counter));
        try!(packet.write_be_u32(raw.recv));
        try!(packet.write_be_u32(raw.sent));
        try!(packet.write_struct(&self.missing_packets()));

        self.ludp.udp.send_to(raw.addr, packet.get_ref())
    }

    fn missing_packets(&self) -> Vec<u32> {
        let raw = self.raw();
        let mut missing = Vec::new();
        for i in range(0, raw.recv_buf.cap()) {
            let num = raw.recv as uint + i + 1;
            if num > raw.other_sent as uint {
                break;
            }
            if !raw.recv_buf.has(i) {
                missing.push(num as u32);
            }
        }
        missing
    }

    fn handle_data(&mut self, mut data: MemReader) -> IoResult<()> {
        let raw = self.raw_mut();
        let num = try!(data.read_be_u32());
        if num <= raw.recv {
            return Ok(());
        }
        if data.remaining() > MAX_DATA_SIZE {
            return utils::other_error();
        }
        let pos = num - raw.recv - 1;
        if pos as uint > MAX_QUEUE_LEN {
            return Ok(());
        }
        if pos as uint >= raw.recv_buf.cap() {
            if !raw.confirmed {
                return utils::other_error();
            }
            raw.recv_buf.resize(2*pos as uint);
        }
        raw.last_recv = utils::time::milli();
        raw.recv_buf.set_pos(pos as uint, data);
        loop {
            match raw.recv_buf.pop() {
                Some(v) => {
                    raw.recv += 1;
                    // send to other channel
                },
                None => break,
            }
        }
        Ok(())
    }

    fn set_confirmed(&mut self) {
        let mut raw = self.raw_mut();
        raw.killat = u64::MAX;
        raw.inbound = false;
        raw.confirmed = true;
    }

    fn set_timeout(&mut self, sec: u64) {
        self.raw_mut().killat = utils::time::micro() + 1_000_000 * sec;
    }

    fn raw<'b>(&'b self) -> &'b RawConnection {
        self.ludp.cons.get(self.id.unwrap()).as_ref().unwrap()
    }

    fn raw_mut<'b>(&'b mut self) -> &'b mut RawConnection {
        self.ludp.cons.get_mut(self.id.unwrap()).as_mut().unwrap()
    }
}

struct RawConnection {
    addr:         SocketAddr,
    recv:         u32,
    sent:         u32,
    handshake1:   u32,
    other_recv:   u32,
    other_sent:   u32,
    inbound:      bool,
    confirmed:    bool,
    timeout:      u64,
    killat:       u64,
    last_recv:    u64,
    last_sync:    u64,
    send_counter: u8,
    recv_counter: u8,
    status:       ConnectionStatus,
    recv_buf:     XBuffer<MemReader>,
    send_buf:     RingBuffer<Vec<u8>>,
    req_packets:  Vec<u32>,
}

struct LosslessUDP {
    randtable: [[u32, ..256], ..18],
    cons:      Vec<Option<RawConnection>>,
    udp:       UdpWriter,
}

impl<'a> LosslessUDP {
    fn new_connection(&'a mut self, addr: SocketAddr) -> Connection<'a> {
        let mut raw = RawConnection {
            addr:         addr,
            recv:         0,
            sent:         0,
            other_recv:   0,
            other_sent:   0,
            send_counter: 0,
            recv_counter: 0,
            handshake1:   self.gen_id(addr),
            inbound:      false,
            confirmed:    true,
            timeout:      (task_rng().gen_range(1.0, 2.0) * CON_TIMEOUT) as u64,
            last_recv:    0,
            last_sync:    utils::time::micro(),
            killat:       u64::MAX,
            status:       HandshakeSending,
            recv_buf:     XBuffer::new(DEFAULT_QUEUE_LEN),
            send_buf:     RingBuffer::new(DEFAULT_QUEUE_LEN),
            req_packets:  Vec::new(),
        };
        raw.sent = raw.handshake1;
        let mut id = None;
        for i in range(0, self.cons.len()) {
            if self.cons.get(i).is_none() {
                id = Some(i);
                break;
            }
        }
        id = match id {
            Some(i) => {
                *self.cons.get_mut(i) = Some(raw);
                id
            },
            None => {
                self.cons.push(Some(raw));
                Some(self.cons.len()-1)
            }
        };
        Connection { ludp: self, id: id, addr: addr }
    }

    fn gen_id(&mut self, addr: SocketAddr) -> u32 {
        let mut id = 0u32;
        let mut i = 0u;

        let port: [u8, ..2] = unsafe { transmute(addr.port.to_be()) };
        id ^= self.rand_get(&mut i, port[0]);
        id ^= self.rand_get(&mut i, port[1]);
        match addr.ip {
            Ipv4Addr(a, b, c, d) => {
                id ^= self.rand_get(&mut i, a);
                id ^= self.rand_get(&mut i, b);
                id ^= self.rand_get(&mut i, c);
                id ^= self.rand_get(&mut i, d);
            },
            Ipv6Addr(a, b, c, d, e, f, g, h) => {
                let x = [a.to_be(), b.to_be(), c.to_be(), d.to_be(),
                         e.to_be(), f.to_be(), g.to_be(), h.to_be()];
                let x: [u8, ..16] = unsafe { transmute(x) };
                for v in x.iter() {
                    id ^= self.rand_get(&mut i, *v);
                }
            },
        }
        match id {
            0 => 1,
            _ => id,
        }
    }
    
    fn get_con(&'a mut self, addr: SocketAddr) -> Connection<'a> {
        let cap = self.cons.len();
        for i in range(0, cap) {
            let found = match self.cons.get(i).as_ref() {
                Some(con) => con.addr == addr,
                None => false,
            };
            if found {
                return Connection { ludp: self, id: Some(i), addr: addr };
            }
        }
        Connection { ludp: self, id: None, addr: addr }
    }

    fn rand_get(&mut self, index: &mut uint, value: u8) -> u32 {
        if self.randtable[*index][value as uint] == 0 {
            self.randtable[*index][value as uint] = task_rng().next_u32();
        }
        *index = *index + 1;
        self.randtable[*index - 1][value as uint]
    }

    fn handle_handshake(&mut self, addr: SocketAddr,
                        mut data: MemReader) -> IoResult<()> {
        let id1 = try!(data.read_be_u32());
        let id2 = try!(data.read_be_u32());

        let mut con = self.get_con(addr);

        if id2 == 0 && con.status() != Established && con.status() != TimedOut {
            let hid = con.gen_id();
            return con.send_handshake(hid, id1)
        }

        if con.status() != HandshakeSending {
            return utils::other_error();
        }

        let raw = con.raw_mut();
        if id2 == raw.handshake1 {
            raw.status     = NotConfirmed;
            raw.other_recv = id2;
            raw.other_sent = id1;
            raw.recv       = id1;
        }

        Ok(())
    }

    fn handle_sync(&mut self, addr: SocketAddr, mut data: MemReader) -> IoResult<()> {
        let counter = try!(data.read_u8());
        let other_recv = try!(data.read_be_u32());
        let other_sent = try!(data.read_be_u32());

        let mut con = self.get_con(addr);
        match con.status() {
            NoConnection => con.handle_sync1(other_recv, other_sent),
            NotConfirmed => con.handle_sync2(counter, other_recv, other_sent),
            Established  => con.handle_sync3(counter, other_recv, other_sent, data),
            _ => Ok(())
        }
    }

    fn handle_data(&mut self, addr: SocketAddr, mut data: MemReader) -> IoResult<()> {
        let mut con = self.get_con(addr);
        if con.status() != Established {
            return utils::other_error();
        };
        con.handle_data(data)
    }
}

pub struct LudpControl;

impl LudpControl {
    pub fn kill(&self, addr: SocketAddr) {
        unreachable!();
    }
}
