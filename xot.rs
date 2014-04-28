extern crate time;

use std::fmt;
use std::from_str::{FromStr};
use time::Tm;
use std::io::{IoResult, MemReader, MemWriter, standard_error, OtherIoError};
use std::io::net::ip::{SocketAddr};
use crypt::{Nonce, Key};
use utils::{other_error};

mod crypt;

static MAX_NAME_LENGTH:           uint = 128;
static MAX_MESSAGE_LENGTH:        uint = 1003;
static MAX_STATUS_MESSAGE_LENGTH: uint = 1007;

static PORT_MIN:     uint = 33445;
static PORT_MAX:     uint = 33545;
static PORT_DEFAULT: uint = PORT_MIN;

pub type ClientId = Key;

impl fmt::Show for ClientId {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        let my = self.raw();
        for &n in my.iter() {
            try!(fmt.buf.write_str(format!("{:x}", n)));
        }
        Ok(())
    }
}

impl FromStr for ClientId {
    fn from_str(s: &str) -> Option<ClientId> {
        let mut buf = [0u8, ..32];
        match parse_hex(s, buf.as_mut_slice()) {
            Ok(_)  => Some(Key(buf)),
            Err(_) => None,
        }
    }
}

fn parse_hex(s: &str, buf: &mut [u8]) -> Result<(),()> {
    if s.len() != 2*buf.len() {
        return Err(());
    }
    for i in range(0u, buf.len()) {
        for j in range(0u, 2) {
            buf[i] = (buf[i] << 4) + match s[2*i + j] as char {
                c @ '0' .. '9' => (c as u8) - ('0' as u8),
                c @ 'a' .. 'f' => (c as u8) - ('a' as u8) + 10,
                c @ 'A' .. 'F' => (c as u8) - ('A' as u8) + 10,
                _              => return Err(()),
            }
        }
    }
    return Ok(());
}

struct Address {
    id: ClientId,
    nospam: [u8, ..4],
}

impl fmt::Show for Address {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        try!(fmt.buf.write_str(format!("{}", self.id)));
        for &n in self.nospam.iter() {
            try!(fmt.buf.write_str(format!("{:x}", n)));
        }
        Ok(())
    }
}

enum RotoxError {
    MessageTooLong,
    NoMessage,
    OwnKey,
    AlreadyInvited,
    Unknown,
    BadChecksum,
}

struct Friend<'a> {
    tox: &'a Rotox,
    id: uint,
}

impl<'a> Friend<'a> {
    /*
    pub fn client_id(&'a self) -> &'a ClientId { }
    pub fn delete(self) { }
    pub fn is_connected(&self) -> bool { }
    pub fn send(&mut self, msg: &str) -> u64 { }
    pub fn action(&mut self, msg: &str) -> u64 { }
    pub fn status_message(&'a self) -> &'a str { }
    pub fn status(&self) -> UserStatus { }
    pub fn last_online(&self) -> Tm { }
    pub fn set_typing(&mut self, typing: bool) { }
    pub fn typing(&self) -> bool { }
    pub fn set_send_receipts(&mut self, send: bool) { }
    */
}

enum UserStatus {
    NoStatus,
    Away,
    Busy,
    Invalid,
}

struct Rotox;

impl<'a> Rotox {
    /*
    pub fn address(&self) -> Address { }
    pub fn add_friend(&mut self, addr: Address, msg: &str) -> Result<(),RotoxError> { }
    pub fn friend(&'a mut self, friend: ClientId) -> Option<Friend<'a>> { }
    pub fn set_name(&mut self, name: &str) -> Result<(),()> { }
    pub fn name(&'a self) -> &'a str { }
    pub fn set_status_message(&mut self, msg: &str) -> Result<(),()> { }
    pub fn status_message(&self) -> &str { }
    pub fn set_status(&mut self, status: UserStatus) { }
    pub fn status(&self) -> UserStatus { }
    pub fn friends(&'a mut self) -> &'a [Friend<'a>] { }


    fn handle_get_nodes(&mut self, addr: SocketAddr, req: ~MemReader) -> IoResult {
        let id: ClientId = try!(req.read_struct());
        let nonce: Nonce = try!(req.read_struct());
        let key = self.precomputed(id);
        let data = try!(req.read_encrypted(key.with_nonce(nonce)));

        let req = MemReader::new(data);
        let req_id: ClientId = try!(req.read_struct());
        let close_nodes = self.close_nodes(req_id);

        let plain = MemWriter::new(data);
        plain.write_struct(close_nodes);
        plain.write(req.slice_to_end());

        let resp = MemWriter::new();
        nonce = Nonce::random();
        resp.write_u8(3);
        resp.write_struct(nonce);
        resp.write_encrypted(key.with_nonce(nonce), plain.get_ref());

        self.udp_sender.send_to(addr, resp.get_ref())
    }

    fn handle_send_nodes(&mut self, addr: SocketAddr, resp: ~MemReader) -> IoResult {
        let id: ClientId = try!(resp.read_struct());
        let nonce: Nonce = try!(resp.read_struct());
        let key = self.precomputed(id);
        let data = try!(resp.read_encrypted());
        if data.len() < 160 /* size of (private data + nonce) in request */ {
            return other_error();
        }

        let nodes = data.slice(0, data.len() - 160);
        let nodes: Vec<Node4> = try!(BufReader::new(nodes).read_struct());

        let private = BufReader::new(data.slice_from(data.len() - 160));
        nonce = try!(private.read_struct());
        data = try!(private.read_encrypted(self.symmetric.with_nonce(nonce)));
        private = BufReader::new(data);
        let time = try!(private.read_be_u64());
        if Ping::timed_out(time) {
            return other_error();
        }
        let nf: Node4 = try!(private.read_struct());
        if nf.addr != addr || nf.id != id {
            return other_error();
        }
        let nf: Node4 = try!(private.read_struct());
        if nf.not_empty() {
            /* sendback */
        }

        self.add_to_dht(addr, id);
    }
    */
}
