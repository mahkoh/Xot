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

/////////////////////////////////////////////////
// ClientAddr
/////////////////////////////////////////////////

pub struct ClientAddr {
    id: ClientId,
    nospam: [u8, ..2],
}

impl ClientAddr {
    fn checksum(&self) -> [u8, ..2] {
        let check = [0u8, 0u8];
        let Key(ref key) = self.id;
        for (i, x) in key.enumerate() {
            check[i % 2] ^= x;
        }
        check[(crypt::KEY + 0) % 2] ^= self.nospam[0];
        check[(crypt::KEY + 1) % 2] ^= self.nospam[1];
        check
    }
}

impl fmt::Show for ClientAddr {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        self.id.fmt(fmt);
        try!(fmt.buf.write_str(format!("{:x}", self.nospam[0])));
        try!(fmt.buf.write_str(format!("{:x}", self.nospam[1])));
        let checksum = self.checksum();
        try!(fmt.buf.write_str(format!("{:x}", checksum[0])));
        try!(fmt.buf.write_str(format!("{:x}", checksum[1])));
        Ok(())
    }
}

impl FromStr for ClientAddr {
    fn from_str(s: &str) -> Option<ClientAddr> {
        if s.len() != 2 * (crypt::KEY + 2 + 2) {
            return None;
        }

        let mut id     = [0u8, ..32];
        let mut nospam = [0u8, ..2];
        let mut check  = [0u8, ..2];

        if parse_hex(s.slice(0, crypt::KEY), buf.as_mut_slice()).is_err() {
            return None;
        }
        if parse_hex(s.slice(crypt::KEY, crypt::KEY+2), nospam.as_mut_slice()).is_err() {
            return None;
        }
        if parse_hex(s.slice(crypt::KEY+2, crypt::KEY+4), check.as_mut_slice()).is_err() {
            return None;
        }

        let addr = ClientAddr { id: Key(id), nospam: nospam };
        if addr.checksum().as_slice() != checksum.as_slice() {
            return None;
        }
        addr
    }
}

/////////////////////////////////////////////////
// ClientId
/////////////////////////////////////////////////

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

///////////////////////////////////////////
// Friend
///////////////////////////////////////////

struct Friend {
    id:        ClientId,
    messenger: MessengerControler,
    dht:       DHTControler,
}

impl<'a> Friend {
    pub fn id(&'a self) -> &'a ClientId {
        &self.id
    }

    pub fn delete(self) {
        self.messenger.delete(self.id.clone());
    }

    pub fn status(&self) -> FriendStatus {
        self.messenger.status(self.id.clone())
    }

    pub fn message(&self, msg: ~str) -> u64 {
        self.messenger.message(self.id.clone(), msg)
    }

    pub fn action(&self, msg: ~str) -> u64 {
        self.messenger.action(self.id.clone(), msg)
    }

    pub fn status_message(&self) -> ~str {
        self.messenger.status_message(self.id.clone())
    }

    pub fn last_online(&self) -> Tm {
        self.messenger.last_online(self.id.clone())
    }

    pub fn set_typing(&self, typing: bool) {
        self.messenger.set_typing(self.id.clone(), typing)
    }

    pub fn typing(&self) -> bool {
        self.messenger.typing(self.id.clone())
    }

    pub fn set_send_receipts(&self, send: bool) {
        self.messenger.set_send_receipts(self.id.clone(), send)
    }
}

///////////////////////////////////////////
// Xot
///////////////////////////////////////////

struct Xot;

impl<'a> Xot {
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
    */
}
