use std::io::{IoResult, MemWriter, MemReader};
use std::io::net::ip::{SocketAddr};
use std::str::{from_utf8};
use time::{Timespec};
use utils;
use utils::{other_error, parse_hex};
use collections::hashmap::{HashMap};
use crypt;
use crypt::{Key};
use std::{fmt, mem};
use std::from_str::{FromStr};

static ACTION:            u8 = 63;
static FILE_CONTROL:      u8 = 81;
static FILE_DATA:         u8 = 82;
static FILE_SEND_REQUEST: u8 = 80;
static ID_MSI:            u8 = 69;
static ID_RECEIPT:        u8 = 65;
static INVITE_GROUP_CHAT: u8 = 144;
static JOIN_GROUP_CHAT:   u8 = 145;
static MESSAGE:           u8 = 64;
static NICKNAME:          u8 = 48;
static PING:              u8 = 0;
static STATUS_MESSAGE:    u8 = 49;
static TYPING:            u8 = 51;
static USER_STATUS:       u8 = 50;

pub struct ClientAddr {
    id: Key,
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

        if parse_hex(s.slice(0, crypt::KEY), id.as_mut_slice()).is_err() {
            return None;
        }
        if parse_hex(s.slice(crypt::KEY, crypt::KEY+2), nospam.as_mut_slice()).is_err() {
            return None;
        }
        if parse_hex(s.slice(crypt::KEY+2, crypt::KEY+4), check.as_mut_slice()).is_err() {
            return None;
        }

        let addr = ClientAddr { id: Key(id), nospam: nospam };
        if addr.checksum().as_slice() != check.as_slice() {
            return None;
        }
        addr
    }
}

enum UserStatus {
    NoStatus = 0,
    Away     = 1,
    Busy     = 2,
}

impl UserStatus {
    fn from_u8(v: u8) -> IoResult<UserStatus> {
        match v {
            0 => Ok(NoStatus),
            1 => Ok(Away),
            2 => Ok(Busy),
            _ => other_error(),
        }
    }
}

pub enum FriendStatus {
    Requested,
    Offline,
    Online,
}

struct Client<'a> {
    raw: &'a mut RawClient,
}

impl<'a> Client<'a> {
    fn send_message_action(&self, msg: &str, kind: u8) -> IoResult<()> {
        self.raw.msg_id += 1;

        let mut packet = MemWriter::new();
        try!(packet.write_u8(kind));
        try!(packet.write_be_u32(self.raw.msg_id));

        self.crypto.send_packet(self.raw.addr, packet.unwrap());
        Ok(())
    }

    fn send_message(&self, msg: &str) -> IoResult<()> {
        self.send_message_action(msg, MESSAGE)
    }

    fn send_action(&self, msg: &str) -> IoResult<()> {
        self.send_message_action(msg, ACTION)
    }

    fn set_nick(&self, nick: ~str) -> IoResult<()> {
        self.raw.nick = nick;
    }

    fn last_online(&self) -> Timespec {
        self.raw.last_ping
    }

    fn is_typing(&self) -> bool {
    }

    fn invite_to_group(&self, group_id: &Key) -> IoResult<()> {
        let packet = MemWriter::new();
        try!(packet.write_u8(INVITE_GROUP_CHAT));
        try!(packet.write_struct(group_id));

        self.crypto.send_packet(self.raw.addr, packet.unwrap());
        Ok(())
    }

    fn handle_ping(&self) -> IoResult<()> {
        self.raw.last_ping = utils::time::sec();
    }

    fn handle_nick(&self, mut data: MemReader) -> IoResult<()> {
        let nick = try!(data.read_to_end());
        match from_utf8(nick.as_slice()) {
            Some(nick) => {
                /* send to frontend */
                Ok(())
            },
            None => other_error(),
        }
    }

    fn handle_status_message(&self, mut data: MemReader) -> IoResult<()> {
        let message = try!(data.read_to_end());
        match from_utf8(message.as_slice()) {
            Some(message) => {
                self.raw.status_message = message.to_owned();
                /* send to frontend */
                Ok(())
            },
            None => other_error(),
        }
    }

    fn ping(&self) -> IoResult<()> {
        self.crypto.send_packet(self.addr.clone, vec!(PING));
        self.raw.last_ping = utils::time::sec();
        Ok(())
    }

    fn handle_user_status(&self, mut data: MemReader) -> IoResult<()> {
        let status = try!(data.read_u8());
        let status = try!(UserStatus::from_u8(status));
        self.raw.user_status = status;
        /* send to frontend */
    }

    fn handle_typing(&self, mut data: MemReader) -> IoResult<()> {
        let typing = try!(data.read_u8());
        let typing = typing != 0;
        self.raw.typing = typing;
        /* send to frontend */
    }

    fn handle_message_action(&self, mut data: MemReader) -> IoResult<(u32, ~str)> {
        let id = try!(data.read_be_u32());
        let message = try!(data.read_to_end());
        let message = match from_utf8(message.as_slice()) {
            Some(m) => m.to_owned(),
            None => return other_error(),
        };
        if self.raw.send_receipts {
            self.send_receipt(id);
        }
        Ok((id, message))
    }

    fn handle_message(&self, mut data: MemReader) -> IoResult<()> {
        let (id, message) = try!(self.handle_message_action(data));
        /* send to frontend */
    }

    fn handle_action(&self, mut data: MemReader) -> IoResult<()> {
        let (id, message) = try!(self.handle_message_action(data));
        /* send to frontend */
    }

    fn handle_receipt(&self, mut data: MemReader) -> IoResult<()> {
        let id = try!(data.read_be_u32());
        /* send to frontend */
    }

    fn handle_invite_groupchat(&self, mut data: MemReader) -> IoResult<()> {
        let key: Key = try!(data.read_struct());
        /* ??? */
    }

    fn handle_join_groupchat(&self, mut data: MemReader) -> IoResult<()> {
        let group_key: Key = try!(data.read_struct());
        let friend: Key = try!(data.read_struct());
        if !self.invited(&group_key) {
            return other_error();
        }
        /* ??? */
    }
}

struct RawClient {
    message:         ~str,
    userstatus:      UserStatus,
    typing:          bool,
    request_timeout: i64,
    request_last:    i64,
    last_ping:       Timespec,
    status:          FriendStatus,
    msg_id:          u32,
    send_receipts:   bool,
}

struct Messenger {
    addr: ClientAddr,
    friends: HashMap<Key, RawClient>,
}

impl Messenger {
    fn add_friend(&mut self, addr: ClientAddr, msg: &str) -> Result<(),()> {
        if msg == "" {
            return other_error();
        }
        if self.add_friend_norequest(addr, msg).is_ok() {
            self.friends.find_mut(addr).unwrap().status = Offline;
            self.onion.friendrequest(addr, msg);
        }
        Ok(())
    }

    fn add_friend_norequest(&mut self, addr: ClientAddr) -> Result<(),()> {
        if addr.id == self.addr.id {
            return other_error();
        }
        if self.friends.contains_key(&addr.id) {
            return other_error();
        }
        self.friends.insert(&addr.id, unsafe { mem::init() });
        self.onion.add_friend(addr.id.clone());
        Ok(())
    }

    fn del_friend(&mut self, addr: ClientAddr) -> Result<(),()> {
        let friend = match self.friends.pop(&addr.id) {
            Some(f) => f,
            None => return other_error(),
        };
        self.onion.del_friend(addr.id.clone());
        self.crypto.kill(addr.id.clone());
    }

    fn set_nick(&mut self, nick: ~str) {
        self.nick = nick;

        let mut packet = MemWriter::new();
        let _ = packet.write_u8(NICKNAME);
        let _ = packet.write(self.status_message.as_bytes());
        let packet = packet.unwrap();

        for addr in self.friends.keys() {
            self.crypto.send_packet(addr.clone(), packet.clone());
        }
    }

    fn set_status_message(&mut self, status: ~str) {
        self.status_message = status;

        let mut packet = MemWriter::new();
        let _ = packet.write_u8(STATUS_MESSAGE);
        let _ = packet.write(self.status_message.as_bytes());
        let packet = packet.unwrap();

        for addr in self.friends.keys() {
            self.crypto.send_packet(addr.clone(), packet.clone());
        }
    }

    fn set_user_status(&mut self, status: u8) {
        self.user_status = status;

        let mut packet = MemWriter::new();
        let _ = packet.write_u8(USER_STATUS);
        let _ = packet.write_u8(status);
        let packet = packet.unwrap();

        for addr in self.friends.keys() {
            self.crypto.send_packet(addr.clone(), packet.clone());
        }
    }
}

pub struct MessengerControl;

impl MessengerControl {
    fn friend_request(&self, source: &Key, msg: ~str) {
        unreachable!();
    }
}
