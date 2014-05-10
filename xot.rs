/*
extern crate time;

use std::fmt;
use std::from_str::{FromStr};
use time::Tm;
use std::io::{IoResult, MemReader, MemWriter, standard_error, OtherIoError};
use std::io::net::ip::{SocketAddr};
use crypt::{Nonce, Key, KEY};
use utils::{other_error, parse_hex};
use messenger::{MessengerControl, FriendStatus};
use dht::{DHTControl};

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

/////////////////////////////////////////////////
// ClientId
/////////////////////////////////////////////////

pub type ClientId = Key;


///////////////////////////////////////////
// Friend
///////////////////////////////////////////

struct Friend {
    id:        ClientId,
    messenger: MessengerControl,
    dht:       DHTControl,
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
*/
