use std::comm::{channel, Sender, Receiver};
use messenger::{MessengerControl, UserStatus, ClientAddr};
use crypt::{Key};

struct PeerChange;

pub enum Event {
    FriendRequest(Key, ~str),
    FriendMessage(Key, ~str),
    FriendAction(Key, ~str),
    FriendName(Key, ~str),
    FriendStatusMessage(Key, ~str),
    FriendUserStatus(Key, UserStatus),
    FriendTyping(Key, bool),
    FriendReceipt(Key, u32),
    FriendOnline(Key, bool),

    GroupInvite(Key, Key),
    GroupMessage(Key, Key, ~str),
    GroupAction(Key, Key, ~str),
    GroupNewPeer(Key, Key),
    GroupDelPeer(Key, Key),
    GroupPeerName(Key, Key, ~str),
}

pub struct FriendInfo {
    addr: ClientAddr,
    name: ~str,
    status_message: ~str,
    online: bool,
    last_seen: i64,
    user_status: UserStatus,
}

pub enum XotError {
    FriendNotFound,
    GroupNotFound,
}

enum InfoType {
    GetAddress(Sender<ClientAddr>),
    GetFriendName(Key, Sender<Option<~str>>),
    GetName(Sender<~str>),
    GetFriendInfo(Key, Sender<Option<FriendInfo>>),
    GetFriends(Sender<Vec<FriendInfo>>),
    GetStatusMessage(Sender<Option<~str>>),
    GetUserStatus(Sender<UserStatus>),
}

enum Setting {
    SetName(~str),
    SetStatusMessage(~str),
    SetUserStatus(UserStatus),
    SetNospam([u8, ..4]),
}

type XotResult<T> = Result<T, XotError>;

struct Xot {
    info: Sender<InfoType>,
    friend_req: Sender<(ClientAddr, Option<~str>)>,
    friend_del: Sender<(Sender<XotResult<()>>, Key)>,
    friend_msg: Sender<(Sender<XotResult<u32>>, Key, ~str)>,
    friend_action: Sender<(Sender<XotResult<u32>>, Key, ~str)>,
    settings: Sender<Setting>,
}

impl Xot {
    pub fn address(&self) -> ClientAddr {
        let (snd, rcv) = channel();
        self.info.send(GetAddress(snd));
        rcv.recv()
    }

    pub fn add_friend(&self, friend: &ClientAddr, msg: ~str) {
        self.friend_req.send((*friend, Some(msg)));
    }

    pub fn add_friend_norequest(&self, friend: &ClientAddr) {
        self.friend_req.send((*friend, None));
    }

    pub fn del_friend(&self, friend: &Key) -> XotResult<()> {
        let (snd, rcv) = channel();
        self.friend_del.send((snd, *friend));
        rcv.recv()
    }

    pub fn send_message(&self, friend: &Key, msg: ~str) -> XotResult<u32> {
        let (snd, rcv) = channel();
        self.friend_msg.send((snd, *friend, msg));
        rcv.recv()
    }

    pub fn send_action(&self, friend: &Key, msg: ~str) -> XotResult<u32> {
        let (snd, rcv) = channel();
        self.friend_action.send((snd, *friend, msg));
        rcv.recv()
    }

    pub fn set_name(&self, name: ~str) {
        self.settings.send(SetName(name));
    }

    pub fn get_name(&self) -> ~str {
        let (snd, rcv) = channel();
        self.info.send(GetName(snd));
        rcv.recv()
    }

    pub fn get_friend_name(&self, friend: &Key) -> Option<~str> {
        let (snd, rcv) = channel();
        self.info.send(GetFriendName(*friend, snd));
        rcv.recv()
    }

    pub fn set_status_message(&self, msg: ~str) {
        self.settings.send(SetStatusMessage(msg));
    }

    pub fn get_status_message(&self) -> Option<~str> {
        let (snd, rcv) = channel();
        self.info.send(GetStatusMessage(snd));
        rcv.recv()
    }

    pub fn set_user_status(&self, status: UserStatus) {
        self.settings.send(SetUserStatus(status));
    }

    pub fn get_user_status(&self) -> UserStatus {
        let (snd, rcv) = channel();
        self.info.send(GetUserStatus(snd));
        rcv.recv()
    }

    pub fn friend_info(&self, friend: &Key) -> Option<FriendInfo> {
        let (snd, rcv) = channel();
        self.info.send(GetFriendInfo(*friend, snd));
        rcv.recv()
    }

    pub fn friends(&self) -> Vec<FriendInfo> {
        let (snd, rcv) = channel();
        self.info.send(GetFriends(snd));
        rcv.recv()
    }

    pub fn set_nospam(&self, ns: [u8, ..4]) {
        self.settings.send(SetNospam(ns));
    }
}
