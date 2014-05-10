use std::io::{MemWriter, MemReader, IoResult};
use std::io::net::ip::{SocketAddr};
use std::{mem};
use crypt;
use crypt::{Key, SecretKey, PrecomputedKey, key_pair, Nonce, KEY};
use utils;
use utils::time::{sec};
use utils::ringbuffer::{RingBuffer};
use utils::bufreader::{BufReader};
use utils::{other_error, Choice, One, Two, StructReader, StructWriter, CryptoWriter,
            SlicableReader, CryptoReader};
use net::{Node, IpAddrInfo};
use rand;
use rand::{task_rng, Rng};
use onion::pipe::{PipeControl};
use onion::consts::{META_REQUEST, ONION_FORWARD_REQUEST, FAKE_ID, CRYPTO,
                    CRYPTO_PACKET_FRIEND_REQ};
use dht;
use dht::{DHTControl};
use messenger::{MessengerControl};

/// Size of send back data in an meta request.
static SEND_BACK: uint = 108u;
/// Size of a ping id in a meto request.
static PING_ID: uint = 32u;
/// Path timeout in seconds.
static PATH_TIMEOUT: u64 = 30;
/// Maximal path lifetime in seconds.
static PATH_MAX_LIFETIME: u64 = 600;
/// Friend timeout in seconds.
static DEAD_ONION_TIMEOUT: u64 = 600;
static ANNOUNCE_INTERVAL_NOT_ANNOUNCED: u64 = 10;
static ANNOUNCE_INTERVAL_ANNOUNCED: u64 = 30;
static ONION_FAKE_ID_INTERVAL: u64 = 30;
static DHT_FAKE_ID_INTERVAL: u64 = 20;
static MAX_CLIENTS: uint = 8;
static META_TIMEOUT: u64 = 300;
static MAX_PING_NODES_SECOND: uint = 5;
static MAX_STORED_PINGED_NODES: uint = 9;
static ONION_CONTACT_TIMEOUT: u64 = 120;
static ONION_CONTACT_PING_INTERVAL: u64 = 30;
static MIN_NODE_PING_TIME: u64 = 10;
static MAX_ONION_PATHS: uint = 3;

/// A node in the onion network.
pub struct PathNode {
    /// Our public key generated specifically for this node.
    pub public: Key,
    /// The key precomputed from the peer's public key and the private key which
    /// corresponds to the public key above.
    pub encoder: PrecomputedKey,
    /// The address of the node.
    pub addr: SocketAddr,
}

/// The intemediate steps in an onion request.
pub struct OnionPath {
    pub nodes: [PathNode, ..3],
    last_success: u64,
    creation: u64,
}

impl OnionPath {
    fn new(raw: Box<[Node, ..3]>, dht_pub: &Key, dht_priv: &SecretKey) -> OnionPath {
        let pub0 = *dht_pub;
        let (priv1, pub1) = crypt::key_pair();
        let (priv2, pub2) = crypt::key_pair();

        let enc0 = PrecomputedKey::new( dht_priv, &raw[0].id);
        let enc1 = PrecomputedKey::new(&priv1,    &raw[1].id);
        let enc2 = PrecomputedKey::new(&priv2,    &raw[2].id);

        let node0 = PathNode { public: pub0, encoder: enc0, addr: raw[0].addr };
        let node1 = PathNode { public: pub1, encoder: enc1, addr: raw[1].addr };
        let node2 = PathNode { public: pub2, encoder: enc2, addr: raw[2].addr };

        OnionPath {
            nodes: [node0, node1, node2],
            last_success: utils::time::sec(),
            creation:     utils::time::sec(),
        }
    }

    fn should_replace(&self) -> bool {
        let now = utils::time::sec();
        self.last_success + PATH_TIMEOUT < now || self.creation + PATH_MAX_LIFETIME < now
    }
}


/// Convenience wrapper for RawFriend.
struct Friend<'a> {
    /// The underlying RawFriend.
    raw:            &'a RawFriend,
    /// The OnionClient's symmetric key.
    symmetric:      &'a Key,
    /// The pipe control.
    pipe:           &'a PipeControl,
    /// The OnionClient's data key.
    data_key:       &'a Key,
    /// The crypto module's private key.
    crypto_private: &'a SecretKey,
    /// The crypto module's public key.
    crypto_public:  &'a Key,
    /// The DHT module's public key.
    dht_pub:        &'a Key,
    /// The DHT module's private key.
    dht_priv:       &'a SecretKey,
    /// The DHT controler.
    dht:            &'a DHTControl,
}

impl<'a> Friend<'a> {
    fn random_path<'a>(&'a mut self, num: Option<uint>) -> IoResult<&'a OnionPath> {
        match self.raw.paths.len() {
            MAX_ONION_PATHS => {
                let n = match num {
                    Some(n) => n % MAX_ONION_PATHS,
                    None    => task_rng().gen_range(0, MAX_ONION_PATHS),
                };
                if self.raw.paths.get(n).should_replace() {
                    let nodes = try!(self.dht.random_path());
                    *self.raw.paths.get_mut(n) = OnionPath::new(nodes, self.dht_pub,
                                                                self.dht_priv);
                }
                Ok(self.raw.paths.get(n))
            },
            _ => {
                let nodes = try!(self.dht.random_path());
                self.raw.paths.push(OnionPath::new(nodes, self.dht_pub,
                                                   self.dht_priv));
                let n = self.raw.paths.len() - 1;
                Ok(self.raw.paths.get(n))
            },
        }
    }

    fn set_path_timeout(&mut self, addr: SocketAddr) -> Option<uint> {
        for (i, path) in self.raw.paths.mut_iter().enumerate() {
            if path.nodes[0].addr == addr {
                path.last_success = utils::time::sec();
                return Some(i);
            }
        }
        None
    }

    /// Change the onion status of the friend.
    /// 
    /// Use this instead of setting the onlien friend manually.
    fn set_online(&mut self, online: bool) {
        if self.raw.is_online && !online {
            self.raw.last_seen = utils::time::sec();
        }
        self.raw.is_online = online;
        if !online {
            self.raw.last_no_replay = utils::time::sec();
        }
    }

    /// Check if the friend is cosidered dead because we haven't seen him in a long time.
    fn is_kill(&self) -> bool {
        self.raw.last_seen + DEAD_ONION_TIMEOUT < utils::time::sec()
    }

    /// Send a meta request to `dest`.
    ///
    /// If `self` is `myself` from the client then we announce our data key.
    /// Otherwise we ask for the data key of our friend.
    /// 
    /// If `dest` is One(node), we send a new request to it.
    /// If `dest` is Two(i), we take the contact at that position from our contact list.
    fn send_meta_request(&mut self, dest: Choice<&Node, uint>) -> IoResult<()> {
        // Let's do this first because all those other try!s probably won't fail.
        let path = try!(self.random_path(None));

        let (dest_addr, dest_id) = match dest {
            One(d) => (d.addr, &d.id),
            Two(i) => {
                let c = &self.raw.contacts.get(i);
                (c.addr, &c.id)
            },
        };

        let send_back = {
            let nonce = Nonce::random();

            let private = MemWriter::new();
            // id is None for `myself`. We encode this as 0.
            match self.raw.id {
                Some(n) => try!(private.write_be_u32((n+1) as u32)),
                None    => try!(private.write_be_u32(0)),
            };
            try!(private.write_be_u64(utils::time::sec()));
            match dest {
                One(n) => {
                    try!(private.write_struct(&n.id));
                    try!(private.write_struct(&n.addr));
                },
                Two(i) => {
                    let c = self.raw.contacts.get(i);
                    try!(private.write_struct(&c.id));
                    try!(private.write_struct(&c.addr));
                },
            }
            let send_back = MemWriter::new();
            try!(send_back.write_struct(&nonce));
            try!(send_back.write_encrypted(&self.symmetric.with_nonce(&nonce),
                                           private.get_ref()));
            send_back.unwrap()
        };

        let plain = {
            let mut plain = MemWriter::new();
            match dest {
                One(_) => try!(plain.write([0u8, ..PING_ID])),
                Two(i) => try!(plain.write(self.raw.contacts.get(i).ping_id)),
            }
            try!(plain.write_struct(&self.raw.real_id));
            match self.raw.id.is_none() {
                true  => try!(plain.write_struct(self.data_key)),
                false => try!(plain.write([0u8, ..KEY])),
            }
            try!(plain.write(send_back.as_slice()));
            plain.unwrap()
        };

        let packet = {
            let nonce = Nonce::random();
            let mut packet = MemWriter::new();
            try!(packet.write_u8(META_REQUEST));
            try!(packet.write_struct(&nonce));
            try!(packet.write_struct(&self.raw.tmp_public));
            {
                let machine = PrecomputedKey::new(&self.raw.tmp_private,
                                                  dest_id).with_nonce(&nonce);
                try!(packet.write_encrypted(&machine, plain.as_slice()));
            }
            packet.unwrap()
        };

        let (addr, id) = match dest {
            One(n) => (n.addr, &n.id),
            Two(i) => {
                let c = self.raw.contacts.get(i);
                (c.addr, &c.id)
            }
        };

        self.pipe.send(path, addr, packet);
        self.raw.last_pinged.push(Ping { id: *id, timestamp: utils::time::sec() });
        self.raw.ping_nodes_second += 1;
        Ok(())
    }

    /// Send data to a friend via the onion network.
    /// 
    /// If the function returns and error, we cannot assume that anything was sent.
    /// Currently we send Fake ID and Friend Request via this function.
    fn send_onion_data(&self, data: &[u8]) -> IoResult<()> {
        let paths = Vec::new();
        let total_live_contacts = 0u;
        for (i, contact) in self.raw.contacts.iter().enumerate() {
            if contact.timed_out() {
                continue;
            }
            total_live_contacts += 1;
            if contact.data_key.is_some() {
                match self.random_path(None) {
                    Ok(p)  => paths.push((i, p.clone())),
                    Err(_) => { },
                }
            }
        }
        // Formula discovered by irungentoo using the scientific method.
        if paths.len() < (total_live_contacts / 4) + 1 {
            return other_error();
        }

        let nonce = Nonce::random();
        let encrypted = {
            let machine = PrecomputedKey::new(self.crypto_private,
                                              &self.raw.real_id).with_nonce(&nonce);
            let mut encrypted = MemWriter::new();
            try!(encrypted.write_struct(self.crypto_public));
            try!(encrypted.write_encrypted(&machine, data));
            encrypted.unwrap()
        };

        for &(i, path) in paths.iter() {
            let node = self.raw.contacts.get(i);

            let packet = {
                let (rand_priv, rand_pub) = key_pair();
                let machine = {
                    let data_key = node.data_key.as_ref().unwrap();
                    PrecomputedKey::new(&rand_priv, data_key).with_nonce(&nonce)
                };
                let mut packet = MemWriter::new();
                try!(packet.write_u8(ONION_FORWARD_REQUEST));
                try!(packet.write_struct(&self.raw.real_id));
                try!(packet.write_struct(&nonce));
                try!(packet.write_struct(&rand_pub));
                try!(packet.write_encrypted(&machine, encrypted.as_slice()));
                packet.unwrap()
            };

            self.pipe.send(path, node.addr, packet);
        }
        Ok(())
    }

    /// Do general maintenance for `myself`.
    ///
    /// This function should ONLY be called on `myself`.
    fn do_myself(&mut self) {
        let count = 0u;
        for i in range(0, self.raw.contacts.len()) {
            if self.raw.contacts.get(i).timed_out() {
                continue;
            }
            count += 1;
            if self.raw.contacts.get(i).last_pinged == 0 {
                self.raw.contacts.get(i).last_pinged = 1;
                continue;
            }
            let interval = match self.raw.contacts.get(i).data_key {
                Some(_) => ANNOUNCE_INTERVAL_NOT_ANNOUNCED,
                None    => ANNOUNCE_INTERVAL_ANNOUNCED,
            };
            if self.raw.contacts.get(i).last_pinged + interval > utils::time::sec() {
                self.send_meta_request(Two(i));
            }
        }
        if count <= task_rng().gen_range(0, MAX_CLIENTS) {
            let lan_ok = true;
            let want_good = false;
            let nodes = self.dht.get_close_nodes(self.crypto_public, lan_ok, want_good);
            for node in nodes.iter() {
                self.send_meta_request(One(node));
            }
        }
    }

    /// Do general maintenance for a friend.
    ///
    /// This function should NOT be called on `myself`.
    fn do_friend(&mut self) {
        if self.raw.is_online {
            return;
        }
        let count = 0u;
        for i in range(0, self.raw.contacts.len()) {
            if self.raw.contacts.get(i).timed_out() {
                continue;
            }
            count += 1;
            if self.raw.contacts.get(i).should_ping() {
                self.send_meta_request(Two(i));
                self.raw.contacts.get(i).last_pinged = utils::time::sec();
            }
        }
        if count <= task_rng().gen_range(0, MAX_CLIENTS) {
            // Is this correct?
            let lan_ok = false;
            let want_good = false;
            let nodes = self.dht.get_close_nodes(self.crypto_public, lan_ok, want_good);
            for node in nodes.iter() {
                self.send_meta_request(One(node));
            }
        }
        if self.should_send_onion_fake_id() {
            let dht_instead_of_onion = false;
            self.send_fake_id(dht_instead_of_onion);
            self.raw.last_onion_fake_id = utils::time::sec();
        }
        if self.should_send_dht_fake_id() {
            let dht_instead_of_onion = true;
            self.send_fake_id(dht_instead_of_onion);
            self.raw.last_dht_fake_id = utils::time::sec();
        }
    }

    /// Check if we should send the frind our fake id via onion.
    fn should_send_onion_fake_id(&self) -> bool {
        self.raw.last_onion_fake_id + ONION_FAKE_ID_INTERVAL < utils::time::sec()
    }

    /// Check if we should send the frind our fake id via DHT.
    fn should_send_dht_fake_id(&self) -> bool {
        self.raw.last_dht_fake_id + DHT_FAKE_ID_INTERVAL < utils::time::sec()
    }

    /// Generate a fake id packet and send it via onion or DHT.
    fn send_fake_id(&self, dht_instead_of_onion: bool) -> IoResult<()> {
        let packet = {
            let close_nodes = self.dht.get_closelist_nodes();
            let mut packet = MemWriter::new();
            try!(packet.write_u8(FAKE_ID));
            try!(packet.write_be_u64(utils::time::sec()));
            try!(packet.write_struct(self.dht_pub));
            try!(packet.write_struct(&close_nodes));
            packet.unwrap()
        };
        if dht_instead_of_onion {
            self.send_dht_fake_id(packet.as_slice())
        } else {
            self.send_onion_data(packet.as_slice())
        }
    }

    /// Send a fake id packet via DHT.
    fn send_dht_fake_id(&self, data: &[u8]) -> IoResult<()> {
        let encrypted = {
            let nonce = Nonce::random();
            let mut encrypted = MemWriter::new();
            try!(encrypted.write_struct(self.crypto_public));
            try!(encrypted.write_struct(&nonce));
            let machine = PrecomputedKey::new(self.crypto_private,
                                              &self.raw.real_id).with_nonce(&nonce);
            try!(encrypted.write_encrypted(&machine, data));
            encrypted.unwrap()
        };

        let packet = {
            let nonce = Nonce::random();
            let mut tmp = MemWriter::new();
            try!(tmp.write_u8(FAKE_ID));
            try!(tmp.write(encrypted.as_slice()));

            let machine = PrecomputedKey::new(self.dht_priv,
                                              &self.raw.real_id).with_nonce(&nonce);
            let mut packet = MemWriter::new();
            try!(packet.write_u8(CRYPTO));
            try!(packet.write_struct(&self.raw.fake_id.unwrap()));
            try!(packet.write_struct(self.dht_pub));
            try!(packet.write_struct(&nonce));
            try!(packet.write_encrypted(&machine, tmp.get_ref()));
            packet.unwrap()
        };

        self.dht.route_to_friend(self.raw.fake_id.as_ref().unwrap(), packet);
        Ok(())
    }
}

/// A contact in the onion network connecting us to a friend.
struct Contact {
    /// The id of the contact.
    id:          Key,
    /// The address of the contact.
    addr:        SocketAddr,
    /// TODO
    timestamp:   u64,
    /// Last time we pinged this contact.
    last_pinged: u64,
    /// The friend's onion path we used for this contact.
    path_used:   uint,
    /// The friend's data key, according to this contact.
    data_key:    Option<Key>,
    /// The contact's current ping id.
    ping_id:     [u8, ..32],
}

impl Contact {
    fn new() -> Contact {
        let contact: Contact = unsafe { mem::init() };
        contact.data_key = None;
        contact
    }

    fn timed_out(&self) -> bool {
        self.timestamp + ONION_CONTACT_TIMEOUT < utils::time::sec()
    }

    fn should_ping(&self) -> bool {
        self.last_pinged + ONION_CONTACT_PING_INTERVAL < utils::time::sec()
    }
}

struct Ping {
    id: Key,
    timestamp: u64,
}

impl Ping {
    fn timed_out(&self) -> bool {
        self.timestamp + MIN_NODE_PING_TIME < utils::time::sec()
    }
}

/// A friend in the onion network or `myself`.
struct RawFriend {
    /// Is the friend online.
    is_online:      bool,
    /// List of contacts connecting us to the friend.
    contacts:       Vec<Contact>,
    /// The real id of the friend.
    real_id:        Key,
    /// The fake DHT id of the friend.
    fake_id:        Option<Key>,
    /// The position of the friend in the OnionClient's friends vector or None if
    /// RawFriend is `myself`.
    id:             Option<uint>,
    /// TODO
    tmp_public:     Key,
    /// TODO
    tmp_private:    SecretKey,
    /// Path's generated to connect to the friend.
    paths: Vec<OnionPath>,
    /// TODO Field to prevent replay attacks.
    last_no_replay: u64,
    /// Last time we saw this friend online.
    last_seen: u64,
    last_pinged: RingBuffer<Ping>,
    ping_nodes_second: uint,
    last_onion_fake_id: u64,
    last_dht_fake_id: u64,
}

/// Iterator over all convenience wrappers for all friends.
struct FriendsIter<'a> {
    client: &'a Client,
    pos: uint,
}

impl<'a> Iterator<Friend<'a>> for FriendsIter<'a> {
    fn next(&mut self) -> Option<Friend<'a>> {
        if self.pos == self.client.friends.len() {
            return None;
        }
        let friend = self.client.get_friend(self.pos).unwrap();
        self.pos += 1;
        Some(friend)
    }
}

/// The onion client running this module.
struct Client {
    /// List of our friends. The thing to note about this vector is that we can never
    /// shift elements in it. TODO Friend -> Option<Friend>
    friends:     Vec<RawFriend>,
    /// Temporary symmetric key.
    symmetric: Key,
    /// The pipe control.
    pipe: PipeControl,
    /// Our public data key.
    data_key_public: Key,
    /// Our public data key.
    data_key_private: SecretKey,
    /// The crypto module's private key.
    crypto_private: SecretKey,
    /// The crypto module's public key.
    crypto_public: Key,
    /// The DHT module's public key.
    dht_pub: Key,
    /// The DHT module's private key.
    dht_priv: SecretKey,
    /// The DHT controller.
    dht: DHTControl,
    /// Our nospam number.
    nospam: [u8, ..4],
    /// The messenger contorller.
    messenger: MessengerControl,
    /// 
    myself: RawFriend,
}

impl Client {
    /// Do all the maintenance work. Run this exactly once per second.
    fn do_client(&mut self) {
        self.myself().do_myself();
        self.do_friends();
    }

    /// Create an iterator to iterate over all convenience friends.
    fn friends_iter<'a>(&'a mut self) -> FriendsIter<'a> {
        FriendsIter { client: self, pos: 0 }
    }

    /// Do maintenance for all friends.
    fn do_friends(&mut self) {
        for f in self.friends_iter() {
            f.do_friend();
            if f.raw.fake_id.is_some() && !f.raw.is_online && f.is_kill() {
                f.dht.del_friend(f.raw.fake_id.as_ref().unwrap());
                f.raw.fake_id = None;
            }
        }
    }

    fn myself(&mut self) -> Friend {
        // TODO find out what goes here
        unreachable!();
    }

    /// Create a convenience wrapper for the friend at position `i`.
    ///
    /// Fails if i is out of bounds.
    fn get_friend<'a>(&'a self, i: uint) -> IoResult<Friend<'a>> {
        if i >= self.friends.len() {
            return other_error();
        }
        let friend = Friend {
            raw:            self.friends.get(i),
            symmetric:      &self.symmetric,
            pipe:           &self.pipe,
            data_key:       &self.data_key_public,
            crypto_private: &self.crypto_private,
            crypto_public:  &self.crypto_public,
            dht_pub:        &self.dht_pub,
            dht_priv:       &self.dht_priv,
            dht:            &self.dht,
        };
        Ok(friend)
    }

    fn find_friend<'a>(&'a self, id: &Key) -> IoResult<Friend<'a>> {
        match self.friends.iter().position(|f| f.real_id == *id) {
            Some(i) => self.get_friend(i),
            None    => other_error()
        }
    }

    /// Send a friend request.
    fn send_friend_request(&self, id: &Key, nospam: [u8, ..4],
                           msg: &[u8]) -> IoResult<()> {
        let friend = try!(self.find_friend(id));
        let packet = {
            let mut packet = MemWriter::new();
            try!(packet.write_u8(CRYPTO_PACKET_FRIEND_REQ));
            try!(packet.write(nospam));
            try!(packet.write(msg));
            packet.unwrap()
        };
        friend.send_onion_data(packet.as_slice())
    }

    /// Handle a friend request.
    fn handle_friend_request(&self, source: &Key,
                             mut data: MemReader) -> IoResult<()> {
        let nospam = try!(data.read_exact(4));
        if nospam.as_slice() != self.nospam {
            return other_error();
        }
        let msg: ~str = try!(data.read_struct());
        self.messenger.friend_request(source, msg);
        Ok(())
    }

    /// Handle a meta response.
    fn handle_meta_response(&self, source: SocketAddr,
                            mut data: MemReader) -> IoResult<()> {
        /////
        // PART 1: Read the send-back-data.
        /////

        let (num, addr, id) = {
            // Don't forget to consume the send back slice below.
            let send_back = data.slice_to_end().slice(0, SEND_BACK);
            let send_back = BufReader::new(send_back);
            let nonce: Nonce = try!(send_back.read_struct());
            let private =
                try!(self.symmetric.with_nonce(&nonce).decrypt(send_back.slice_to_end()));
            let private = MemReader::new(private);
            let num = match try!(private.read_be_u32()) {
                0 => None,
                n => Some(n-1),
            };
            let time = try!(private.read_be_u64());
            let id: Key = try!(private.read_struct());
            let addr: SocketAddr = try!(private.read_struct());

            let now = utils::time::sec();
            if time + META_TIMEOUT < now || now < time {
                return other_error();
            }
            (num, addr, id)
        };
        data.consume(SEND_BACK);

        /////
        // PART 2: Decrypt the nodes.
        /////

        let decrypted = {
            let nonce: Nonce = try!(data.read_struct());
            let friend = match num {
                Some(n) => try!(self.get_friend(n as uint)),
                None    => self.myself(),
            };
            let machine =
                PrecomputedKey::new(&friend.raw.tmp_private, &id).with_nonce(&nonce);
            let decrypted = try!(data.read_encrypted(&machine));
            MemReader::new(decrypted)
        };

        let is_data_key = try!(decrypted.read_u8()) != 0;
        let ping_id_or_data_key: Key = try!(decrypted.read_struct());
        let nodes: Vec<Node> = try!(decrypted.read_struct());

        /////
        // PART 3: Store the respondee in the nodes list (if possible).
        /////

        let friend = match num {
            Some(n) => try!(self.get_friend(n as uint)),
            None => {
                if is_data_key && self.data_key_public != ping_id_or_data_key {
                    is_data_key = false;
                }
                self.myself()
            },
        };
        // Sort worst --> best.
        friend.raw.contacts.sort_by(|c1,c2| {
            match (c1.timed_out(), c2.timed_out()) {
                (true,  true)  => Equal,
                (false, true)  => Greater,
                (true,  false) => Less,
                // real_id.cmp returs better < worse, so we interchange the arguments.
                (false, false) => friend.raw.real_id.cmp(&c2.id, &c1.id),
            }
        });
        // Store some info for use further down. This isn't perfect but good enough for
        // now.
        let furthest_away: Option<Key>;
        let has_timed_out = true;
        // We need a spot to store the respondee in. If the list is already filled, we try
        // to find a node which is worse. If the list isn't full, we simply add a new node
        // to it.
        let index = match friend.raw.contacts.len() {
            MAX_CLIENTS => {
                let index = {
                    let contact = friend.raw.contacts.get(0);
                    // See comment above.
                    has_timed_out = contact.timed_out();
                    furthest_away = Some(contact.id);
                    match has_timed_out ||
                          friend.raw.real_id.cmp(&contact.id, &id) == Greater {
                        true => Some(0),
                        false => None,
                    }
                };
                for (i, contact) in friend.raw.contacts.iter().enumerate() {
                    if contact.id == id {
                        index = Some(i);
                        break;
                    }
                }
                index
            },
            _ => {
                friend.raw.contacts.push(Contact::new());
                Some(friend.raw.contacts.len()-1)
            },
        };
        match index {
            Some(i) => {
                let c = friend.raw.contacts.get(i);
                c.id = id;
                c.addr = addr;
                c.timestamp = utils::time::sec();
                c.last_pinged = utils::time::sec();
                c.path_used = friend.set_path_timeout(source).unwrap();
                match is_data_key {
                    true  => c.data_key = Some(ping_id_or_data_key),
                    false => c.ping_id = *ping_id_or_data_key.raw(),
                }
            },
            None => { }
        }

        /////
        // PART 4: Send announce requests to all the new nodes we received.
        /////

        // Remove all timed out pings.
        friend.raw.last_pinged.remove_while(|p| p.timed_out());

        let lan_ok = source.ip.is_lan();
        for node in nodes.iter() {
            if friend.raw.ping_nodes_second > MAX_PING_NODES_SECOND {
                break;
            }
            if !lan_ok && node.addr.ip.is_lan() {
                continue;
            }
            // Don't send a request if the list is already good.
            if !has_timed_out && furthest_away.is_some() {
                let furthest_away = furthest_away.as_ref().unwrap();
                if friend.raw.real_id.cmp(furthest_away, &node.id) == Less {
                    continue;
                }
            }
            // Don't ping if the list already contains the node.
            if friend.raw.contacts.iter().any(|c| c.id == node.id) {
                continue;
            }
            // Don't ping if we're already pinging.
            if friend.raw.last_pinged.len() == MAX_STORED_PINGED_NODES {
                if friend.raw.last_pinged.iter().any(|p| p.id == node.id) {
                    continue;
                }
            }
            let _ = friend.send_meta_request(One(node));
        }

        Ok(())
    }

    /// Handle data forwarded via the onion network.
    fn handle_forwarded(&self, source: SocketAddr, mut data: MemReader) -> IoResult<()> {
        let nonce: Nonce = try!(data.read_struct());

        let encrypted = {
            let key: Key = try!(data.read_struct());
            let machine =
                PrecomputedKey::new(&self.data_key_private, &key).with_nonce(&nonce);
            MemReader::new(try!(data.read_encrypted(&machine)))
        };
        let key: Key = try!(encrypted.read_struct());

        let encrypted = {
            let machine =
                PrecomputedKey::new(&self.crypto_private, &key).with_nonce(&nonce);
            MemReader::new(try!(encrypted.read_encrypted(&machine)))
        };
        match try!(encrypted.read_u8()) {
            FAKE_ID => self.handle_fake_id(&key, encrypted),
            FRIEND_REQUEST => { unreachable!() },
        }
    }

    /// Handle a fake id sent via DHT.
    fn handle_dht_fake_id(&self, source: &Key, mut data: MemReader) -> IoResult<()> {
        let key: Key = try!(data.read_struct());
        let mut data = {
            let nonce: Nonce = try!(data.read_struct());
            let machine =
                PrecomputedKey::new(&self.crypto_private, &key).with_nonce(&nonce);
            let data = try!(data.read_encrypted(&machine));
            MemReader::new(data)
        };
        /* See
         * https://github.com/irungentoo/ProjectTox-Core/commit/9fccb80eec
        if key != *source {
            return other_error();
        }
        */
        self.handle_fake_id(&key, data)
    }

    /// Handle a fake id sent via the onion network.
    fn handle_fake_id(&self, id: &Key, mut data: MemReader) -> IoResult<()> {
        let friend = try!(self.find_friend(id));
        {
            let no_replay = try!(data.read_be_u64());
            match no_replay <= friend.raw.last_no_replay {
                true  => return other_error(),
                false => friend.raw.last_no_replay = no_replay,
            }
        }
        {
            let fake_id: Key = try!(data.read_struct());
            match friend.raw.fake_id {
                Some(id) => if fake_id != id {
                    friend.dht.refresh_friend(&id, &fake_id);
                    friend.raw.last_seen = utils::time::sec();
                },
                None => friend.dht.add_friend(&fake_id),
            }
            friend.raw.fake_id = Some(fake_id);
        }
        let nodes: Vec<Node> = try!(data.read_struct());
        friend.dht.get_all_nodes(nodes, &friend.raw.fake_id.unwrap());
        Ok(())
    }
}

pub struct OnionControl;

impl OnionControl {
    pub fn friend_request(&self, id: &Key, nospam: [u8, ..4], msg: &str) {
        unreachable!();
    }

    pub fn add_friend(&self, id: &Key) {
        unreachable!();
    }

    pub fn del_friend(&self, id: &Key) {
        unreachable!();
    }
}
