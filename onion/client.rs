use std::io::{MemWriter, MemReader, IoResult};
use crypt::{Key};
use utils::{other_error};

static PING_ID_TIMEOUT: u64 = 20;

/// The intemediate steps in an onion request.
pub struct OnionPath {
    nodes: [PathNode, ..3],
    last_success: u64,
    creation: u64,
}

impl OnionPath {
    fn new(raw: [Node, ..3], dht_pub: &Key, dht_priv: &SecretKey) -> OnionPath {
        let pub0 = dht_pub.clone();
        let (priv1, pub1) = crypt::key_pair();
        let (priv2, pub2) = crypt::key_pair();

        let enc0 = PrecomputedKey::new(&dht_priv, &raw[0].id);
        let enc1 = PrecomputedKey::new(&priv1,    &raw[1].id);
        let enc2 = PrecomputedKey::new(&priv2,    &raw[2].id);

        let node0 = OnionNode { public: pub0, encoder: enc0, addr: raw[0].addr };
        let node1 = OnionNode { public: pub1, encoder: enc1, addr: raw[1].addr };
        let node2 = OnionNode { public: pub2, encoder: enc2, addr: raw[2].addr };

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

struct OnionPaths {
    paths: Vec<OnionPath>,
}

impl OnionPaths {
    fn random<'a>(&'a mut self, num: Option<uint>) -> Result<&'a OnionPath, ()> {
        match paths.len() {
            MAX_ONION_PATHS => {
                let n = match num {
                    Some(n) => n % MAX_ONION_PATHS,
                    None    => task_rng().range(0, MAX_ONION_PATHS),
                };
                if self.paths[n].should_replace() {
                    let nodes = try!(self.dht.random_path());
                    self.paths[n] = OnionPath::new(nodes);
                }
                Ok(&self.paths[n])
            },
            _ => {
                let nodes = try!(self.dht.random_path());
                self.paths.push(OnionPath::new(nodes));
                let n = self.paths.len() - 1;
                Ok(&self.paths[n])
            },
        }
    }

    fn set_timeouts(&mut self, addr: SocketAddr) -> Option<uint> {
        for (i, path) in self.paths.mut_iter().enumerate() {
            if path.nodes[0].addr == addr {
                path.last_success = utils::time::sec();
                return Some(i);
            }
        }
        None;
    }
}

static PING_ID: uint = 32u;

struct Node {
    id: Key,
    addr: SocketAddr,
    timestamp: u64,
    last_pinged: u64,
    path_used: uint,
    data_key: Option<Key>,
    ping_id: [u8, ..32],
}

struct Friend {
    is_online:      bool,
    nodes:          Vec<Node>,
    real_id:        Key,
    id:             Option<uint>,
    fake_id:        Option<Key>,
    tmp_public:     Key,
    tmp_private:    SecretKey,
    paths:          OnionPaths,
    last_no_replay: u64,
    last_seen:      u64,
}

impl Friend {
    fn set_online(&mut self, online: bool) {
        if self.is_online && !online {
            self.last_seen = utils::time::sec();
        }
        self.is_online = online;
        if !online {
            self.last_no_replay = utils::time::sec();
        }
    }

    fn is_kill(&self) -> bool {
        self.last_seen + DEAD_ONION_TIMEOUT < utils::time::sec()
    }

    fn send_announce_request(&mut self, dest: Choice<&Node, uint>,
                             ping_id: Option<&[u8, ..PING_ID]>, path_num: Option<u32>,
                             pipe: &PipeControl, symmetric: &Key,
                             data_public: &Key) -> IoResult<()> {
        // Let's do this first because all those other try!s probably won't fail.
        let path = try!(self.paths.random_path());

        let (dest_addr, dest_id) = match dest {
            One(d) => (d.addr, &d.id),
            Two(i) => {
                let node = &self.nodes[i];
                (node.addr, &node.real_id)
            },
        };

        let send_back = {
            let nonce = Nonce::random();

            let private = MemWriter::new();
            match self.id {
                Some(n) => try!(private.write_be_u32(n+1)),
                None    => try!(private.write_be_u32(0)),
            };
            try!(private.write_be_u64(utils::time::sec()));
            try!(private.write_struct(&dest_id));
            try!(private.write_struct(&dest_addr));

            let send_back = MemWriter::new();
            try!(send_back.write_struct(&nonce));
            try!(send_back.write_encrypted(&symmetric.with_nonce(&nonce),
                                           private.get_ref()));
            send_back.unwrap()
        };

        let plain = {
            let mut plain = MemWriter::new();
            match ping_id {
                Some(p) => try!(plain.write(p)),
                None => try!(plain.write([0u8, ..PING_ID])),
            }
            try!(plain.write(self.real_id));
            match self.id.is_none() {
                true  => try!(plain.write_struct(data_public)),
                false => try!(plain.write([0u8, ..KEY])),
            }
            try!(plain.write(send_back));
            plain.unwrap()
        };

        let packet = {
            let nonce = Nonce::random();
            let mut packet = MemWriter::new();
            try!(packet.write_u8(ANNOUNCE_REQUEST));
            try!(packet.write_struct(&nonce));
            try!(packet.write_struct(self.tmp_public));
            {
                let machine =
                    PrecomputedKey::new(self.tmp_private, dest_id).with_nonce(&nonce);
                try!(packet.write_encrypted(&machine, plain.get_ref()));
            }
            packet.unwrap()
        };

        pipe.send(path, dest_addr, packet.get_ref());

        self.last_pinged.push(Ping { id: node.id, timestamp: utils::time::sec() });
        self.ping_nodes_second += 1;
    }

    fn send_onion_data(&self, data: &[u8], my_pub: &Key, my_priv: &SecretKey,
                       dht: &DHTControl) -> IoResult<()> {
        let paths = Vec::new();
        let total_nodes = 0u;
        for (i, node) in self.nodes.iter() {
            if node.timed_out() {
                continue;
            }
            total_nodes += 1;
            if node.data_key.is_some() {
                match self.paths.random(&dht, None) {
                    Ok(p) => paths.push((i, p.clone())),
                    Err(_) => { },
                }
            }
        }
        if ids.len() < (total_nodes / 4) + 1 {
            return other_error();
        }

        let nonce = Nonce::random();
        let encrypted = {
            let machine = PrecomputedKey::new(my_priv, self.real_id).with_nonce(&nonce);
            let mut encrypted = MemWriter::new();
            try!(encrypted.write_struct(my_pub));
            try!(encrypted.write_encrypted(&machine, data));
            encrypted.unwrap()
        };

        for (i, path) in paths.iter() {
            let (rand_priv, rand_pub) = key_pair();
            let node = self.nodes.get(i);
            let machine =
              PrecomputedKey::new(&rand_priv, &node.data_key.unwrap()).with_nonce(&nonce);

            let mut packet = MemWriter::new();
            try!(packet.write_u8(ONION_DATA_REQUEST));
            try!(packet.write_struct(&public));
            try!(packet.write_struct(&nonce));
            try!(packet.write_struct(&rand_pub));
            try!(packet.write_encrypted(&machine, encrypted));

            self.pipe.send(path, node.addr, packet.unwrap());
        }
        Ok(())
    }

    fn do_myself(&mut self, dht: &DHTControl, symmetric: &Key, data_key: &Key,
                 pipe: &PipeControl) {
        let count = 0u;
        for i in range(0, self.nodes.len()) {
            if self.nodes[i].timed_out() {
                continue;
            }
            count += 1;
            if self.nodes[i].last_pinged == 0 {
                self.nodes[i].last_pinged = 1;
                continue;
            }
            let interval = match self.nodes[i].data_key {
                Some(_) => ANNOUNCE_INTERVAL_NOT_ANNOUNCED,
                None    => ANNOUNCE_INTERVAL_ANNOUNCED,
            };
            if self.nodes[i].last_pinged + interval > utils::time::sec() {
                let path_id = None;
                self.send_announce_request(Two(i), path_id, pipe, symmetric,
                                           data_public);
            }
        }
        if count <= task_rng().range(0, MAX_ONION_CLIENTS) {
            let is_lan = 1;
            let want_good = false;
            let kind = task_rng().choose([AF_INET, AF_INET6]);
            let nodes = dht.get_close(self.crypto_public, kind, is_lan, want_good);
            for node in nodes.iter() {
                let ping_id = None;
                let path_num = None;
                self.send_announce_request(One(node), ping_id, path_num, pipe, symmetric,
                                           data_public);
            }
        }
    }

    fn do_friend(&mut self, dht: &DHTControl, symmetric: &Key, pipe: &PipeControl) {
        if self.is_online {
            return;
        }
        let count = 0u;
        for i in range(0, self.nodes.len()) {
            if self.nodes[i].timed_out() {
                continue;
            }
            count += 1;
            if self.nodes[i].should_ping() {
                let path_id = None;
                self.send_announce_request(Two(i), path_id, pipe, symmetric,
                                           &self.id);
                self.nodes[i].last_pinged = utils::time::sec();
            }
        }
        if count != MAX_ONION_CLIENTS && count < task_rng().range(0, MAX_ONION_CLIENTS) {
            let is_lan = 1;
            let want_good = false;
            let kind = task_rng().choose([AF_INET, AF_INET6]);
            let nodes = dht.get_close(self.crypto_public, kind, is_lan, want_good);
            for node in nodes.iter() {
                let ping_id = None;
                let path_num = None;
                self.send_announce_request(One(node), ping_id, path_num, pipe, symmetric,
                                           &self.id);
            }
        }
        if self.should_send_onion_fake_id() {
            let dht_instead_of_onion = false;
            self.send_fake_id(dht_instead_of_onion);
        }
        if self.should_send_dht_fake_id() {
            let dht_instead_of_onion = true;
            self.send_fake_id(dht_instead_of_onion);
        }
    }

    fn should_send_onion_fake_id(&self) -> bool {
        self.last_onion_fake_id + ONION_FAKE_ID_INTERVAL < utils::time::sec()
    }

    fn should_send_dht_fake_id(&self) -> bool {
        self.last_dht_fake_id + DHT_FAKE_ID_INTERVAL < utils::time::sec()
    }

    fn send_fake_id(&self, dht_instead_of_onion: bool) -> IoResult<()> {
        let packet = {
            let close_nodes = self.dht.close_nodes();
            let mut packet = MemWriter::new();
            try!(packet.write_u8(FAKE_ID));
            try!(packet.write_be_u64(utils::time::sec()));
            try!(packet.write_struct(dht_pub));
            try!(packet.write_struct(close_nodes));
            packet.unwrap()
        };
        if dht_instead_of_onion {
            self.send_dht_fake_id(packet, cypto_public, crypto_private, dht)
        } else {
            self.send_onion_data(packet, cypto_public, crypto_private, dht)
        }
    }

    fn send_dht_fake_id(&self, public: &Key, private: &SecretKey,
                        data: &[u8]) -> IoResult<()> {
        let encrypted = {
            let nonce = Nonce::random();
            let mut encrypted = MemWriter::new();
            try!(encrypted.write_struct(public));
            try!(encrypted.write_struct(&nonce));
            let machine = PrecomputedKey::new(private, &self.real_id).with_nonce(&nonce);
            try!(encrypted.write_encrypted(&nonce, data));
            encrypted.unwrap()
        };

        let packet = {
            let nonce = Nonce::random();
            let mut tmp = MemWriter::new();
            try!(tmp.write_u8(FAKE_ID));
            try!(tmy.write(encrypted));

            let machine = PrecomputedKey::New(dht_priv, &self.real_id).with_nonce(&nonce);
            let mut packet = MemWriter::new();
            try!(packet.write_u8(PACKET_CRYPTO));
            try!(packet.write_struct(&self.fake_id.unwrap()));
            try!(packet.write_struct(dht_pub));
            try!(packet.write_struct(&nonce));
            try!(packet.write_encrypted(&nonce, tmp.get_ref()));
            packet.unwrap()
        };

        self.dht.route_to_friend(self.fake_id.unwrap(), packet);
        Ok(())
    }
}

struct Client {
    friends:     Vec<Friend>,
    tmp_public:  Key,
    tmp_private: SecretKey,
    symmetric:   SecretKey,
}

impl Client {
    // at most once per second
    fn do_client(&mut self) {
        self.myself.do_myself();
        self.do_friends();
    }

    fn do_friends(&mut self) {
        for friend in self.friends.iter() {
            friend.do_friend(&self.dht, &self.symmetric, &self.pipe);
            if friend.fake_id.is_some() && !friend.is_online && friend.is_kill() {
                self.dht.del_friend(friend.fake_id.as_ref().unwrap());
                friend.fake_id = None;
            }
        }
    }

    fn send_friend_request(&self, id: &Key, nospam: [u8, ..4],
                           msg: &[u8]) -> IoResult<()> {
        let mut packet = MemWriter::new();
        try!(packet.write_u8(CRYPTO_PACKET_FRIEND_REQ));
        try!(packet.write(nospam));
        try!(packet.write(msg));
        self.send_data(id, packet.unwrap())
    }

    fn handle_friend_request(&self, source: &Key,
                             mut data: MemReader) -> IoResult<()> {
        let nospam = try!(data.read_exact(4));
        if nospam.as_slice() != self.nospam {
            return other_error();
        }
        let msg: ~str = try!(data.read_struct());
        self.messenger.on_friend_request(source, msg);
        Ok(())
    }


    fn handle_data_request(&self, source: SocketAddr,
                           mut data: MemReader) -> IoResult<()> {
    }

    fn handle_announce_response(&self, source: SocketAddr,
                                mut data: MemReader) -> IoResult<()> {
        /////
        // PART 1: Read the send-back-data.
        /////

        let (num, addr, id) = {
            let send_back = BufReader::new(data.slice_to_end().slice(0, 108));
            let nonce: Nonce = try!(send_back.read_struct());
            let private =
                self.symmetric.with_nonce(&nonce).decrypt(send_back.slice_to_end());
            let private = match private {
                Some(p) => MemReader::new(p),
                None => return other_error(),
            };
            let num = match try!(private.read_be_u32()) {
                0 => None,
                n => Some(n-1),
            };
            let time = try!(private.read_be_u64());
            let id: Key = try!(private.read_struct());
            let addr: SocketAddr = try!(private.read_struct());

            let now = utils::time::sec();
            if time + ANNOUNCE_TIMEOUT < now || now < time {
                return other_error();
            }
            (num, addr, id)
        };

        /////
        // PART 2: Decrypt the nodes.
        /////

        let decrypted = {
            let nonce: Nonce = try!(data.read_struct());
            let friend = match num {
                Some(n) => try!(self.get_friend(n)),
                None => self.myself,
            };
            let machine =
                PrecomputedKey::new(&friend.tmp_private, &id).with_nonce(&nonce);
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
            Some(n) => try!(self.get_friend(n)),
            None => {
                if is_data_key && self.myself.data_key != ping_id_or_data_key {
                    is_data_key = false;
                }
                &mut self.myself
            },
        };
        // Sort worst --> best.
        friend.list_nodes.sort_by(|n1,n2| {
            match (n1.timed_out(), n2.timed_out()) {
                (true,  true)  => Equal,
                (false, true)  => Greater,
                (true,  false) => Less,
                // real_id.cmp returs better < worse, so we interchange the arguments.
                (false, false) => friend.real_id.cmp(&n2.id, &n1.id),
            }
        });
        // Store some info for use further down. This isn't perfect but good enough for
        // now.
        let furthest_away: Option<Key>;
        let has_timed_out = true;
        // We need a spot to store the respondee in. If the list is already filled, we try
        // to find a node which is worse. If the list isn't full, we simply add a new node
        // to it.
        let index = match friend.list_nodes.len() {
            MAX_CLIENTS => {
                let index = {
                    let node = friend.list_nodes.get(0);
                    // See comment above.
                    has_timed_out = node.timed_out();
                    furthest_away = Some(node.id);
                    match has_timed_out || friend.real_id.cmp(node.id, id) == Greater {
                        true => Some(0),
                        false => None,
                    }
                };
                for (i, node) in friend.list_nodes.enumerate() {
                    if node.id == id {
                        index = Some(i);
                        break;
                    }
                }
                index
            },
            _ => {
                friend.list_nodes.push(Node::new());
                Some(friend.list_nodes.len()-1)
            },
        };
        match index {
            Some(i) => {
                let node = friend.list_node.get(i);
                node.id = id;
                node.addr = addr;
                node.timestamp = utils::time::sec();
                node.lost_pinged = utils::time::sec();
                node.path_used = friend.paths.set_timeouts(source);
                match stored {
                    true => node.data_public = Some(ping_id_or_data_key),
                    false => node.ping_id = *ping_id_or_data_key.raw(),
                }
            },
            None => { }
        }

        /////
        // PART 4: Send announce requests to all the new nodes we received.
        /////

        // Remove all timed out pings.
        friend.last_pinged.remove_while(|p| p.timed_out());

        let lan_ok = source.is_lan();
        for node in nodes.iter() {
            if friend.ping_nodes_second > MAX_PING_NODES_SECOND {
                break;
            }
            if !lan_ok && node.addr.is_lan() {
                continue;
            }
            // Don't send a request if the list is already good.
            if !has_timed_out && furthest_away.is_some() {
                let furthest_away = furthest_away.as_ref().unwrap();
                if friend.real_id.cmp(furthest_away.id, node.id) == Less {
                    continue;
                }
            }
            // Don't ping if the list already contains the node.
            if friend.list_nodes.any(|n| n.id == node.id) {
                continue;
            }
            // Don't ping if we're already pinging.
            if friend.last_pinged.len() == MAX_STORED_PINGED_NODES {
                if friend.last_pinged.iter().any(|p| p.id == node.id) {
                    continue;
                }
            }
            friend.send_announce_request(&node, None, None, &self.pipe, &self.symmetric,
                                         &self.data_public);
        }

        Ok(())
    }


    fn handle_forwarded(&self, source: SocketAddr, mut data: MemReader) -> IoResult<()> {
        let nonce: Nonce = try!(data.read_struct());

        let encrypted = {
            let key: Key = try!(data.read_struct());
            let machine = Precomputed::new(&self.tmp_private, &key).with_nonce(&nonce);
            MemReader::new(try!(data.read_encrypted(&machine)))
        };
        let key: Key = try!(encrypted.read_struct());

        let encrypted = {
            let machine = Precomputed::new(&self.crypto_private, &key).with_nonce(&nonce);
            MemReader::new(try!(encrypted.read_encrypted(&machine)))
        };
        match try!(encypted.read_u8()) {
            FAKE_ID => self.handle_fake_id(&key, encrypted),
            FRIEND_REQUEST => { /* ... */ },
        }
    }

    fn handle_dht_fake_id(&self, source: &Key, mut data: MemReader) -> IoResult<()> {
        let key: Key = try!(data.read_struct());
        let mut data = {
            let nonce: Nonce = try!(data.read_struct());
            let machine = PrecomputedKey::new(&self.crypto_key, &key).with_nonce(&nonce);
            let data = try!(data.read_encrypted(&machine));
            MemReader::new(data)
        };
        if key != *source {
            return other_error();
        }
        self.handle_fake_id(&key, data)
    }

    fn handle_fake_id(&self, id: &Key, mut data: MemReader) -> IoResult<()> {
        let friend = match self.find_friend(id) {
            Some(f) => f,
            None => return other_error(),
        };
        {
            let no_replay = try!(data.read_be_u64(data));
            match no_replay <= friend.last_no_replay {
                true => return other_error(),
                false => friend.last_no_replay = no_replay,
            }
        }
        {
            let fake_id: Key = try!(data.read_struct());
            match friend.fake_id {
                Some(id) => if fake_id != id {
                    self.dht.refresh_friend(&id, &fake_id);
                    friend.last_seen = utils::time::sec();
                },
                None => self.dht.add_friend(&fake_id),
            }
            friend.fake_id = Some(fake_id);
        }
        let nodes: Vec<Node> = try!(data.read_struct());
        self.dht.get_all_nodes(nodes, friend.fake_id.unwrap());
        Ok(())
    }
}
