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
    nodes: Vec<Node>,
    real_id: Key,
    id: Option<uint>,
    tmp_public: Key,
    tmp_private: SecretKey,
    paths: OnionPaths,
}

impl Friend {
    fn send_announce_request(&mut self, dest: &Node, ping_id: Option<&[u8, ..PING_ID]>,
                             path_num: Option<u32>, pipe: &PipeControl,
                             symmetric: &Key, data_public: &Key) -> IoResult<()> {
        // Let's do this first because all those other try!s probably won't fail.
        let path = try!(self.paths.random_path());

        let send_back = {
            let nonce = Nonce::random();

            let private = MemWriter::new();
            match self.id {
                Some(n) => try!(private.write_be_u32(n+1)),
                None    => try!(private.write_be_u32(0)),
            };
            try!(private.write_be_u64(utils::time::sec()));
            try!(private.write_struct(&dest.id));
            try!(private.write_struct(&dest.addr));

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
                None => try!(plain.write([0u8, ..32])),
            }
            // this is wrong. What is self.id supposed to be?
            try!(plain.write(self.id));
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
                    PrecomputedKey::new(self.tmp_private, dest.id).with_nonce(&nonce);
                try!(packet.write_encrypted(&machine, plain.get_ref()));
            }
            packet.unwrap()
        };

        pipe.send(path, dest.addr, packet.get_ref());

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

            self.send(path, node.addr, packet.unwrap());
        }
        Ok(())
    }
}

struct Client;

impl Client {
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

    fn handle_announce_request(&self, source: SocketAddr,
                               mut data: MemReader) -> IoResult<()> {
        let (our_key, public, return_path, ping_id, clint_id, data_public, send_back) = {
            let PRIVATE_DATA_LEN = 192;
            let nonce: Nonce = try!(data.read_struct());
            let their_key: Key = try!(data.read_struct());
            let our_key = self.precomputed(&their_key).clone();
            let mut plain = {
                if data.remaining() < PRIVATE_DATA_LEN {
                    return other_error();
                }
                let data = BufReader::new(data.slice_to_end().initn(PRIVATE_DATA_LEN));
                let plain = try!(data.read_encrypted(&our_key.with_nonce(&nonce)));
                MemReader::new(plain)
            };
            let return_path = data.slice_to_end().lastn(PRIVATE_DATA_LEN);
            let ping_id = try!(plain.read_exact(32));
            let client_id: Key = try!(plain.read_struct());
            let data_public: Key = try!(plain.read_struct());
            // This is a bit of a waste since we only need a slice but plain is out of
            // scope once we leave this block. Given that send_back will soon be very
            // small, I guess this is ok. Maybe, once the size of send_back is fixed, we
            // can turn this into a stack allocation.
            let send_back = plain.slice_to_end().to_owned();
            (our_key, their_key, return_path, ping_id, client_id, data_public, send_back)
        };

        let (ping1, ping2) = {
            let time = utils::time::sec();
            let ping1 = self.generate_ping_id(time                  , &public, source);
            let ping2 = self.generate_ping_id(time + PING_ID_TIMEOUT, &public, source);
            (ping1, ping2)
        };

        let index = if ping1 == ping_id || ping2 == ping_id {
            /////
            // Add a new entry if possible or update the old one.
            /////
            let pos = match self.entries.len() {
                MAX_ENTRIES => {
                    match self.in_entries(&public) {
                        Some(p) => Some(p),
                        None => {
                            match self.entries.iter().position(|e| e.timed_out()) {
                                Some(p) => Some(p),
                                None => {
                                    match self.dht_pub.cmp(&self.entries[0].id, &public) {
                                        Greater => Some(0),
                                        _ => None,
                                    }
                                },
                            }
                        },
                    }
                },
                _ => {
                    self.entries.push(Entry::new());
                    Soem(self.entries.len()-1)
                },
            };
            match pos {
                Some(p) => {
                    {
                        let e = &self.entries[p];
                        e.public = *public;
                        e.ret_addr = source;
                        e.ret = return_path.to_owned();
                        e.data_public = data_public;
                        e.time = utils::time::sec();
                    }
                    self.entries.sort_by(|e1, e2| {
                        match (e1.timed_out(), e2.timed_out()) {
                            (true,  true)  => Equal,
                            (false, true)  => Greater,
                            (true,  false) => Less,
                            // real_id.cmp returs better < worse, so we interchange the
                            // arguments.
                            (false, false) => self.dht_pub.cmp(&e2.id, &e1.id),
                        }
                    });
                },
                None => { }
            }
            pos
        } else {
            self.in_entries(client_id)
        };

        let encrypted = {
            let only_good = true;
            let nodes = self.dht.get_close(client_id, source, only_good);

            let mut encrypted = MemWriter::new();
            if index == -1 {
                try!(encrypted.write_u8(0));
                try!(encrypted.write(ping2));
            } else {
                let entry = &self.entries[index];
                if entry.public == public && entry.data_public == data_public {
                    try!(encrypted.write_u8(0));
                    try!(encrypted.write(ping2));
                } else {
                    try!(encrypted.write_u8(1));
                    try!(encrypted.write(entry.data_public));
                }
            }
            try!(encrypted.write_struct(nodes));
            encrypted.unwrap()
        };

        let packet = {
            let nonce = Nonce::random();
            let mut packet = MemWriter::new();
            try!(packet.write_u8(ANNOUNCE_RESPONSE));
            try!(packet.write(send_back));
            try!(packet.write_struct(&nonce));
            try!(packet.write_encrypted(&our_key.with_nonce(&nonce)));
            packet.unwrap()
        };

        self.pipe.send_response(source, packet, return_path);
        Ok(())
    }

    fn handle_data_request(&self, source: SocketAddr,
                           mut data: MemReader) -> IoResult<()> {
    }

    fn generate_ping_id(&self, time: u64, public: &Key, addr: SocketAddr) -> [u8, ..32] {
        let mut data = MemWriter::new();
        let _ = data.write(self.secret_bytes);
        let _ = data.write_be_u64(time / PING_ID_TIMEOUT);
        let _ = data.write_struct(public);
        let _ = data.write_struct(addr);
        crypt::hash(time.get_ref())
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
                if is_data_key && self.myself.tmp_public != ping_id_or_data_key {
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

    fn do_annonnce(&mut self) {
        let count = 0u;
        for node in self.myself.nodes.mut_iter() {
            if node.timed_out() {
                continue;
            }
            count += 1;
            if node.last_pinged == 0 {
                node.last_pinged = 1;
                continue;
            }
            let interval = match self.data_key {
                Some(_) => ANNOUNCE_INTERVAL_NOT_ANNOUNCED,
                None => ANNOUNCE_INTERVAL_ANNOUNCED,
            };
            if node.last_pinged + interval >= utils::time::sec() {
                let path_id = None;
                // Obviously this doesn't work because myself is already borrowed mutably.
                self.myself.send_announce_request(node.ip_port, node.ping_id, path_id,
                                                  &self.pipe, &self.symmetric,
                                                  &self.data_public);
            }
        }
        if count != MAX_ONION_CLIENTS && count < task_rng().range(0, MAX_ONION_CLIENTS) {
            let is_lan = 1;
            let want_good = false;
            let nodes
                = self.dht.get_close(self.crypto_public, AF_INET, is_lan, want_good);
            for node in nodes {
                self.myself.send_annonce_request(&node, None, None, &self.pipe,
                                                 &self.symmetric, &self.data_public);
            }
        }
    }
}
