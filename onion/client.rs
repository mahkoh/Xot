use std::io::{MemWriter, MemReader, IoResult};
use crypt::{Key};
use utils::{other_error};

static PING_ID_TIMEOUT: u64 = 20;

/// The intemediate steps in an onion request.
pub struct OnionPath {
    nodes: [Node, ..3],
    last_success: u64,
    creation: u64,
}

impl OnionPath {
    fn new(raw: [Node, ..3], dht_pub: &Key, dht_priv: &Key) -> OnionPath {
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
        self.last_success + PATH_TIMEOUT < now ||
            self.creation + PATH_MAX_LIFETIME < now
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

struct Friend;

impl Friend {
    fn send_announce_request(&self, dest: &Node, ping_id: Option<&[u8, ..PING_ID]>,
                             path_num: u32, pipe: &PipeControl,
                             symmetric: &Key, data_public: &Key) -> IoResult<()> {
        // Let's do this first because all those other try!s probably won't fail.
        let path = try!(self.paths.random_path());

        let send_back = {
            let nonce = Nonce::random();

            let private = MemWriter::new();
            match self.id() {
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
            try!(plain.write(self.id));
            match self.id().is_none() {
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

        friend.last_pinged.push(Ping { id: node.id, timestamp: utils::time::sec() });
        friend.ping_nodes_second += 1;
    }

    fn send_onion_data(&self, data: &[u8], my_pub: &Key, my_priv: &SecretKey,
                       dht: &DHTControl) -> IoResult<()> {
        let paths = Vec::new();
        let total_nodes = 0u;
        for (i, node) in self.list_nodes.iter() {
            if node.timed_out() {
                continue;
            }
            total_nodes += 1;
            if node.stored {
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
                PrecomputedKey::new(&rand_priv, &node.data_public).with_nonce(&nonce);

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

    fn send_announce_request(&self, num: Option<u32>, dest: &Node, ping_id: Option<&[u8]>,
                             path_num: u32) -> IoResult<()> {
        let send_back = {
            let nonce = Nonce::random();

            let private = MemWriter::new();
            match num {
                Some(n) => try!(private.write_be_u32(n+1)),
                None    => try!(private.write_be_u32(0)),
            };
            try!(private.write_be_u64(utils::time::sec()));
            try!(private.write_struct(&dest.id));
            try!(private.write_struct(&dest.addr));

            let send_back = MemWriter::new();
            try!(send_back.write_struct(&nonce));
            try!(send_back.write_encrypted(&self.symmetric.with_nonce(&nonce),
                                           private.get_ref()));
            send_back.unwrap()
        };

        match num {
            None => {
                let path = try!(self.my_paths.random_path());
                Client::send_announce_request_inner(
                    self.pipe, path, dest, &self.dht_public, &self.dht_private,
                    ping_id, &self.dht_public, &self.tmp_public, send_back);
            },
            Some(n) => {
                let friend = self.friends.get(n);
                let path = try!(friend.paths.random_path());
                let zero_id = Key([0u8, ..32]);
                Client::send_announce_request_inner(
                    &self.pipe, path, dest, &friend.tmp_public, &friend.tmp_private,
                    ping_id, &friend.id, &zero_id, send_back);
            }
        }
    }

    fn send_announce_request_inner(pipe: PipeControl, path: ~OnionPath, dest: &Node,
                                   public: &Key, private: &Key, ping_id: Option<&[u8]>,
                                   client_id: &Key, data_public: &Key,
                                   send_back: &[u8]) -> IoResult<()> {
        let mut plain = MemWriter::new();
        match ping_id {
            Some(p) => try!(plain.write(p)),
            None => try!(plain.write([0u8, ..32])),
        }
        try!(plain.write(client_id));
        try!(plain.write(data_public));
        try!(plain.write(send_back));

        let nonce = Nonce::random();
        let mut packet = MemWriter::new();
        try!(packet.write_u8(ANNOUNCE_REQUEST));
        try!(packet.write_struct(&nonce));
        try!(packet.write_struct(public));
        {
            let machine = PrecomputedKey::new(private, dest.id).with_nonce(&nonce);
            try!(packet.write_encrypted(&machine, plain.get_ref()));
        }

        pipe.send(path, dest.addr, packet.get_ref());
    }

    fn handle_announce_request(&self, source: SocketAddr,
                               mut data: MemReader) -> IoResult<()> {
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
        let send_back = plain.slice_to_end();

        let time = utils::time::sec();
        let ping1 = self.generate_ping_id(time                  , &public, source);
        let ping2 = self.generate_ping_id(time + PING_ID_TIMEOUT, &public, source);

        let index = if ping1.as_slice() == ping_id || ping2.as_slice() == ping_id {
            self.add_to_entries(source, &public, &data_public, return_path)
        } else {
            self.in_entries(client_id)
        };

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

        let nonce = Nonce::random();
        let mut packet = MemWriter::new();
        try!(packet.write_u8(ANNOUNCE_RESPONSE));
        try!(packet.write(send_back));
        try!(packet.write_struct(&nonce));
        try!(packet.write_encrypted(&our_key.with_nonce(&nonce)));

        self.respond(source, packet, return_path);
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

        let stored = try!(decrypted.read_u8()) != 0;
        let ping_id_or_key: Key = try!(decrypted.read_struct());
        let nodes: Vec<Node> = try!(decrypted.read_struct());

        /////
        // PART 3: Store the respondee in the nodes list (if possible).
        /////

        let friend = match num {
            Some(n) => try!(self.get_friend(n)),
            None => {
                if stored && self.myself.tmp_public != ping_id_or_key {
                    stored = 0;
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
                node.stored = stored;
                node.timestamp = utils::time::sec();
                node.lost_pinged = utils::time::sec();
                node.path_used = friend.paths.set_timeouts(source);
                match stored {
                    true => node.data_public = ping_id_or_key,
                    false => node.ping_id = *ping_id_or_key.raw(),
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
            friend.send_announce_request(node.addr, node.id, None, None);
        }

        Ok(())
    }
}
