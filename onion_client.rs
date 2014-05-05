use std::io::{MemWriter, MemReader, IoResult};
use crypt::{Key};
use utils::{other_error};

static PING_ID_TIMEOUT: u64 = 20;

/// The intemediate steps in an onion request.
pub struct OnionPath {
    nodes: [OnionNode, ..3],
    last_success: u64,
    creation: u64,
}

impl OnionPath {
    fn new(raw: [Node, ..3], dht_pub: &Key, dht_priv: &Key) -> OnionPath {
        let pub0 = dht_pub.clone();
        let (priv1, pub1) = crypt::key_pair();
        let (priv2, pub2) = crypt::key_pair();

        let enc0 = PrecomputedKey::new(dht_priv, raw[0].id);
        let enc1 = PrecomputedKey::new(priv1,    raw[1].id);
        let enc2 = PrecomputedKey::new(priv2,    raw[2].id);

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
    fn random_path<'a>(&'a self, id: &Key, num: uint) -> Result<&'a OnionPath, ()> {
        if paths.len() == MAX_ONION_PATHS {
            if num >= MAX_ONION_PATHS {
                num = task_rng().range(0, self.num_paths);
            }
            if self.paths[num].should_replace() {
                let nodes = try!(self.dht.random_path());
                self.paths[num] = OnionPath::new(nodes);
            }
        } else {
            let nodes = try!(self.dht.random_path());
            self.paths.push(OnionPath::new(nodes));
            num = self.paths.len() - 1;
        }
        &self.paths[num]
    }

    fn set_timeouts(&mut self, addr: SocketAddr) {
        for path in self.paths.mut_iter() {
            if path.nodes[0].addr == addr {
                path.last_success = utils::time::sec();
                return;
            }
        }
    }
}

struct OnionClient;

impl OnionClient {
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

    fn send_announce_request(&self, path: ~OnionPath, dest: Node, public: &Key,
                             private: &Key, ping_id: &[u8], client_id: &Key,
                             data_public_key: &Key, send_back: &[u8]) -> IoResult<()> {
        let mut plain = MemWriter::new();
        try!(plain.write(ping_id));
        try!(plain.write(client_id));
        try!(plain.write(data_public_key));
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

        self.send(path, dest.addr, packet.get_ref());
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
        let data_public_key: Key = try!(plain.read_struct());
        let send_back = plain.slice_to_end();

        let time = utils::time::sec();
        let ping1 = self.generate_ping_id(time                  , &public, source);
        let ping2 = self.generate_ping_id(time + PING_ID_TIMEOUT, &public, source);

        let index = if ping1.as_slice() == ping_id || ping2.as_slice() == ping_id {
            self.add_to_entries(source, &public, &data_public_key, return_path)
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
            if entry.public == public && entry.data_public == data_public_key {
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

    fn send_data_request(&self, path: ~OnionPath, dest: SocketAddr, public: &Key,
                         encrypt_public: &Key, nonce: &Nonce,
                         data: &[u8]) -> IoResult<()> {
        let (rand_priv, rand_pub) = key_pair();
        let machin = PrecomputedKey::new(rand_priv, encrypt_public).with_nonce(nonce);

        let mut packet = MemWriter::new();
        try!(packet.write_u8(ONION_DATA_REQUEST));
        try!(packet.write_struct(public));
        try!(packet.write_struct(nonce));
        try!(packet.write_struct(&rand_pub));
        try!(packet.write_encrypted(&machin, data));

        self.send(path, dest, packet.unwrap());
    }

    fn handle_announce_response(&self, source: SocketAddr,
                                mut data: MemReader) -> IoResult<()> {
    }

}
