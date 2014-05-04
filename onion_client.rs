use std::io::{MemWriter, MemReader, IoResult};
use crypt::{Key};
use utils::{other_error};

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

}
