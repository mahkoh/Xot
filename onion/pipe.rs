//! The layer handling onion requests and responses.
//!
//! The onion consists of five-step paths connecting two nodes.
//! Every path has three intermediate steps called levels 0, 1, and 2.
//! This means that a complete onion path looks like this:
//! ```
//! - Sender
//! - Level 0
//! - Level 1
//! - Level 2
//! - Receiver
//! ```

use crypt::{PrecomputedKey, Key, Nonce, NONCE};
use std::io::{MemWriter, MemReader, IoResult, standard_error, OtherIoError};
use std::io::net::ip::{SocketAddr};
use utils::{StructWriter, StructReader, CryptoWriter, FiniteReader, SlicableReader,
            Writable, other_error};
use sockets::{UdpWriter};
use keylocker::{Keylocker};
use onion::consts::{LEVEL0_RESPONSE, LEVEL1_RESPONSE, LEVEL2_RESPONSE,
                    LEVEL0_SEND, LEVEL1_SEND, LEVEL2_SEND};

/// Size of return data stored by Level 0. 
static LEVEL0_PRIVATE: uint = 64u;
/// Size of return data stored by Level 1. 
static LEVEL1_PRIVATE: uint = 2u * LEVEL0_PRIVATE;
/// Size of return data stored by Level 2. 
static LEVEL2_PRIVATE: uint = 3u * LEVEL0_PRIVATE;
/// TODO
static PING_ID_TIMEOUT: u64 = 20;

/// A node in the onion network.
pub struct OnionNode {
    /// Our public key generated specifically for this node.
    public: Key,
    /// The key precomputed from the peer's public key and the private key which
    /// corresponds to the public key above.
    encoder: PrecomputedKey,
    /// The address of the node.
    addr: SocketAddr,
}

/// Client to whom we have an onion path.
struct Contact {
    /// The id of the client.
    id: Key,
    /// The addr of the Level 2 part of the return path.
    addr: SocketAddr,
    /// The private data to be send to Level 2.
    private: Vec<u8>,
    data_key: Key,
    timestamp: u64,
}

/// The object running the onion layer.
pub struct Onion {
    udp:       UdpWriter,
    locker:    Keylocker,
    symmetric: Key,
    contacts:  Vec<Contact>,
    secret_bytes: [u8, ..32],
    locker: Keylocker,
}

impl Onion {
    /// Forward a packet if we have the receiver in our contacts.
    fn handle_forward_request(&self, mut data: MemReader) -> IoResult<()> {
        let contact = {
            let dest: Key = try!(data.read_struct());
            match self.contacts.iter().find(|c| c.id == dest) {
                Some(c) => c,
                None => return other_error(),
            }
        };
        if data.remaining() < LEVEL2_PRIVATE {
            return other_error();
        }
        let packet = {
            let mut packet = MemWriter::new();
            try!(packet.write_u8(LEVEL2_RESPONSE));
            try!(packet.write(contact.private));
            try!(packet.write(raw));
            try!(raw.write_u8(ONION_FORWARDED));
            try!(raw.write(data.slice_to_end().initn(LEVEL2_PRIVATE)));
            packet.unwrap()
        };
        self.udp.send_to(contact.addr, packet)
    }

    /// TODO
    fn generate_ping_id(&self, time: u64, key: &Key,
                        addr: SocketAddr) -> IoResult<[u8, ..32]> {
        let mut data = MemWriter::new();
        try!(data.write(self.secret_bytes));
        try!(data.write_be_u64(time / PING_ID_TIMEOUT));
        try!(data.write_struct(key));
        try!(data.write_struct(addr));
        crypt::hash(data.get_ref())
    }

    fn precomputed(&'a mut self, key: &Key) -> &'a PrecomputedKey {
        self.locker.get(key)
    }

    /// Handle a meta request packet.
    ///
    /// So, this packet is by far the most complicated one. As far as I can see, it has
    /// two purposes:
    /// 1 Announcing yourself to a node and sending the node your data_key.
    /// 2 Requesting the data key of another node.
    fn handle_meta_request(&mut self, source: SocketAddr,
                           mut data: MemReader) -> IoResult<()> {
        let (our_key, id, return_path, ping_id, requested_id, data_key, send_back) = {
            let nonce: Nonce = try!(data.read_struct());
            let their_key: Key = try!(data.read_struct());
            let our_key = self.precomputed(&their_key).clone();
            let (mut plain, private) = {
                // These manual checks look error prone. Maybe we can come up with
                // something better.
                if data.remaining() < LEVEL2_PRIVATE {
                    return other_error();
                }
                let data = BufReader::new(data.slice_to_end().initn(LEVEL2_PRIVATE));
                let plain = try!(data.read_encrypted(&our_key.with_nonce(&nonce)));
                let private = data.slice_to_end().lastn(PRIVATE_DATA_LEN);
                (MemReader::new(plain), private)
            };
            let ping_id = try!(plain.read_exact(32));
            let requested_id: Key = try!(plain.read_struct());
            let data_key: Key = try!(plain.read_struct());
            // This is a bit of a waste since we only need a slice but plain is out of
            // scope once we leave this block. Given that send_back will soon be very
            // small, I guess this is ok. Maybe, once the size of send_back is fixed, we
            // can turn this into a stack allocation.
            let send_back = plain.slice_to_end().to_owned();
            (our_key, their_key, return_path, ping_id, requested_id, data_key, send_back)
        };

        let (ping1, ping2) = {
            let time = utils::time::sec();
            let ping1 = self.generate_ping_id(time                  , &id, source);
            let ping2 = self.generate_ping_id(time + PING_ID_TIMEOUT, &id, source);
            (ping1, ping2)
        };

        let index = if ping1 == ping_id || ping2 == ping_id {
            // This branch is case 1
            // First we check if the node is already in the contacts or if we have space
            // to add a new one.
            let pos = match self.contacts.len() {
                MAX_CONTACTS => {
                    self.contacts.iter().position(|e| e.id == id).or_else(|| {
                        self.contacts.iter().position(|e| e.timed_out()).or_else(|| {
                            match self.dht_pub.cmp(&self.contacts.get(0).id, &id) {
                                Greater => Some(0),
                                _       => None,
                            }
                        })
                    })
                },
                _ => {
                    self.contacts.push(Contact::new());
                    Soem(self.contacts.len()-1)
                },
            };
            // If we have a reserved position in the contacts list, we update it with the
            // new data.
            match pos {
                Some(p) => {
                    {
                        let c = &self.contacts[p];
                        c.id        = id;
                        c.addr      = source;
                        c.private   = return_path.to_owned();
                        c.data_key  = data_key;
                        c.timestamp = utils::time::sec();
                    }
                    self.contact.sort_by(|e1, e2| {
                        match (e1.timed_out(), e2.timed_out()) {
                            (true,  true)  => Equal,
                            (false, true)  => Greater,
                            (true,  false) => Less,
                            // dht_pub.cmp returs better < worse, so we interchange the
                            // arguments.
                            (false, false) => self.dht_pub.cmp(&e2.id, &e1.id),
                        }
                    });
                },
                None => { }
            }
            // See the comment in the `index` match further down.
            None
        } else if requested_id == id {
            // It is an unfortunate shortcoming of the protocol that we have to first
            // send our own id as requested_id to the the ping_id back.
            None
        } else {
            // This branch is case 2
            self.contacts.iter().position(|c| c.id == requested_id)
        };

        let encrypted = {
            let only_good = true;
            // For good measure we also send some dht nodes back.
            let nodes = self.dht.get_close(requested_id, source, only_good);

            let mut encrypted = MemWriter::new();
            // If `index` is None, then we're either in case 1 or we haven't found the
            // requested id.
            let (is_data_key, val) = match index {
                None    => (0, ping2),
                Some(i) => (1, entry.data_key.as_slice()),
            };
            try!(encrypted.write_u8(is_data_key));
            try!(encrypted.write(val));
            try!(encrypted.write_struct(&nodes));
            encrypted.unwrap()
        };

        let packet = {
            let nonce = Nonce::random();
            let mut packet = MemWriter::new();
            try!(packet.write_u8(LEVEL2_RESPONSE));
            try!(packet.write(return_path));
            try!(packet.write_u8(ANNOUNCE_RESPONSE));
            try!(packet.write(send_back));
            try!(packet.write_struct(&nonce));
            try!(packet.write_encrypted(&our_key.with_nonce(&nonce)));
            packet.unwrap()
        };

        self.udp.send_to(source, packet.get_ref());
        Ok(())
    }

    /// Send to packet via the path to the final destination `dest`.
    fn send_to_level_0(&self, path: &OnionPath, dest: SocketAddr,
                       data: &[u8]) -> IoResult<()> {
        let nonce = Nonce::random();

        // Stuff that Level 2 is supposed to read.
        let level2 = {
            let mut level2 = MemWriter::new();
            try!(level2.write_struct(&dest));
            try!(level2.write(data));
            level2.unwrap()
        };

        // Stuff that Level 1 is supposed to read.
        let level1 = {
            let mut level1 = MemWriter::new();
            try!(level1.write_struct(&path.nodes[2].addr));
            try!(level1.write_struct(&path.nodes[2].public));
            try!(level1.write_encrypted(&path.nodes[2].encoder.with_nonce(&nonce),
                                        level2.as_slice()));
            level1.unwrap()
        };

        // Stuff that Level 0 is supposed to read.
        let level0 = {
            let mut level0 = MemWriter::new();
            try!(level0.write_struct(&path.nodes[1].addr));
            try!(level0.write_struct(&path.nodes[1].public));
            try!(level0.write_encrypted(&path.nodes[1].encoder.with_nonce(&nonce),
                                        level1.as_slice()));
            level0.unwrap()
        };

        let packet = {
            let mut packet = MemWriter::new();
            try!(packet.write_u8(LEVEL0_SEND));
            try!(packet.write_struct(&nonce));
            try!(packet.write_struct(&path.nodes[0].public));
            try!(packet.write_encrypted(&path.nodes[0].encoder.with_nonce(&nonce),
                                        level_0.get_ref()));
            packet.unwrap()
        };

        self.udp.send_to(path.nodes[0].addr, packet);
        Ok(())
    }

    fn handle_send_common(&mut self, data: &mut MemReader, pdw: uint, pk: bool)
                             -> IoResult<(MemReader, SocketAddr, Option<Key>, Nonce)> {
        let nonce: Nonce = try!(data.read_struct());
        let id: Key = try!(data.read_struct());
        if data.remaining() < pdw {
            return other_error();
        }
        let decrypted = {
            let key = self.precomputed(&id);
            try!(key.with_nonce(&nonce).decrypt(data.slice_to_end().initn(pdw)))
        };
        data.consume(data.remaining() - pdw);
        let mut decrypted = MemReader::new(decrypted);

        let dest: SocketAddr = try!(decrypted.read_struct());
        let pk: Option<Key> = match pk {
            true  => Some(try!(decrypted.read_struct())),
            false => None,
        };

        Ok((decrypted, dest, pk, nonce))
    }

    /// Handle a send packet where we're level 0.
    pub fn handle_send_level_0(&mut self, source: SocketAddr,
                               mut data: MemReader) -> IoResult<()> {
        let (decrypted, dest, pk2, nonce) = {
            let get_public_key = true;
            let private_data_size = 0;
        };

        let packet = {
            let my_nonce = Nonce::random();
            let mut packet = MemWriter::new();
            try!(packet.write_u8(129));
            try!(packet.write_struct(&nonce));
            try!(packet.write_struct(&pk2.unwrap()));
            try!(packet.write(decrypted.slice_to_end()));
            try!(packet.write_struct(&my_nonce));
            try!(packet.write_encrypted(&self.symmetric.with_nonce(&my_nonce),
                                        source.encode().as_slice()));
            packet.unwrap()
        };

        self.udp.send_to(dest, packet.as_slice())
    }

    /// Handle a send packet where we're level 1.
    pub fn handle_send_level_1(&mut self, source: SocketAddr,
                               mut data: MemReader) -> IoResult<()> {
        let (decrypted, dest, pk, nonce) = {
            let get_public_key = true;
            let private_data_size = LEVEL0_PRIVATE;
            try!(self.handle_send_common(&mut data, private_data_size, get_public_key))
        };

        let private = {
            let mut private = MemWriter::new();
            try!(private.write_struct(&source));
            try!(private.write(data.slice_to_end()));
            private.unwrap()
        };

        let packet = {
            let my_nonce = Nonce::random();
            let mut packet = MemWriter::new();
            try!(packet.write_u8(130));
            try!(packet.write_struct(&nonce));
            try!(packet.write_struct(&pk.unwrap()));
            try!(packet.write(decrypted.slice_to_end()));
            try!(packet.write_struct(&my_nonce));
            try!(packet.write_encrypted(&self.symmetric.with_nonce(&my_nonce),
                                        private.as_slice()));
            packet.unwrap()
        };

        self.udp.send_to(dest, packet.as_slice())
    }

    /// Handle a send packet where we're level 2.
    pub fn handle_send_level_2(&mut self, source: SocketAddr,
                               mut data: MemReader) -> IoResult<()> {
        let (decrypted, dest, _, _) = {
            let get_public_key = false;
            let private_data_size = LEVEL1_PRIVATE;
            try!(self.handle_send_common(&mut data, private_data_size, get_public_key))
        };

        let private = {
            let mut private = MemWriter::new();
            try!(private.write_struct(&source));
            try!(private.write(data.slice_to_end()));
            private.unwrap()
        };

        let packet = {
            let my_nonce = Nonce::random();
            let mut packet = MemWriter::new();
            try!(packet.write(decrypted.slice_to_end()));
            try!(packet.write_struct(&my_nonce));
            try!(packet.write_encrypted(&self.symmetric.with_nonce(&my_nonce),
                                        private.as_slice()));
            packet.unwrap()
        };

        self.udp.send_to(dest, packet.as_slice())
    }

    /* this is probably not needed anymore
    pub fn respond(&mut self, dest: SocketAddr, data: &[u8],
                   path: &[u8]) -> IoResult<()> {
        let mut packet = MemWriter::new();
        try!(packet.write_u8(140));
        try!(packet.write(path));
        try!(packet.write(data));

        self.udp.send_to(dest, packet.get_ref())
    }
    */

    pub fn handle_recv_common(&self, data: &mut MemReader, pdw: uint)
                                    -> IoResult<(MemReader, SocketAddr)> {
        if data.remaining() < pdw {
            return other_error();
        }
        let nonce: Nonce = try!(data.read_struct());
        let decrypted = try!(self.symmetric.with_nonce(&nonce).decrypt(
                               data.read_exact(pdw-NONCE).unwrap().as_slice()));
        let mut decrypted = MemReader::new(decrypted);
        let dest: SocketAddr = try!(decrypted.read_struct());

        Ok((decrypted, dest))
    }

    /// Handle a send packet where we're level 2.
    pub fn handle_recv_level_2(&self, mut data: MemReader) -> IoResult<()> {
        let (decrypted, dest) = try!(self.handle_recv_common(&mut data, LEVEL2_PRIVATE));

        let packet = {
            let mut packet = MemWriter::new();
            try!(packet.write_u8(LEVEL1_RESPONSE));
            try!(packet.write(decrypted.slice_to_end()));
            try!(packet.write(data.slice_to_end()));
            packet.unwrap()
        };

        self.udp.send_to(dest, packet.as_slice());
        Ok(())
    }

    /// Handle a send packet where we're level 1.
    pub fn handle_recv_level_1(&self, mut data: MemReader) -> IoResult<()> {
        let (decrypted, dest) = try!(self.handle_recv_common(&mut data, LEVEL1_PRIVATE));

        let packet = {
            let mut packet = MemWriter::new();
            try!(packet.write_u8(LEVEL0_RESPONSE));
            try!(packet.write(decrypted.slice_to_end()));
            try!(packet.write(data.slice_to_end()));
            packet.unwrap()
        };

        self.udp.send_to(dest, packet.as_slice());
        Ok(())
    }

    /// Handle a send packet where we're level 1.
    pub fn handle_recv_level_0(&self, mut data: MemReader) -> IoResult<()> {
        let (_, dest) = try!(self.handle_recv_common(&mut data, LEVEL0_PRIVATE));
        self.udp.send_to(dest, data.slice_to_end());
        Ok(())
    }
}
