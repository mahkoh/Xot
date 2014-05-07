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

struct Contact {
    id: Key,
    ret_addr: SocketAddr,
    ret: Vec<u8>,
}

/// The object running the onion layer.
pub struct Onion {
    udp:       UdpWriter,
    locker:    Keylocker,
    symmetric: Key,
    contacts:  Vec<Contact>,
    secret_bytes: [u8, ..32],
}

impl Onion {
    fn handle_forward_request(&self, source: SocketAddr,
                              mut data: MemReader) -> IoResult<()> {
        let contact = {
            let dest: Key = try!(data.read_struct());
            try!(self.find_contact(&dest))
        };
        if data.remaining() < 192 {
            return other_error();
        }
        let packet = {
            let mut packet = MemWriter::new();
            try!(packet.write_u8(ONION_FORWARDED));
            try!(packet.write(data.slice_to_end().initn(192)));
            packet.unwrap()
        };
        self.respond(contact.ret_addr, packet, &contact.ret)
    }

    fn generate_ping_id(&self, time: u64, public: &Key, addr: SocketAddr) -> [u8, ..32] {
        let mut data = MemWriter::new();
        let _ = data.write(self.secret_bytes);
        let _ = data.write_be_u64(time / PING_ID_TIMEOUT);
        let _ = data.write_struct(public);
        let _ = data.write_struct(addr);
        crypt::hash(time.get_ref())
    }

    fn handle_contact_announce(&self, source: SocketAddr,
                               mut data: MemReader) -> IoResult<()> {
        let (our_key, id, return_path, ping_id, real_id, data_key, send_back) = {
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
            let real_id: Key = try!(plain.read_struct());
            let data_key: Key = try!(plain.read_struct());
            // This is a bit of a waste since we only need a slice but plain is out of
            // scope once we leave this block. Given that send_back will soon be very
            // small, I guess this is ok. Maybe, once the size of send_back is fixed, we
            // can turn this into a stack allocation.
            let send_back = plain.slice_to_end().to_owned();
            (our_key, their_key, return_path, ping_id, real_id, data_key, send_back)
        };

        let (ping1, ping2) = {
            let time = utils::time::sec();
            let ping1 = self.generate_ping_id(time                  , &id, source);
            let ping2 = self.generate_ping_id(time + PING_ID_TIMEOUT, &id, source);
            (ping1, ping2)
        };

        let index = if ping1 == ping_id || ping2 == ping_id {
            /////
            // Add a new contact if possible or update the old one.
            /////
            let pos = match self.contacts.len() {
                MAX_CONTACTS => {
                    match self.find_contact(&id) {
                        Some(p) => Some(p),
                        None => {
                            match self.contacts.iter().position(|e| e.timed_out()) {
                                Some(p) => Some(p),
                                None => {
                                    match self.dht_pub.cmp(&self.contacts[0].id, &id) {
                                        Greater => Some(0),
                                        _ => None,
                                    }
                                },
                            }
                        },
                    }
                },
                _ => {
                    self.contacts.push(Contact::new());
                    Soem(self.contacts.len()-1)
                },
            };
            match pos {
                Some(p) => {
                    {
                        let c = &self.contacts[p];
                        c.id       = id;
                        c.ret_addr = source;
                        c.ret      = return_path.to_owned();
                        c.data_key = data_key;
                        c.time     = utils::time::sec();
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
            pos
        } else {
            self.find_contact(real_id)
        };

        let encrypted = {
            let only_good = true;
            let nodes = self.dht.get_close(real_id, source, only_good);

            let mut encrypted = MemWriter::new();
            let (is_data_key, val) = match index {
                None => (0, ping2),
                Some(i) => {
                    let entry = &self.entries[index];
                    match entry.id == id && entry.data_key == data_key {
                        true  => (0, ping2),
                        false => (1, entry.data_key.as_slice()),
                    }
                },
            };
            try!(encrypted.write_u8(is_data_key));
            try!(encrypted.write(val));
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

    fn send(&mut self, path: &OnionPath, dest: SocketAddr, data: &[u8]) {
        let _ = self.send_to_level_0(path, dest, data);
    }

    fn precomputed<'b>(&'b mut self, public: &Key) -> &'b PrecomputedKey {
        self.locker.get(public)
    }

    fn send_to_level_0(&mut self, path: &OnionPath, dest: SocketAddr,
                       data: &[u8]) -> IoResult<()> {
        let nonce = Nonce::random();

        let mut level_2 = MemWriter::new();
        try!(level_2.write_struct(&dest))
        try!(level_2.write(data))

        let mut level_1 = MemWriter::new();
        try!(level_1.write_struct(&path.nodes[2].addr))
        try!(level_1.write_struct(&path.nodes[2].public))
        try!(level_1.write_encrypted(&path.nodes[2].encoder.with_nonce(&nonce),
                                     level_2.get_ref()))

        let mut level_0 = MemWriter::new();
        try!(level_0.write_struct(&path.nodes[1].addr))
        try!(level_0.write_struct(&path.nodes[1].public))
        try!(level_0.write_encrypted(&path.nodes[1].encoder.with_nonce(&nonce),
                                     level_1.get_ref()))

        let mut packet = MemWriter::new();
        try!(packet.write_u8(128))
        try!(packet.write_struct(&nonce))
        try!(packet.write_struct(&path.nodes[0].public))
        try!(packet.write_encrypted(&path.nodes[0].encoder.with_nonce(&nonce),
                               level_0.get_ref()));

        self.udp.send_to(path.nodes[0].addr, packet.get_ref())
    }

    fn handle_send_common(&mut self, data: &mut MemReader, pdw: uint, pk: bool)
                             -> IoResult<(MemReader, SocketAddr, Option<Key>, Nonce)> {
        let nonce: Nonce = try!(data.read_struct());
        let id: Key = try!(data.read_struct());
        let remaining = data.remaining();
        // pdw = private data width
        if remaining < pdw {
            return other_error();
        }
        let decrypted = {
            let key = self.precomputed(&id);
            try!(key.with_nonce(&nonce).decrypt(
                     data.read_exact(remaining-pdw).unwrap().as_slice()))
        };
        let mut decrypted = MemReader::new(decrypted);

        let dest: SocketAddr = try!(decrypted.read_struct());
        let pk: Option<Key> = match pk {
            true => Some(try!(decrypted.read_struct())),
            false => None,
        };

        Ok((decrypted, dest, pk, nonce))
    }

    pub fn handle_send_level_0(&mut self, source: SocketAddr,
                               mut data: MemReader) -> IoResult<()> {
        let (decrypted, dest, pk2, nonce) =
            try!(self.handle_send_common(&mut data, 0, true));

        let my_nonce = Nonce::random();
        let mut packet = MemWriter::new();
        try!(packet.write_u8(129));
        try!(packet.write_struct(&nonce));
        try!(packet.write_struct(&pk2.unwrap()));
        try!(packet.write(decrypted.slice_to_end()));
        try!(packet.write_struct(&my_nonce));
        try!(packet.write_encrypted(&self.symmetric.with_nonce(&my_nonce),
                                    source.encode().as_slice()))

        self.udp.send_to(dest, packet.get_ref())
    }

    pub fn handle_send_level_1(&mut self, source: SocketAddr,
                               mut data: MemReader) -> IoResult<()> {
        let (decrypted, dest, pk, nonce) =
            try!(self.handle_send_common(&mut data, 64, true));

        let mut private = MemWriter::new();
        try!(private.write_struct(&source));
        try!(private.write(data.slice_to_end()));

        let my_nonce = Nonce::random();
        let mut packet = MemWriter::new();
        try!(packet.write_u8(130));
        try!(packet.write_struct(&nonce));
        try!(packet.write_struct(&pk.unwrap()));
        try!(packet.write(decrypted.slice_to_end()));
        try!(packet.write_struct(&my_nonce));
        try!(packet.write_encrypted(&self.symmetric.with_nonce(&my_nonce),
                                    private.get_ref()));

        self.udp.send_to(dest, packet.get_ref())
    }

    pub fn handle_send_level_2(&mut self, source: SocketAddr,
                               mut data: MemReader) -> IoResult<()> {
        let (decrypted, dest, _, _) =
            try!(self.handle_send_common(&mut data, 128, false));

        let mut private = MemWriter::new();
        try!(private.write_struct(&source));
        try!(private.write(data.slice_to_end()));

        let my_nonce = Nonce::random();
        let mut packet = MemWriter::new();
        try!(packet.write(decrypted.slice_to_end()));
        try!(packet.write_struct(&my_nonce));
        try!(packet.write_encrypted(&self.symmetric.with_nonce(&my_nonce),
                                    private.get_ref()));

        self.udp.send_to(dest, packet.get_ref())
    }

    pub fn respond(&mut self, dest: SocketAddr, data: &[u8],
                   path: &[u8]) -> IoResult<()> {
        let mut packet = MemWriter::new();
        try!(packet.write_u8(140));
        try!(packet.write(path));
        try!(packet.write(data));

        self.udp.send_to(dest, packet.get_ref())
    }

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

    pub fn handle_recv_level_2(&mut self, mut data: MemReader) -> IoResult<()> {
        let (decrypted, dest) = try!(self.handle_recv_common(&mut data, 192));

        let mut packet = MemWriter::new();
        try!(packet.write_u8(141));
        try!(packet.write(decrypted.slice_to_end()));
        try!(packet.write(data.slice_to_end()));

        self.udp.send_to(dest, packet.get_ref())
    }

    pub fn handle_recv_level_1(&mut self, mut data: MemReader) -> IoResult<()> {
        let (decrypted, dest) = try!(self.handle_recv_common(&mut data, 128));

        let mut packet = MemWriter::new();
        try!(packet.write_u8(142));
        try!(packet.write(decrypted.slice_to_end()));
        try!(packet.write(data.slice_to_end()));

        self.udp.send_to(dest, packet.get_ref())
    }

    pub fn handle_recv_level_0(&mut self, mut data: MemReader) -> IoResult<()> {
        let (_, dest) = try!(self.handle_recv_common(&mut data, 64));
        self.udp.send_to(dest, data.slice_to_end())
    }
}
