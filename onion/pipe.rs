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

/// The object running the onion layer.
pub struct Onion {
    udp:       UdpWriter,
    locker:    Keylocker,
    symmetric: Key,
}

impl Onion {
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
