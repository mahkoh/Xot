#![feature(macro_rules)]

use std::io::net::ip::{SocketAddr};
use std::io::{MemReader, MemWriter, IoResult};
use crypt::{Key, Nonce, PrecomputedKey, key_pair, SecretKey};
use utils;
use utils::{other_error, StructReader, StructWriter, CryptoWriter, CryptoReader};
use std::{u64, mem};
use messenger::{Offline, MessengerControl};
use ludp::{LudpControl};
use keylocker::{Keylocker};

static CRYPTO_HANDSHAKE: u8 = 2;
static CRYPTO_PACKET: u8 = 3;
static HANDSHAKE_TIMEOUT: u64 = 10;
static COOKIE_TIMEOUT: u64 = 10;
static KILL: u8 = 2;
static REQUEST: u8 = 1;
static PADDING: u8 = 0;

static COOKIE_SIZE: uint = MAC + NONCE + 8 + 2*KEY;

#[deriving(Eq)]
enum ConnectionStatus {
    Established,
    AwaitingData,
}

struct Connection<'a> {
    raw: &'a mut RawConnection,
    public: &'a Key,
}

impl<'a> Connection<'a> {
}

struct OutboundPacket {
    requested: bool,
    data: Vec<u8>,
}

struct RawConnection {
    addr:         SocketAddr,
    public:       Key,
    recv_nonce:   Nonce,
    send_nonce:   Nonce,
    session_pub:  Key,
    session_priv: SecretKey,
    peer_pub:     Key,
    precomputed:  PrecomputedKey,
    status:       ConnectionStatus,
    timeout:      u64,
    locker:       Keylocker,
}

struct Cons {
    cons: Vec<RawConnection>,
    ludp: LudpControl,
    messenger: MessengerControl,
    public: Key,
    // locker secret key = dht secret key
    locker: Keylocker,
}

impl Cons {
    fn handle_data_int(&mut self, i: uint,
                       mut data: MemReader) -> IoResult<(u8, MemReader)> {
        let con = self.established.get_mut(i);

        let mut encrypted = {
            let nonce_u16 = try!(data.read_be_16());
            let mut nonce = con.peer_nonce;
            nonce.increment_by(nonce_u16 - nonce.u16());
            let encrypted = try!(data.read_encrypted(con.data_key.with_nonce(&nonce)));
            if nonce_u16 - nonce.u16 > 2 * 21_845 {
                con.peer_nonce.increment_by(21_845);
            }
            MemReader::new(encrypted)
        };
        let packet_num = {
            // Remove received packets.
            let peer_buf_start = try!(encrypted.read_be_u32());
            let buf_start = con.send_buf_start;
            let buf_len = con.send_buf.len() as u32;
            if !peer_buf_start.in_between(buf_start, buf_start+buf_len) {
                return other_error();
            }
            con.send_buf.consume(peer_buf_start - buf_start);

            try!(encrypted.read_be_u32())
        };
        let packet_type = 0;
        // Packets may contain padding bytes to obscure the packet size.
        while packet_type == 0 {
            packet_type = try!(data.read_u8());
        }
        Ok(packet_type, encrypted)
    }

    fn handle_data(&mut self, source: SocketAddr, mut data: MemReader) -> IoResult<()> {
        let i = match self.established.iter().position(|c| c.addr == source) {
            Some(i) => i,
            None => return other_error(),
        };
        let (packet_type, mut data) = try!(self.handle_data_int(i, data));

        match packet_type {
            REQUEST => try!(self.handle_request(data)),
            KILL => {
            },
            _ => {
            },
        }
    }

    fn handle_hs_common(data: &mut MemReader, my_pub: &Key, symmetric: &Key,
                        locker: &mut Keylocker) -> IoResult<(Key, Nonce, Key, Vec<u8>)> {
        let (time, peer_pub, should_be_my_pub, cookie_num) = {
            let nonce: Nonce = try!(data.read_struct());
            let cookie_data = symmetric.with_nonce(&nonce).decrypt(
                                   data.slice_to_end().slice(0, COOKIE_SIZE-NONCE-8));
            data.consume(COOKIE_SIZE-NONCE-8);
            let cookie_data = MemReader::new(cookie_data);
            let time = try!(cookie_data.read_be_u64());
            let peer_pub: Key = try!(cookie_data.read_struct());
            let should_be_my_pub: Key = try!(cookie_data.read_struct());
            let cookie_num = try!(data.read_be_u64());
            (time, peer_pub, should_be_my_pub, cookie_num)
        };
        if utils::time::sec() < time || time + COOKIE_TIMEOUT < utils::time::sec() {
            return other_error();
        }
        if should_be_my_pub != *my_pub {
            return other_error();
        }
        let mut encrypted = {
            let nonce: Nonce = try!(data.read_struct());
            let key = locker.get(&peer_pub);
            let encrypted = try!(data.read_encypted(&key.with_nonce(&nonce)));
            MemReader::new(encrypted)
        };
        let (peer_nonce, cookie_hash, peer_session_pub, peer_cookie) = {
            let peer_nonce: Nonce = try!(encrypted.read_struct());
            let session_pub: Key = try!(encrypted.read_struct());
            let cookie_hash = try!(encrypted.read_exact(HASH));
            let peer_cookie = encrypted.slice_to_end().to_owned();
            (peer_nonce, hash, session_pub, peer_cookie)
        };
        {
            // Don't forget the packet id.
            let my_cookie = data.get_ref().slice(1, COOKIE_SIZE+1);
            if crypt::hash(my_cookie).as_slice() != cookie_hash.as_slice() {
                return other_error();
            }
        }
        Ok((peer_pub, peer_nonce, peer_session_pub, peer_cookie))
    }

    fn create_handshake(peer_pub: &Key, my_priv: &SecretKey, my_pub: &Key,
                        my_session_pub: &Key, my_nonce: &Nonce, symmetric: &Key, 
                        peer_cookie: &[u8]) -> IoResult<Vec<u8>> {
        let my_cookie = {
            let mut my_cookie = MemWriter::new();
            try!(private.write_be_u64(utils::time::sec()));
            try!(my_cookie.write_struct(peer_pub));
            try!(my_cookie.write_struct(my_pub));
            my_cookie.unwrap()
        };
        let private = {
            let mut private = MemWriter::new();
            try!(private.write_struct(my_nonce));
            try!(private.write_struct(my_session_pub));
            try!(private.write(crypt::hash(peer_cookie)));
            try!(private.write_encrypted(symmetric.with_nonce(my_nonce),
                                         my_cookie.as_slice()));
            private.unwrap()
        };
        let packet = {
            let nonce = Nonce::random();
            let key = PrecomputedKey::new(my_priv, peer_pub);

            let mut packet = MemWriter::new();
            try!(packet.write_u8(HANDSHAKE));
            try!(packet.write(peer_cookie));
            try!(packet.write_struct(&nonce));
            try!(packet.write_encrypted(key.with_nonce(&nonce), private.as_slice()));
            packet.unwrap()
        };
        Ok(packet)
    }

    fn connect_to(&mut self, peer_pub: &Key, peer_dht: &Key, addr: SocketAddr) {
        macro_rules! check(
            ($cons:ident) => (
                match self.$cons.iter().position(|c| c.peer_pub == *peer_pub) {
                    Some(i) => {
                        match self.$cons.get(i).peer_dht == *peer_dht {
                            true  => return,
                            false => self.$cons.swap_remove(i),
                        }
                    },
                    None => { }
                }
            );
        );
        check!(pending);
        check!(enstablished);

        let my_nonce = Nonce::random();
        let (my_session_priv, my_session_pub) = key_pair();
        let cookie_request_num = task_rng().next_u64();

        let plain = {
            let mut plain = MemWriter::new();
            try!(plain.write_struct(&self.my_pub));
            try!(plain.write_struct(peer_pub));
            try!(plain.write_be_u64(cookie_request_num));
            plain.unwrap()
        };
        let request = {
            let nonce = Nonce::random();
            let key = self.locker.get(peer_dht);

            let mut request = MemWriter::new();
            try!(request.write_u8(COOKIE_REQUEST));
            try!(request.write_struct(&self.my_dht));
            try!(request.write_struct(&nonce));
            try!(request.write_encrypted(&key.with_nonce(&nonce), plain.as_slice()));
            request.unwrap()
        };
        self.udp.send_to(addr, request.as_slice());

        let pending = Pending {
            addr: addr,
            my_nonce: my_nonce,
            peer_pub: *peer_pub,
            peer_dht: *peer_dht,
            my_session_priv: my_session_priv,
            my_session_pub: my_session_pub,
            cookie_request_num: cookie_request_num,
            packet: request,
        };

        self.pending.push(pending);
        Ok(())
    }

    fn handle_cookie_request(&self, source: SocketAddr,
                             mut data: MemReader) -> IoResult<()> {
        let (keys, cookie_num, precomputed) = {
            let peer_dht: Key = try!(data.read_struct());
            let nonce: Nonce = try!(data.read_struct());
            let key = self.locker.get(&peer_dht);
            let plain = try!(data.read_encrypted(&key.with_nonce(&nonce)));
            let mut plain = MemReader::new(plain);
            let keys = try!(plain.read_exact(KEY * 2));
            let cookie_num = try!(plain.read_be_u64());
            (keys, cookie_num, precomputed)
        };
        let encrypted = {
            let mut encrypted = MemWriter::new();
            try!(encrypted.write_be_u64(utils::time::sec()));
            try!(encrypted.write(keys.as_slice()));
            encrypted.unwrap()
        };
        let my_cookie = {
            let nonce = Nonce::random();
            let mut my_cookie = MemWriter::new();
            try!(my_cookie.write_struct(&nonce));
            try!(my_cookie.write_encrypted(self.symmetric.with_nonce(&nonce),
                                           encypted.as_slice()));
            try!(my_cookie.write_be_u64(cookie_num));
            my_cookie.unwrap()
        };
        let packet = {
            let nonce = Nonce::random();

            let mut packet = MemWriter::new();
            try!(packet.write_u8(COOKIE_RESPONSE));
            try!(packet.write_struct(&nonce));
            try!(packet.write_encrypted(&precomputed.with_nonce(&nonce),
                                        my_cookie.as_slice()));
            packet.unwrap()
        };
        self.udp.send_to(source, packet);
        OK(())
    }

    fn handle_cookie_response(&self, source: SocketAddr,
                              mut data: MemReader) -> IoResult<()> {
        let pending = match self.pending.find(|c| c.addr == source) {
            Ok(c) => c,
            None => return other_error(),
        };

        let mut plain = {
            let nonce: Nonce = try!(data.read_struct());
            let key = self.locker.get(&pending.peer_dht);
            let plain = try!(data.read_encrypted(key.with_nonce(&nonce)));
            MemReader::new(plain)
        };
        // COOKIE_SIZE is the size of the nonce and the symmetrically encrypted stuff, but
        // not cookie_num.
        let peer_cookie = try!(plain.read_exact(COOKIE_SIZE));
        let cookie_num = try!(plain.read_be_u64());
        if cookie_num != pending.cookie_num {
            return other_error();
        }
        let handshake = try!(Cons::create_handshake(
                &pending.peer_pub, &self.my_pub, &pending.my_session_pub,
                &pending.my_nonce, &self.symmetric, &mut self.locker,
                peer_cookie.as_slice()));
        self.udp.send_to(addr, handshake.as_slice());

        pending.packet = handshake;
        Ok(())
    }

    fn handle_handshake(&self, source: SocketAddr, mut data: MemReader) -> IoResult<()> {
        match self.connections.iter().find(|c| c.addr == source) {
            Some(c) => c.handle_handshake(data),
            None => { }
        }
        self.handle_hs_new(source, data)
    }

    fn handle_hs_new(&mut self, source: Source, mut data: MemReader) -> IoResult<()> {
        let (peer_pub, peer_nonce, peer_session_pub, peer_cookie) =
            try!(Cons::handle_hs_common(&mut data, self.my_pub, self.symmetric,
                                        &mut self.locker));

        match self.cons.iter().find(|c| c.peer_pub == peer_pub) {
            Some(c) => {
                c.addr = source.to_udp();
                c.ctrl.new_source(source, peer_nonce, peer_session_pub, peer_cookie);
                return Ok(());
            }
            None => { },
        }

        // We only accept connections from our friends.
        if !self.messenger.has_friend(&peer_pub) {
            return other_error();
        }

        let (my_session_priv, my_session_pub) = key_pair();
        let my_nonce = Nonce::random();

        let handshake = try!(Cons::create_handshake(
                &peer_pub, &self.my_priv, &self.my_pub, &my_session_pub, &my_nonce,
                &self.symmetric, peer_cookie.as_slice()));
        match source {
            UDP(addr) => self.udp.send_to(addr, handshake.as_slice()),
            TCP(con) => con.send(handshake.as_slice()),
        }

        let mut con = Connection {
            status: AwaitingData,

            udp_addr: None,
            tcp_cons: Vec::new(),

            symmetric: self.symmetric,
            my_pub: self.my_pub,
            my_priv: self.my_priv.clone(),
            my_dht_pub: self.my_dht_pub,
            my_session_pub: my_session_pub,
            my_session_priv: my_session_priv,
            my_nonce: my_nonce,

            peer_pub: peer_pub,
            peer_nonce: Some(peer_nonce),
            peer_session_pub: Some(peer_session_pub),
            data_key: PrecomputedKey::new(&my_session_priv, &peer_session_pub),

            interval_packet: Some(handshake),

            udp: self.udp.clone(),
            messenger: self.messenger.clone(),
        };
        match source {
            UDP(addr) => con.udp_addr = Some(addr),
            TCP(con) => con.tcp_cons.push(con),
        }
        let (snd, rcv) = connection::con_control();

        self.sched.spawn(TaskOpts::new(), || con.run(rcv));
        self.cons.push(ConInfo { peer_pub: peer_pub, addr: source.to_udp(), ctrl: snd });

        Ok(())
    }
}

pub struct CryptoControl;

impl CryptoControl {
    pub fn send_packet(&self, id: &Key, data: Vec<u8>) {
        unreachable!();
    }

    pub fn kill(&self, id: &Key) {
        unreachable!();
    }
}
