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

#[deriving(Eq)]
enum ConnectionStatus {
    HandshakeSent,
    NotConfirmed,
    Established,
    TimedOut,
}

struct Connection<'a> {
    raw: &'a mut RawConnection,
    public: &'a Key,
}

impl<'a> Connection<'a> {
    fn handle(&mut self, mut data: MemReader) -> IoResult<()> {
        match self.raw.status {
            HandshakeSent => self.handle_handshake_sent(data),
            NotConfirmed  => self.handle_not_confirmed(data),
            Established   => self.handle_established(data),
            _ => other_error(),
        }
    }

    fn handle_handshake_sent(&mut self, mut data: MemReader) -> IoResult<()> {
        let kind = try!(data.read_u8());
        match kind {
            CRYPTO_HANDSHAKE => self.handle_handshake(data),
            _ => {
                self.raw.status = TimedOut;
                other_error()
            }
        }
    }

    fn handle_not_confirmed(&mut self, mut data: MemReader) -> IoResult<()> {
        let kind = try!(data.read_u8());
        if kind != CRYPTO_PACKET {
            return other_error();
        }
        let data = {
            let key = &self.raw.precomputed;
            try!(data.read_encrypted(&key.with_nonce(&self.raw.recv_nonce)))
        };
        if data.as_slice() != [0u8, ..4].as_slice() {
            self.raw.status = TimedOut;
            return other_error();
        }
        self.raw.recv_nonce.increment();
        self.raw.status = Established;
        self.raw.timeout = u64::MAX;

        // ludp confirm
        unreachable!();
    }

    fn handle_established(&mut self, mut data: MemReader) -> IoResult<()> {
        let kind = try!(data.read_u8());
        if kind != CRYPTO_PACKET {
            return other_error();
        }
        let data = {
            let machine = self.raw.precomputed.with_nonce(&self.raw.recv_nonce);
            try!(data.read_encrypted(&machine))
        };
        self.raw.recv_nonce.increment();

        // send to messenger
        unreachable!();
    }

    fn handle_handshake(&self, mut data: MemReader) -> IoResult<()> {
        // todo
        Ok(())
    }

    fn send_packet(&mut self, data: &[u8]) -> IoResult<()> {
        let mut packet = MemWriter::new();
        try!(packet.write_u8(CRYPTO_PACKET));
        {
            let key = &self.raw.precomputed.with_nonce(&self.raw.send_nonce);
            try!(packet.write_encrypted(key, data));
        }
        self.raw.send_nonce.increment();

        // send to ludp
        unreachable!();
    }

    fn send_handshake(&mut self) -> IoResult<()> {
        let mut private = MemWriter::new();
        try!(private.write_struct(&self.raw.recv_nonce));
        try!(private.write_struct(&self.raw.session_pub));

        let nonce = Nonce::random();
        let mut packet = MemWriter::new();
        try!(packet.write_u8(CRYPTO_HANDSHAKE));
        try!(packet.write_struct(self.public));
        try!(packet.write_struct(&nonce));
        {
            let key = self.raw.locker.get(&self.raw.public).with_nonce(&nonce);
            try!(packet.write_encrypted(&key, private.get_ref()));
        }

        self.raw.recv_nonce.increment();

        // send to ludp
        unreachable!();
    }

    fn send_zero(&mut self) -> IoResult<()> {
        self.send_packet([0u8, ..4].as_slice())
    }

    fn precomputed<'b>(&'b mut self, public: &Key) -> &'b PrecomputedKey {
        self.raw.locker.get(public)
    }
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

impl RawConnection {
    fn new() -> RawConnection {
        unsafe { mem::uninit() }
    }
}

struct Cons {
    cons: Vec<RawConnection>,
    ludp: LudpControl,
    messenger: MessengerControl,
    public: Key,
    locker: Keylocker,
}

impl Cons {
    fn precomputed<'a>(&'a mut self, public: &Key) -> &'a PrecomputedKey {
        self.locker.get(public)
    }

    fn find_con<'a>(&'a mut self, addr: SocketAddr) -> Option<Connection<'a>> {
        match self.cons.mut_iter().find(|c| c.addr == addr) {
            Some(c) => {
                let con = Connection {
                    raw: c,
                    public: &self.public,
                };
                Some(con)
            },
            None => None
        }
    }

    fn handle(&mut self, addr: SocketAddr, mut data: MemReader) -> IoResult<()> {
        match self.find_con(addr) {
            Some(mut con) => return con.handle(data),
            None => { }
        }
        self.handle_new(addr, data)
    }

    fn handle_new(&mut self, addr: SocketAddr, mut data: MemReader) -> IoResult<()> {
        let kind = try!(data.read_u8());
        if kind != CRYPTO_HANDSHAKE {
            self.ludp.kill(addr);
            return other_error();
        }

        let public: Key = try!(data.read_struct());

        if self.messenger.friend_status(&public) != Offline {
            return other_error();
        }

        let nonce: Nonce = try!(data.read_struct());
        let data =
            try!(data.read_encrypted(&self.precomputed(&public).with_nonce(&nonce)));
        let mut data = MemReader::new(data);
        let secret_nonce: Nonce = try!(data.read_struct());
        let session_key: Key = try!(data.read_struct());

        let (session_private, session_public) = key_pair();
        let precomputed = PrecomputedKey::new(&session_private, &session_key);

        let mut raw = RawConnection {
            addr: addr,
            locker: Keylocker::new(session_private.clone()),
            public:       public,
            recv_nonce:   Nonce::random(),
            send_nonce:   secret_nonce,
            session_pub:  session_public,
            session_priv: session_private,
            peer_pub:     session_key,
            precomputed:  precomputed,
            status:       NotConfirmed,
            timeout:      utils::time::sec() + HANDSHAKE_TIMEOUT,
        };
        raw.send_nonce.increment();

        self.cons.push(RawConnection::new());
        let mut con = self.find_con(addr).unwrap();
        try!(con.send_handshake());
        con.send_zero()
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
