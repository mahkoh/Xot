use std::io::net::ip::{SocketAddr};
use std::io::{MemReader, MemWriter, IoResult};
use crypt::{Key, Nonce};
use utils::{other_error};

static CRYPTO_HANDSHAKE: u8 = 2;
static CRYPTO_PACKET:    u8 = 3;

#[deriving(Eq)]
enum ConnectionStatus {
    HandshakeSent,
    NotConfirmed,
    Established,
    TimedOut,
}

struct Connection<'a> {
    cons: &'a mut Cons,
    id: uint,
}

impl Connection {
    fn handle(&mut self, mut data: MemReader) -> IoResult<()> {
        match self.raw().status {
            HandshakeSent => self.handle_handshake_sent(data),
            NotConfirmed  => self.handle_not_confirmed(data),
            Established   => self.handle_established(data),
            _ => other_error(),
        }
    }

    fn handle_handshake_sent(&self, mut data: MemReader) -> IoResult<()> {
        let kind = try!(data.read_u8());
        match kind {
            CRYPTO_HANDSHAKE => self.handle_handshake(data),
            _ => {
                self.raw_mut().status = TimedOut;
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
            let key = &self.raw().precomputed;
            try!(data.read_encrypted(&key.with_nonce(&self.raw().recv_nonce)));
        };
        if data.as_slice() != [0u8, ..4].as_slice() {
            self.raw_mut().status = TimedOut;
            return other_error();
        }
        self.raw_mut().recv_nonce.increment();
        self.raw_mut().status = Established;
        self.raw_mut().timeout = u64::MAX;

        // ludp confirm
    }

    fn handle_established(&mut self, mut data: MemReader) -> IoResult<()> {
        let kind = try!(data.read_u8());
        if kind != CRYPTO_PACKET {
            return other_error();
        }
        let data = {
            let machine = self.raw().precomputed.with_nonce(&self.raw().recv_nonce);
            try!(data.read_encrypted(&machine))
        };
        self.raw_mut().recv_nonce.increment();

        // send to messenger
    }

    fn handle_handshake(&self, mut data: MemReader) -> IoResult<()> {
        // todo
        Ok(())
    }

    fn send_packet(&mut self, data: &[u8]) -> IoResult<()> {
        let mut packet = MemWriter::new();
        try!(packet.write_u8(CRYPTO_PACKET));
        {
            let key = &self.raw().precomputed.with_nonce(&self.raw().send_nonce);
            try!(packet.write_encrypted(key, data));
        }
        self.send_nonce.increment();

        // send to ludp
    }

    fn send_handshake(&self) -> IoResult<()> {
        let mut private = MemWriter::new();
        try!(private.write_struct(&self.raw().recv_nonce));
        try!(private.write_struct(&self.raw().session_key));

        let nonce = Nonce::random();
        let mut packet = MemWriter::new();
        try!(packet.write_u8(CRYPTO_HANDSHAKE));
        try!(packet.write_struct(&self.cons.public));
        try!(packet.write_struct(&nonce));
        {
            let key = self.cons.precomputed(self.raw.public).with_nonce(&nonce);
            try!(packet.write_encrypted(&key, private.get_ref()));
        }

        self.recv_nonce.increment();

        // send to ludp
    }

    fn send_zero(&mut self) -> IoResult<()> {
        self.send_packet([0u8, ..4].as_slice())
    }
}

struct RawConnection {
    public:          Key,
    recv_nonce:      Nonce,
    send_nonce:      Nonce,
    session_public:  Key,
    session_private: Key,
    peer_public:     Key,
    precomputed:     PrecomputedKey,
    status:          ConnectionStatus,
    timeout:         u64,
}

struct Cons {
    public: Key,
}

impl Cons {
    fn handle(&self, addr: SocketAddr, mut data: MemReader) -> IoResult<()> {
        match self.find_con(addr) {
            Some(con) => con.handle(data),
            None => self.handle_new(addr, data),
        }
    }

    fn handle_new(&self, addr: SocketAddr, mut data: MemReader) -> IoResult<()> {
        let kind = try!(data.read_u8());
        if kind != CRYPTO_HANDSHAKE {
            // ludp kill
            return other_error();
        }

        let public: Key = try!(data.read_struct());

        if self.messenger.friend_status(&public) != Offline {
            return other_error();
        }

        let nonce: Nonce = try!(data.read_struct());
        let data =
            try!(data.read_encrypted(self.precomputed(&public).with_nonce(&nonce)));
        let mut data = MemReader(data);
        let secret_nonce: Nonce = try!(data.read_struct());
        let session_key: Key = try!(data.read_struct());

        let (session_private, session_public) = key_pair();
        let precomputed = PrecomputedKey::new(&session_private, &session_key);

        let mut raw = RawConnection {
            public:          public,
            recv_nonce:      Nonce::random(),
            send_nonce:      secret_nonce,
            session_public:  session_public,
            session_private: session_private,
            peer_session:    session_key,
            precomputed:     precomputed,
            status:          NotConfirmed,
            timeout:         get_time().sec + HANDSHAKE_TIMEOUT,
        };
        raw.send_nonce.increment();

        let id = None;
        for (i, &con) in self.cons.enumerate() {
            if con.is_none() {
                id = Some(i);
                break;
            }
        }
        let id = match id {
            Some(i) => {
                *self.cons.get_mut(i) = Some(raw);
                i
            },
            None => {
                self.cons.push(Some(con));
                self.cons.len()-1
            },
        };

        let con = Connection { cons: self, id: id };
        try!(con.send_handshake());
        con.send_zero()
    }
}
