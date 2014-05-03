use crypt::{Key, Nonce};
use net::consts::{GROUP};

static GET_NODES:  u8 = 48;
static SEND_NODES: u8 = 49;
static BROADCAST:  u8 = 50;

static MESSAGE:  u8 = 64;
static ACTION:   u8 = 63;
static NICK:     u8 = 48;
static NEW_PEER: u8 = 16;
static PING:     u8 = 0;
static QUIT:     u8 = 24;

struct Peer {
    id: Key,
}

struct ClosePeer {
    id: Key,
    last_ping: i64,
    addr: SocketAddr,
}

struct Group {
    public: Key,
    private: Key,
    peers: HashMap<Key, Peer>,
    close: [Option<ClosePeer>, ..6],
}

impl Group {
    fn handle(&self, addr: SocketAddr, mut data: MemReader) -> IoResult<()> {
        let sender: Key = try!(data.read_struct());
        if sender == self.public || !self.peers.contains(&sender) {
            return other_error();
        }
        let nonce: Nonce = try!(data.read_struct());
        let data =
            try!(data.read_encrypted(self.precomputed(&sender).with_nonce(&nonce)));
        let data = MemReader::new(data);
        let ty = try!(data.read_u8());
        match ty {
            GET_NODES  => self.handle_get_nodes(sender, addr,  data),
            SEND_NODES => self.handle_send_nodes(addr, data),
            BROADCAST  => self.handle_broadcast(addr,  data),
        }
    }

    fn send_packet(&self, dest: SocketAddr, id: &Key, data: &[u8]) -> IoResult<()> {
        let nonce = Nonce::random();
        let mut packet = MemWriter::new();
        try!(packet.write_u8(GROUP));
        try!(packet.write_struct(&id));
        try!(packet.write_struct(&self.public));
        try!(packet.write_struct(&nonce));
        try!(packet.write_encrypted(self.precomputed(&id).with_nonce(&nonce), data));

        /* send */
    }

    fn write_broadcast_header(&mut self, writer: &mut MemWriter) -> IoResult<()> {
        self.message_number += 1;
        try!(writer.write_u8(BROADCAST));
        try!(writer.write_struct(&self.public));
        try!(writer.write_be_u32(self.message_number));
    }

    fn send_to_all(&self, data: &[u8]) -> IoResult<()> {
        for peer in self.peers.values() {
            try!(self.send_packet(peer.addr, &peer.id, data));
        }
    }

    fn send_str(&mut self, msg: &str, ty: u8) -> IoResult<()> {
        let mut packet = MemWriter::new();
        try!(self.write_broadcast_header(&mut packet));
        try!(packet.write_u8(ty));
        try!(packet.write(msg.as_bytes()));
        self.send_to_all(packet.unwrap().as_slice())
    }

    fn send_message(&mut self, msg: &str) -> IoResult<()> {
        self.send_str(msg, MESSAGE);
    }

    fn send_action(&mut self, msg: &str) -> IoResult<()> {
        self.send_str(msg, ACTION);
    }

    fn send_nick(&mut self) -> IoResult<()> {
        let mut packet = MemWriter::new();
        try!(self.write_broadcast_header(&mut packet));
        try!(packet.write_u8(NICK));
        try!(packet.write(self.nick.as_bytes()));
        self.send_to_all(packet.unwrap().as_slice())
    }

    fn set_nick(&mut self, nick: ~str) -> IoResult<()> {
        self.nick = nick;
        self.send_nick()
    }

    fn handle_get_nodes(&mut self, sender: Key, addr: SocketAddr,
                        mut data: MemReader) -> IoResult<()> {
        let packet = MemWriter::new();
        try!(packet.write_u8(SEND_NODES));
        try!(packet.write(data.slice_to_end()));
        for &close in self.close.iter() {
            match close {
                Some(close) => {
                    if !close.timed_out() {
                        try!(packet.write_struct(&close.id));
                        try!(packet.write_struct(&close.addr));
                    }
                },
                None => { }
            }
        }
        try!(self.send_packet(sender, addr, packet.unwrap()));
    }

    fn handle_send_nodes(&mut self, sender: Key, addr: SocketAddr,
                         mut data: MemReader) -> IoResult<()> {
        {
            let peer = self.peers.get(&sender);
            if peer.timed_out() {
                return other_error();
            }
            let ping_id = try!(data.read_be_u64());
            if ping_id != peer.ping_id {
                return other_error();
            }
        }
        while !data.eof() {
            let key:  Key        = try!(data.read_struct());
            let addr: SocketAddr = try!(data.read_struct());
            if self.close.iter().all(|c| self.public.cmp(c, addr) != Greater) {
                continue;
            }
            if !self.peers.contains(&key) {
                continue;
            }
            self.send_getnodes(&addr, &key);
        }
        self.add_close(&sender, addr);
        Ok(())
    }

    fn handle_broadcast(&mut self, addr: SocketAddr,
                        mut data: MemReader) -> IoResult<()> {
        let sender: Key = try!(data.read_struct());
        let num = try!(data.read_be_u32());
        {
            let peer = self.peers.find_mut(&sender).unwrap();
            if peer.last_msg_num != 0 {
                if num - peer.last_msg_num > 64 || num == peer.last_msg_num {
                    return Ok(());
                }
            }
            peer.last_msg_num = num;
            peer.last_recv = get_time().sec;
        }
        match try!(data.read_u8()) {
            MESSAGE => {/* send to frontend */},
            ACTION => {/* send to frontend */},
            NICK => {
                let peer = self.peers.get_mut(&sender);
                peer.nick = try!(data.read_struct());
                /* send to frontend */
            },
            NEW_PEER => {
                let key: Key = try!(data.read_struct());
                if self.peers.contains(&key) {
                    return other_error();
                }
                let peer = Peer {
                    nick: ~"",
                    last_recv: get_time().sec,
                    last_recv_ping: get_time().sec,
                    last_msg_num: 0,
                    id: key.clone(),
                    ping_id: 0,
                    last_pinged: 0,
                    ping_via: None,
                };
                self.peers.insert(key, peer);
                /* send names */
            },
            PING => {
                let peer = self.peers.get_mut(&sender);
                peer.last_recv_ping = get_time().sec;
            },
            QUIT => {
                let peer = self.peers.pop(&sender);
                /* send to frontend */
            },
            _ => return other_error(),
        }
        self.send_to_all(data.unwrap());
        Ok(())
    }


    /*
    fn sort_close(&mut self) {
        self.close.as_mut_slice().sort_by(|&a, &b| {
            match (a, b) {
                (None, None) => Equal,
                (Some(..), None) => Less,
                (None, Some(..)) => Greater,
                (Some(ref a), Some(ref b)) => {

                }
            }
        });
    }
    */


    fn ping_close(&mut self) {
        for &close in self.close.iter() {
            match close {
                None => continue,
                Some(ref close) => {
                    if close.timed_out() {
                        continue;
                    }
                    let peer = match self.find_peer(&close.id) {
                        Some(ref p) => p,
                        None => continue,
                    };
                    if peer.should_ping() {
                        peer.send_getnodes();
                    }
                }
            }
        }
    }

    fn ping_group(&mut self) {
        self.send_broadcast(vec!(PING));
    }

    fn send_nick(&mut self) {
    }
}

struct Groups;

impl Groups {
    fn handle(&self, addr: SocketAddr, mut data: MemReader) -> IoResult<()> {
        let key: Key = try!(data.read_struct());
        match self.find_group(&key) {
            Some(g) => g.handle(addr, data),
            None => other_error(),
        }
    }
}
