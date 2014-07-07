#![feature(macro_rules)]

use crypt::{Key, Nonce, PrecomputedKey, key_pair, SecretKey};
use utils::{ToOption};
use utils::ticker::{Ticker};

enum ConnectionStatus {
    Pending,
    AwaitingData,
    Established,
}

enum Source {
    UDP,
    TCP(uint),
}

enum PacketResult {
    Interval,
    NotInterval,
}

struct TcpCon {
    con: network::TcpCon,
    dead: bool,
    handle: Option<Handle<'a, network::TcpConMessage>>,
}

impl TcpCon {
}

struct TcpVec<'a> {
    vec: Vec<TcpCon>,
    select: &'a Select,
}

impl TcpVec {
    fn new(select: &'a Select) -> TcpVec<'a> {
        TcpVec { vec: Vec::new(), select: select }
    }

    fn modify(&mut self, f: |&mut Vec<TcpCon>|) {
        self.select.remove_many(self.vec.as_mut_slice(), |t| &mut t.handle);
        f(&mut self.vec);
        self.select.add_many(self.vec.as_mut_slice(), |t| &t.con.recv, |t| &mut t.handle);
    }

    fn iter(&'a mut self) -> MutItems<'a, TcpCon> {
        self.vec.mut_iter()
    }
}

struct Connection {
    status: ConnectionStatus,

    symmetric: Key,
    my_pub: Key,
    my_priv: SecretKey,
    my_dht_pub: Key,
    my_session_pub: Key,
    my_session_priv: SecretKey,
    my_nonce: Nonce,

    peer_pub: Key,
    peer_nonce: Option<Nonce>,
    peer_session_pub: Option<Key>,
    data_key: Option<PrecomputedKey>,

    interval_packet: Option<Vec<u8>>,

    udp: UdpWriter,
    messenger: MessengerControl,

    send_queue: RingBuffer<Vec<u8>>,
    send_queue_start: u32,
    recv_queue: XBuffer<Vec<u8>>,
}

macro_rules! receive{
    ($($name:pat <- $rx:expr: $code:expr),+,) => {
        {
            $(
                match $rx.try_recv() {
                    Some($name) => $code,
                    None => { }
                }
            )+
        }
    };
}

impl Connection {
    fn run(&mut self) {
        macro_rules! send{
            ($ex:expr) => {
                {
                    match self.addr {
                        Some(addr) => self.udp.send_to(addr, $ex),
                        None => { }
                    }
                    for c in tcp_cons.iter() {
                        c.send($ex);
                        break;
                    }
                }
            };
        };

        macro_rules! send_opt{
            ($ex: expr) => {
                match $ex.to_option() {
                    Some(p) => send!(p),
                    None => { }
                }
            };
        };

        let select = Select::new();

        let tcp_cons = TcpVec::new(&select);

        let send     = Ticker::new(&select);
        let interval = Ticker::new(&select);
        let timeout  = Ticker::new(&select);

        send.set_interval(50);
        interval.set_interval(50);
        timeout.set_interval(5000);

        let udp_handle     = select.handle(&udp);
        let new_udp_handle = select.handle(&new_udp);
        let new_tcp_handle = select.handle(&new_tcp);

        unsafe { udp_handle.add() };
        unsafe { new_udp_handle.add() };
        unsafe { new_tcp_handle.add() };

        loop {
            select.wait();

            let send_interval_to = None;
            let any_tcp_dead = false;
            let new_tcp_con = None;

            receive!(
                p <- udp: if self.handle_packet(p) == Interval {
                    send_interval_to = Some(UDP);
                },
                _ <- send: send_opt!(self.create_requested_packet()),
                _ <- interval: send_opt!(self.interval),
                _ <- timeout: {
                    if udp_last_recv + UDP_TIMEOUT < utils::time::sec() {
                        udp_addr = None;
                    }
                    let dead_cons = Vec::new();
                    for (i, tcp) in tcp_cons.iter().enumerate().rev() {
                        if tcp.timed_out() {
                            any_tcp_dead = true;
                            tcp.dead = true;
                        }
                    }
                    if udp_addr.is_none() && tcp_cons.len() == 0 {
                        self.cons.drop();
                        return;
                    }
                },
                a <- new_udp: {
                    udp_addr = Some(a);
                    udp_last_recv = utils::time::sec();
                },
                c <- new_tcp: new_tcp_con = Some(c),
            )

            for (i, tcp) in tcp_cons.iter().enumerate() {
                receive!(
                    p <- tcp.recv: match p {
                        Remove => {
                            tcp.dead = true;
                            any_tcp_dead = true;
                        },
                        Packet(p) => if self.handle_packet(p) == Interval {
                            send_interval_to = Some(TCP(i));
                        },
                    },
                )
            }

            if self.interval.is_some() {
                let interval = self.interval.as_ref().unwrap().as_slice();
                match send_interval_to {
                    Some(UDP) => self.udp.send_to(self.addr, interval),
                    Some(TCP(i)) => tcp_cons.get(i).send(interval),
                    None => { }
                }
            }

            if any_tcp_dead || new_tcp_con.is_some() {
                tcp_cons.modify(|vec| {
                    for i in range(0, vec.len()).rev() {
                        if vec.get(i).dead {
                            vec.swap_remove(i);
                        }
                    }

                    match new_tcp_con {
                        Some(con) => {
                            let con = TcpCon { con: con, dead: false };
                            vec.push(con);
                        },
                        None => { }
                    }
                });
            }
        }
    }

    fn handle_packet(&mut self, mut data: MemReader) -> PacketResult {
        let kind = match data.read_u8() {
            Ok(k) => k,
            Err(..) => return NotInterval,
        };
        match kind {
            HANDSHAKE => {
                match self.handle_handshake(data) {
                    Ok(..) => Interval,
                    Err(..) => NotInterval,
                }
            },
            DATA => {
                self.handle_data(data);
                NotInterval
            },
        }
    }

    fn enqueu_packet(&mut self, data: Vec<u8>) {
        self.send_queue.push(OutboundPacket { requested: true, data: data });
        self.send_data(self.send_queue.len()-1);
    }

    fn create_request_packet(&mut self) -> IoResult<Vec<u8>> {
        let encrypted = {
            let mut encrypted = MemWriter::new();
            try!(encrypted.write_be_u32(self.recv_all_before));
            let send_queue_end = self.send_queue_start + self.send_queue.len();
            try!(encrypted.write_be_u32(send_queue_end));
            try!(encrypted.write_u8(REQUEST));

            let recv_queue_len = self.peer_max_sent - self.recv_all_before + 1;
            let num = 1u8;
            for i in range(0, recv_queue_len) {
                if !self.recv_queue.has(i) {
                    try!(encrypted.write_u8(num));
                    num = 0;
                } else if num == 255 {
                    try!(encrypted.write_u8(0));
                    num = 0;
                }
                num += 1;
            }
            encrypted.unwrap()
        };
        let packet = {
            let mut packet = MemWriter::new();
            try!(packet.write_u8(DATA));
            try!(packet.write_be_u16(self.my_nonce.u16()));
            let machine = self.data_key.with_nonce(&self.my_nonce);
            try!(packet.write_encrypted(&machine, encrypted.as_slice()));
            self.my_nonce.increment();
            packet.unwrap()
        };
        Ok(packet)
    }

    fn create_data(&mut self, i: uint) -> IoResult<Vec<u8>> {
        let encrypted = {
            let mut encrypted = MemWriter::new();
            try!(encrypted.write_be_u32(self.recv_all_before));
            {
                let packet = self.send_queue.get(i);
                try!(encrypted.write_be_u32(self.send_queue_start + i));
                try!(encrypted.write(packet.data.as_slice()));
            }
            encrypted.unwrap()
        };
        let packet = {
            let mut packet = MemWriter::new();
            try!(packet.write_u8(CRYPTO_DATA));
            try!(packet.write_be_u16(self.my_nonce.u16()));
            let machine = self.data_key.with_nonce(&self.raw.my_nonce);
            try!(packet.write_encrypted(&machine, encrypted.as_slice()));
            self.my_nonce.increment();
            packet.unwrap()
        };
        Ok(packet)
    }

    fn create_requested_packet(&mut self) -> IoResult<Vec<u8>> {
        match self.send_queue.mut_iter().position(|p| p.requested) {
            Some(i) => {
                self.send_queue.get_mut(i).requested = false;
                self.create_data(i)
            },
            None => other_error(),
        }
    }

    fn handle_request_packet(&mut self, mut packet: MemReader) -> IoResult<()> {
        let pos = -1 as uint;
        while !packet.eof() {
            match try!(packet.read_u8()) {
                0 => pos += u8::MAX as uint,
                n => {
                    pos += n as uint;
                    if pos >= self.send_buf.len() {
                        break;
                    }
                    self.send_buf.get_mut(pos).requested = true;
                },
            }
        }
        Ok(())
    }

    fn handle_handshake(&mut self, mut data: MemReader) -> IoResult<()> {
        match self.status {
            Pending => self.handle_hs_pending(data),
            AwaitingData | Established => self.handle_hs_established(data),
        }
    }

    fn handle_hs_common(&mut self, peer_pub: &Key, peer_nonce: &Nonce,
                        peer_session_pub: &Key, peer_cookie: Vec<u8>) -> IoResult<()> {
        if *peer_pub != self.peer_pub {
            return other_error();
        }

        let handshake = try!(Cons::create_handshake(
                peer_pub, &self.my_priv, &self.my_pub, &self.my_session_pub,
                &self.my_nonce, &self.symmetric, peer_cookie));

        self.peer_nonce = Some(peer_nonce);
        self.peer_session_pub = Some(peer_session_pub);
        self.data_key = PrecomputedKey::new(&self.my_session_priv, &peer_session_pub);
        self.interval_packet = Some(handshake);
        self.status = AwaitingData;

        Ok(())
    }

    fn handle_hs_pending(&mut self, mut data: MemReader) -> IoResult<()> {
        let (peer_pub, peer_nonce, peer_session_pub, peer_cookie) =
            try!(Cons::handle_hs_common(&mut data, &self.my_priv, &self.my_pub,
                                        &self.symmetric));

        try!(self.handle_hs_common(&peer_pub, &peer_nonce, &peer_session_pub,
                                   &peer_cookie))
    }

    fn handle_hs_established(&mut self, mut data: MemReader) -> IoResult<()> {
        let (peer_pub, peer_nonce, peer_session_pub, peer_cookie) =
            try!(Cons::handle_handshake_common(&mut data, &self.my_priv, &self.my_pub,
                                               &self.symmetric));

        if peer_session_pub != self.peer_session_pub {
            if self.status == Established {
                self.messenger.friend_offline(&peer_pub);
            }
            try!(self.handle_hs_common(&peer_pub, &peer_nonce, &peer_session_pub,
                                       &peer_cookie));
        }
        Ok(())
    }
}
