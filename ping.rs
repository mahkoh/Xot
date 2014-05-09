//! The layer which handles ping requests and responses.

use std::io::net::ip::{SocketAddr};
use std::io::{IoResult, MemReader, MemWriter};
use std::io::timer::{Timer};
use crypt::{Nonce, Key, PrecomputedKey};
use net::{LLRcv, LLSnd};
use net::consts::{PING_REQUEST, PING_RESPONSE};
use utils;
use utils::{other_error, StructReader, StructWriter, CryptoReader, CryptoWriter};
use utils::ringbuffer::{RingBuffer};
use net::sockets::{UdpWriter};
use keylocker::{Keylocker};
use rand::{task_rng, Rng};

/// Maximum number of peers whose pongs we're waiting for.
static MAX_PINING: uint = 512;
/// Maximum number of peers we send a ping to every `TIME_TO_PING` seconds.
static MAX_TO_PING: uint = 16;
/// How long we wait between pings.
static TIME_TO_PING: u64 = 5;
/// Time before a ping request is considered timed out.
static PING_TIMEOUT: i64  = 3;

/// An object which represents a ping request.
struct Ping {
    /// Adderss of the peer we're pinging.
    addr: SocketAddr,
    /// Time when we sent the ping.
    time: u64,
    /// Secret ping id we sent with the ping.
    id: u64,
}

impl Ping {
    /// Check if the ping request has timed out.
    fn timed_out(&self) -> bool {
        self.time + PING_TIMEOUT < utils::time::sec()
    }
}

/// Object running the ping task.
struct Pinger {
    udp: UdpWriter,
    locker: Keylocker,
    /// List of peers we've to ping during the next interval.
    to_ping: [Option<(SocketAddr, Key)>, ..MAX_TO_PING],
    /// List of pings we've sent.
    pinging: RingBuffer<Ping>,
    /// The public key we're signing our pings with.
    public: Key,
}

impl Pinger {
    /*
    /// The main loop.
    /// 
    /// Checks for incoming pings and pongs, and pings the peers regularly.
    fn run(&mut self, req: LLRcv, rsp: LLRcv) {
        let mut timer = Timer::new().unwrap();
        let periodic = timer.periodic(TIME_TO_PING * 1000);

        loop {
            select!(
                ()           = periodic.recv()      => self.ping(),
                (addr, data) = req.recv() => {self.handle_ping_request(addr, data);},
                (addr, data) = rsp.recv() => {self.handle_ping_response(addr, data);}
            );
        }
    }
    */

    /// Get a precomputed key from the locker.
    fn precomputed<'b>(&'b mut self, public: &Key) -> &'b PrecomputedKey {
        self.locker.get(public)
    }

    /// Add a peer to the to-be-pinged list if it's closer than the other ones.
    fn add_to_ping(&mut self, addr: SocketAddr, id: &Key) {
        for ping in self.to_ping.as_mut_slice().mut_iter() {
            if ping.is_none() {
                *ping = Some((addr, id.clone()));
                return;
            }
        }
        for ping in self.to_ping.as_mut_slice().mut_iter() {
            let &(ref mut refaddr, ref mut refid) = ping.as_mut().unwrap();
            if self.public.cmp(id, refid) == Less {
                *refaddr = addr;
                *refid = id.clone();
                return;
            }
        }
    }

    /// Remove timed-out elements from the `pinging` list.
    fn remove_timeouts(&mut self) {
        loop {
            match self.pinging.peek() {
                Some(x) => {
                    if !x.timed_out() {
                        return;
                    }
                },
                None => return,
            };
            self.pinging.pop();
        }
    }

    /// Get's the ping id which we sent to `addr` if any.
    fn ping_id(&self, addr: SocketAddr) -> Option<u64> {
        for ping in self.pinging.iter() {
            if ping.addr == addr {
                return Some(ping.id);
            }
        }
        return None;
    }

    /// Adds `addr` and `ping_id` to the `pinging` list.
    fn add_pinging(&mut self, addr: SocketAddr, ping_id: u64) {
        self.remove_timeouts();
        self.pinging.push(Ping {
            addr: addr,
            time: utils::time::sec(),
            id: ping_id,
        });
    }

    /// Pings all elements in `to_ping` and clears `to_ping` afterwards.
    fn ping(&mut self) {
        for i in range(0, MAX_TO_PING) {
            let (addr, id) = match self.to_ping[i] {
                Some(ref x) => x.clone(),
                None => continue,
            };
            self.to_ping[i] = None;
            if self.ping_id(addr).is_some() {
                continue;
            }

            let ping_id = task_rng().next_u64();
            let mut private = MemWriter::new();
            let _ = private.write_be_u64(ping_id);

            let nonce = Nonce::random();
            let mut packet = MemWriter::new();
            let _ = packet.write_u8(PING_REQUEST);
            let _ = packet.write_struct(&self.public);
            let _ = packet.write_struct(&nonce);
            let _ = {
                let key = self.precomputed(&id);
                packet.write_encrypted(&key.with_nonce(&nonce), private.get_ref());
            };

            if self.udp.send_to(addr, packet.get_ref()).is_ok() {
                self.add_pinging(addr, ping_id);
            }
        }
    }

    /// Adds the peer to the `to_ping` list and pongs him immediately.
    fn handle_ping_request(&mut self, addr: SocketAddr,
                           mut req: MemReader) -> IoResult<()> {
        let id: Key = try!(req.read_struct());
        let mut nonce: Nonce = try!(req.read_struct());
        let key = self.precomputed(&id).clone();
        let data = try!(req.read_encrypted(&key.with_nonce(&nonce)));

        self.add_to_ping(addr, &id);

        let mut resp = MemWriter::new();
        nonce = Nonce::random();
        try!(resp.write_u8(PING_RESPONSE));
        try!(resp.write_struct(&self.public));
        try!(resp.write_struct(&nonce));
        try!(resp.write_encrypted(&key.with_nonce(&nonce), data.as_slice()));

        self.udp.send_to(addr, resp.get_ref())
    }

    /// Checks if the ping id is correct and adds the peer to the DHT.
    fn handle_ping_response(&mut self, addr: SocketAddr,
                            mut resp: MemReader) -> IoResult<()> {
        let ping_id = match self.ping_id(addr) {
            Some(i) => i,
            None => return other_error(),
        };
        let id: Key = try!(resp.read_struct());
        let nonce: Nonce = try!(resp.read_struct());
        let key = self.precomputed(&id);
        let data = try!(resp.read_encrypted(&key.with_nonce(&nonce)));

        if ping_id == try!(MemReader::new(data).read_be_u64()) {
            return other_error();
        }
        // self.add_to_dht(addr, id);
        Ok(())
    }
}
