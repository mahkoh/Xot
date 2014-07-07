use std::io::net::ip::{SocketAddr, Ipv4Addr, Ipv6Addr};
use std::io::{MemWriter, MemReader, IoResult};
use crypt::{Key, Nonce, SecretKey, PrecomputedKey};
use net::{Node, IpFamily, IPv4, IPv6, IpAddrInfo, ToIpvNNodes};
use net::sockets::{UdpWriter};
use utils;
use utils::{other_error, StructWriter, CryptoWriter, StructReader, CryptoReader,
            SlicableReader};
use utils::bufreader::{BufReader};
use std::rand::{task_rng, Rng};
use std::{mem};
use std::slice::{Items, MutItems};
use keylocker::{Keylocker};
use std::collections::hashmap::{HashMap};
use ping::{PingControl};

static MAX_SENT_NODES: uint = 4;
static GET_NODES_TIMEOUT: u64 = 3;
static BAD_NODE_TIMEOUT: u64 = 122;
static GET_NODE_INTERVAL: u64 = 20;
static KILL_NODE_TIMEOUT: u64 = 300;
static PING_INTERVAL: u64 = 60;

pub static SEND_NODES4: u8 = 3;
pub static SEND_NODES6: u8 = 4;

struct Friend {
    id: Key,
    clients: ClientList,
}

struct DHT {
    public: Key,
    symmetric: Key,
    locker: Keylocker,
    udp: UdpWriter,
    close: ClientList,
    friends: HashMap<Key, Friend>,
    pinger: PingControl,
}

impl DHT {
    fn precomputed<'a>(&'a mut self, public: &Key) -> &'a PrecomputedKey {
        self.locker.get(public)
    }

    fn get_nodes(&mut self, addr: SocketAddr, id: &Key, req_id: &Key,
                 sendback: Option<&Node>) -> IoResult<()> {
        if *id == self.public {
            return other_error();
        }

        let nonce = Nonce::random();

        let mut private = MemWriter::new();
        try!(private.write_be_u64(utils::time::sec()));
        try!(private.write_struct(&Node { id: *id, addr: addr }));
        match sendback {
            Some(n) => try!(private.write_struct(n)),
            None    => try!(private.write_struct(&Node::new())),
        };

        let mut encrypted = MemWriter::new();
        try!(encrypted.write_struct(req_id));
        try!(encrypted.write_struct(&nonce));
        try!(encrypted.write_encrypted(&self.symmetric.with_nonce(&nonce),
                                       private.get_ref()));

        let mut packet = MemWriter::new();
        try!(packet.write_u8(2));
        try!(packet.write_struct(&self.public));
        try!(packet.write_struct(&nonce));
        try!(packet.write_encrypted(&self.precomputed(id).with_nonce(&nonce),
                                    encrypted.get_ref()));

        self.udp.send_to(addr, packet.get_ref());
        Ok(())
    }

    fn get_close_nodes(&self, close_to: &Key, lan_ok: bool,
                       only_hard: bool) -> Vec<Node> {
        let mut close_nodes = Vec::with_capacity(MAX_SENT_NODES);
        self.close.get_close_nodes(close_to, lan_ok, only_hard, &mut close_nodes);
        for friend in self.friends.values() {
            // hardening is not implemented for friends
            friend.clients.get_close_nodes(close_to, lan_ok, false, &mut close_nodes);
        }
        close_nodes
    }

    fn handle_get_nodes(&mut self, addr: SocketAddr,
                        mut data: MemReader) -> IoResult<()> {
        let their_key: Key = try!(data.read_struct());
        let our_key = *self.precomputed(&their_key);

        let nonce: Nonce = try!(data.read_struct());
        let data = try!(data.read_encrypted(&our_key.with_nonce(&nonce)));
        let mut data = MemReader::new(data);

        let req_key: Key = try!(data.read_struct());
        let lan_ok = addr.ip.is_lan();
        let only_hard = true;
        let close = self.get_close_nodes(&req_key, lan_ok, only_hard);

        // IPv4:

        let mut encrypted = MemWriter::new();
        try!(encrypted.write_struct(&close.ipv4()));
        try!(encrypted.write(data.slice_to_end()));

        let nonce = Nonce::random();
        let mut packet = MemWriter::new();
        try!(packet.write_u8(SEND_NODES4));
        try!(packet.write_struct(&self.public));
        try!(packet.write_struct(&nonce));
        try!(packet.write_encrypted(&our_key.with_nonce(&nonce), encrypted.get_ref()));

        self.udp.send_to(addr, packet.get_ref());

        // IPv6:

        let mut encrypted = MemWriter::new();
        try!(encrypted.write_struct(&close.ipv6()));
        try!(encrypted.write(data.slice_to_end()));

        let nonce = Nonce::random();
        let mut packet = MemWriter::new();
        try!(packet.write_u8(SEND_NODES6));
        try!(packet.write_struct(&self.public));
        try!(packet.write_struct(&nonce));
        try!(packet.write_encrypted(&our_key.with_nonce(&nonce), encrypted.get_ref()));

        self.udp.send_to(addr, packet.get_ref());

        self.pinger.add(addr, &their_key);
        Ok(())
    }

    fn handle_send_nodes4(&mut self, addr: SocketAddr,
                          mut data: MemReader) -> IoResult<()> {
        self.handle_send_nodes(addr, data, IPv4)
    }

    fn handle_send_nodes6(&mut self, addr: SocketAddr,
                          mut data: MemReader) -> IoResult<()> {
        self.handle_send_nodes(addr, data, IPv6)
    }

    fn handle_send_nodes(&mut self, addr: SocketAddr,
                          mut data: MemReader, case: IpFamily) -> IoResult<()> {
        let their_key: Key = try!(data.read_struct());
        let our_key = *self.precomputed(&their_key);

        let nonce: Nonce = try!(data.read_struct());
        let data = try!(data.read_encrypted(&our_key.with_nonce(&nonce)));

        if data.len() < 160 {
            return other_error();
        }

        let nodes = match case {
            IPv4 => try!(Node::parse4(data.slice(0, data.len()-160))),
            IPv6 => try!(Node::parse( data.slice(0, data.len()-160))),
        };

        let mut private = BufReader::new(data.slice(data.len()-160, data.len()));
        let private_nonce: Nonce = try!(private.read_struct());
        let private =
            try!(private.read_encrypted(&self.symmetric.with_nonce(&private_nonce)));
        let mut private = MemReader::new(private);

        let time = try!(private.read_be_u64());
        let now = utils::time::sec();
        if time + GET_NODES_TIMEOUT < now || now < time {
            return other_error();
        }
        let send_to_node: Node = try!(private.read_struct());
        let send_back_node: Node = try!(private.read_struct());
        if send_to_node.addr != addr || send_to_node.id != their_key {
            return other_error();
        }

        for node in nodes.iter() {
            if !node.addr.ip.is_zero() && !node.addr.ip.is_broadcast() {
                self.pinger.add(node.addr, &node.id);
                self.returned_node(node, &their_key);
            }
        }

        if !send_back_node.addr.ip.is_zero() {
            self.send_hardening_getnode_reps(&send_back_node, &their_key, nodes);
        }

        self.add_to_lists(&Node { addr: addr, id: their_key });
        Ok(())
    }

    fn send_hardening_getnode_reps(&self, n: &Node, k: &Key, n: Vec<Node>) {
        unreachable!();
    }

    fn returned_node(&mut self, node: &Node, sender: &Key) {
        let update_first = |mut mut_list: MutItems<Client>| {
            for n in mut_list {
                if *sender == n.id {
                    match node.family() {
                        IPv4 => {
                            n.assoc4.ret_addr = node.addr;
                            n.assoc4.ret_time = utils::time::sec();
                        },
                        IPv6 => {
                            n.assoc6.ret_addr = node.addr;
                            n.assoc6.ret_time = utils::time::sec();
                        }
                    }
                    return true;
                }
            }
            return false;
        };
        if node.id == self.public {
            update_first(self.close.mut_iter());
        } else {
            for (_, friend) in self.friends.mut_iter() {
                if friend.id == node.id {
                    if update_first(friend.clients.mut_iter()) {
                        return;
                    }
                }
            }
        }
    }

    fn add_to_lists(&mut self, node: &Node) {
        let public = &self.public;
        let replace = |mut_list: &mut ClientList| {
            if !mut_list.contains(&node.id) {
                if !mut_list.replace_bad(node) {
                    if !mut_list.replace_possibly_bad(node, public) {
                        mut_list.replace_good(node, public);
                    }
                }
            }
        };
        replace(&mut self.close);
        for (_, friend) in self.friends.mut_iter() {
            replace(&mut friend.clients);
        }
    }

    fn add_friend(&mut self, id: &Key) {
        let friend = Friend {
            id: *id,
            clients: ClientList::new(),
        };
        self.friends.insert(*id, friend);
    }

    fn del_friend(&mut self, id: &Key) {
        self.friends.remove(id);
    }

    fn get_friend_addr(&self, id: &Key) -> Option<SocketAddr> {
        for friend in self.friends.values() {
            if friend.id == *id {
                return friend.clients.get_addr(id);
            }
        }
        None
    }

    fn do_friends(&mut self) {
        let mut pairs = Vec::new();
        for (_, friend) in self.friends.mut_iter() {
            match friend.clients.do_ping_and_sendnode_requests(&self.pinger) {
                Ok(n) => pairs.push((n, friend.id)),
                Err(..) => { }
            }
        }
        for &(n, id) in pairs.iter() {
            self.get_nodes(n.addr, &n.id, &id, None);
        }
    }

    fn do_close(&mut self) {
        match self.close.do_ping_and_sendnode_requests(&self.pinger) {
            Ok(n) => {
                let public = self.public;
                self.get_nodes(n.addr, &n.id, &public, None);
                return;
            },
            Err(false) => return,
            Err(true) => { /* all_kill == true */ }
        }

        // All close clients are kill. Reset them to bad so that we have someone to talk
        // to.
        let time = utils::time::sec() - BAD_NODE_TIMEOUT;
        for client in self.close.mut_iter() {
            client.assoc4.timestamp = time;
            client.assoc6.timestamp = time;
        }
    }

    fn route_to_close(&mut self, to: &Key, packet: &[u8]) -> bool {
        for client in self.close.mut_iter() {
            if client.id == *to {
                if !client.assoc6.addr.ip.is_zero() {
                    self.udp.send_to(client.assoc6.addr, packet);
                    return true;
                } else if !client.assoc4.addr.ip.is_zero() {
                    self.udp.send_to(client.assoc4.addr, packet);
                    return true;
                }
                return false;
            }
        }
        return false;
    }

    fn route_to_friend(&self, to: &Key, packet: &[u8]) -> bool {
        let friend = match self.friends.values().find(|f| *to == f.id) {
            Some(f) => f,
            None => return false,
        };
        let mut sent = false;
        for client in friend.clients.iter() {
            if !client.assoc4.addr.ip.is_zero() && !client.assoc4.is_bad() {
                self.udp.send_to(client.assoc4.addr, packet);
                sent = true;
            } else if !client.assoc6.addr.ip.is_zero() && !client.assoc6.is_bad() {
                self.udp.send_to(client.assoc6.addr, packet);
                sent = true;
            }
        }
        return sent;
    }

    fn random_path(&mut self) -> Result<[Node, ..3], ()> {
        let mut nodes = Vec::with_capacity(3);
        if self.friends.len() < 3 {
            return Err(());
        }
        let lan_ok = false;
        let max_tries = 6;
        for _ in range::<uint>(0, max_tries) {
            let friend_num = task_rng().gen_range(0, self.friends.len());
            let (_, friend) = self.friends.mut_iter().nth(friend_num).unwrap();
            match friend.clients.random_node(lan_ok) {
                Some(n) => nodes.push(n),
                None => continue,
            }
            if nodes.len() == 3 {
                break;
            }
        }
        if nodes.len() != 3 {
            return Err(())
        }
        let mut rv: [Node, ..3] = unsafe { mem::uninitialized() };
        for (i, v) in nodes.move_iter().enumerate() {
            rv[i] = v;
        }
        Ok(rv)
    }
}

struct ClientList {
    clients: Vec<Client>,
    bootstrap_times: u64,
    last_get_node: u64,
}

impl ClientList {
    fn new() -> ClientList {
        ClientList {
            clients: Vec::new(),
            bootstrap_times: 0,
            last_get_node: 0,
        }
    }

    fn contains(&self, id: &Key) -> bool {
        self.clients.iter().any(|c| c.id == *id)
    }

    fn random_node(&mut self, lan_ok: bool) -> Option<Node> {
        let mut possible = Vec::new();
        for (i, client) in self.clients.mut_iter().enumerate() {
            if !client.assoc4.is_bad() && (lan_ok || !client.assoc4.addr.ip.is_lan()) {
                possible.push((i, IPv4));
            }
            if !client.assoc6.is_bad() && (lan_ok || !client.assoc6.addr.ip.is_lan()) {
                possible.push((i, IPv6));
            }
        }
        if possible.len() == 0 {
            return None;
        }
        let &(i, kind) = task_rng().choose(possible.as_slice()).unwrap();
        let client = self.clients.get_mut(i);
        let addr = match kind {
            IPv4 => client.assoc4.addr,
            IPv6 => client.assoc6.addr,
        };
        Some(Node { id: client.id, addr: addr })
    }

    fn replace_bad(&mut self, n: &Node) -> bool {
        for client in self.clients.mut_iter() {
            if client.assoc4.is_bad() && client.assoc6.is_bad() {
                client.replace(n);
                return true;
            }
        }
        return false;
    }

    fn replace_possibly_bad(&mut self, n: &Node, cmp_id: &Key) -> bool {
        self.clients.sort_by(|c1, c2| cmp_id.cmp(&c1.id, &c2.id));
        for client in self.clients.mut_iter().rev() {
            if !client.assoc4.hardened() && !client.assoc6.hardened() {
                client.replace(n);
                return true;
            }
        }
        return false;
    }

    fn replace_good(&mut self, n: &Node, cmp_id: &Key) -> bool {
        if self.clients.len() == 0 {
            return false;
        }
        self.clients.sort_by(|c1, c2| cmp_id.cmp(&c1.id, &c2.id));
        let last = {
            let len = self.clients.len();
            self.clients.get_mut(len-1)
        };
        if cmp_id.cmp(&last.id, &n.id) == Less {
            return false;
        }
        last.replace(n);
        return true;
    }

    fn get_close_nodes(&self, close_to: &Key, lan_ok: bool, only_hard: bool,
                       nodes: &mut Vec<Node>) {
        for cand in self.clients.iter() {
            if nodes.iter().any(|n| n.id == cand.id) {
                continue;
            }
            let addr = if cand.assoc4.timestamp > cand.assoc6.timestamp {
                &cand.assoc4
            } else {
                &cand.assoc6
            };
            if addr.is_bad() {
                continue;
            }
            if addr.addr.ip.is_lan() && !lan_ok {
                continue;
            }
            if !addr.addr.ip.is_lan() && only_hard && !addr.hardened() &&
                    cand.id != *close_to {
                continue;
            }
            if nodes.len() < MAX_SENT_NODES {
                nodes.push(Node { id: cand.id, addr: addr.addr });
                if nodes.len() == MAX_SENT_NODES {
                    nodes.sort_by(|n1, n2| close_to.cmp(&n1.id, &n2.id));
                }
            } else {
                if close_to.cmp(&cand.id, &nodes.last().unwrap().id) == Greater {
                    continue;
                }
                nodes.pop();
                let mut n = nodes.len();
                while n > 0 {
                    if close_to.cmp(&cand.id, &nodes.get(n-1).id) == Greater {
                        break;
                    }
                    n -= 1;
                }
                // This is O(MAX_SENT_NODES) but MAX_SENT_NODES is only 4.
                nodes.insert(n, Node { id: cand.id, addr: addr.addr });
            }
        }
    }

    fn get_addr(&self, id: &Key) -> Option<SocketAddr> {
        for client in self.clients.iter() {
            if client.id == *id {
                if !client.assoc4.is_bad() {
                    return Some(client.assoc4.addr);
                }
                if !client.assoc6.is_bad() {
                    return Some(client.assoc6.addr);
                }
            }
        }
        None
    }

    fn get_node_timed_out(&self) -> bool {
        self.last_get_node + GET_NODE_INTERVAL < utils::time::sec()
    }

    fn do_ping_and_sendnode_requests(&mut self,
                                     pinger: &PingControl) -> Result<Node, bool> {
        let mut all_kill = true;
        let mut possible = Vec::new();
        for (i, client) in self.clients.mut_iter().enumerate() {
            if !client.assoc4.is_kill() {
                all_kill = false;
                if client.assoc4.should_ping() {
                    pinger.send_ping(client.assoc4.addr, &client.id);
                }
                if !client.assoc4.is_bad() {
                    possible.push((i, IPv4));
                }
            }
            if !client.assoc6.is_kill() {
                all_kill = false;
                if client.assoc6.should_ping() {
                    pinger.send_ping(client.assoc6.addr, &client.id);
                }
                if !client.assoc6.is_bad() {
                    possible.push((i, IPv6));
                }
            }
        }
        if (self.get_node_timed_out() || self.can_bootstrap()) && possible.len() > 0 {
            self.last_get_node = utils::time::sec();
            self.bootstrap_times += 1;
            let &(i, family) = task_rng().choose(possible.as_slice()).unwrap();
            let client = self.clients.get(i);
            let addr = match family {
                IPv4 => client.assoc4.addr,
                IPv6 => client.assoc6.addr
            };
            return Ok(Node { id: client.id, addr: addr });
        }
        Err(all_kill)
    }

    fn can_bootstrap(&self) -> bool {
        unreachable!();
    }

    fn iter<'a>(&'a self) -> Items<'a, Client> {
        self.clients.iter()
    }

    fn mut_iter<'a>(&'a mut self) -> MutItems<'a, Client> {
        self.clients.mut_iter()
    }
}

struct Client {
    id: Key,
    assoc4: TimedSocketAddr,
    assoc6: TimedSocketAddr,
}

impl Client {
    fn replace(&mut self, n: &Node) {
        match n.addr.ip {
            Ipv4Addr(..) => {
                self.assoc4.addr = n.addr;
                self.assoc4.timestamp = utils::time::sec();
                self.assoc6 = TimedSocketAddr::new();
                self.id = n.id;
            },
            Ipv6Addr(..) => {
                self.assoc6.addr = n.addr;
                self.assoc6.timestamp = utils::time::sec();
                self.assoc4 = TimedSocketAddr::new();
                self.id = n.id;
            }
        }
    }
}

struct TimedSocketAddr {
    ret_addr: SocketAddr,
    ret_time: u64,
    addr: SocketAddr,
    timestamp: u64,
    last_pinged: u64,
}

impl TimedSocketAddr {
    fn hardened(&self) -> bool {
        unreachable!();
    }

    fn new() -> TimedSocketAddr {
        unsafe { mem::zeroed() }
    }

    fn is_bad(&self) -> bool {
        self.timestamp + BAD_NODE_TIMEOUT < utils::time::sec()
    }

    fn is_kill(&self) -> bool {
        self.timestamp + KILL_NODE_TIMEOUT < utils::time::sec()
    }

    fn should_ping(&self) -> bool {
        self.last_pinged + PING_INTERVAL >= utils::time::sec()
    }
}

pub struct DHTControl;

impl DHTControl {
    pub fn get_close_nodes(&self, id: &Key, lan_ok: bool, only_good: bool) -> Vec<Node> {
        unreachable!();
    }

    pub fn get_closelist_nodes(&self) -> Vec<Node> {
        unreachable!();
    }

    pub fn random_path(&self) -> IoResult<Box<[Node, ..3]>> {
        unreachable!();
    }

    pub fn route_to_friend(&self, id: &Key, data: Vec<u8>) {
        unreachable!();
    }

    pub fn del_friend(&self, id: &Key) {
        unreachable!();
    }

    pub fn refresh_friend(&self, old: &Key, new: &Key) {
        unreachable!();
    }

    pub fn add_friend(&self, id: &Key) {
        unreachable!();
    }

    pub fn get_all_nodes(&self, nodes: Vec<Node>, id: &Key) {
        unreachable!();
    }
}
