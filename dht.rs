use std::io::net::ip::{SocketAddr};
use std::io::{MemWriter, MemReader, IoResult};
use crypt::{Key, Nonce};
use net::{Node, IpFamily, IPv4, IPv6};
use utils;
use utils::{other_error};
use utils::bufreader::{BufReader};
use rand::{task_rng};
use std::{mem};

static MAX_SENT_NODES: uint = 4;
static GET_NODES_TIMEOUT: u64 = 3;
static BAD_NODE_TIMEOUT: u64 = 122;
static GET_NODE_INTERVAL: u64 = 20;
static KILL_NODE_TIMEOUT: u64 = 300;
static PING_INTERVAL: u64 = 60;

pub static SEND_NODES4: u8 = 3;
pub static SEND_NODES6: u8 = 4;

struct DHT;

impl DHT {
    fn get_nodes(&mut self, addr: SocketAddr, id: &Key, req_id: &Key,
                 sendback: Option<&Node>) -> IoResult<()> {
        if id == self.id {
            other_error();
        }

        let nonce = Nonce::random();

        let private = MemWriter::new();
        try!(private.write_be_u64(utils::time::sec()));
        try!(private.write_struct(&Node { id: id, addr: addr }));
        match sendback {
            Some(n) => try!(private.write_struct(n)),
            None    => try!(private.write_struct(&Node::new())),
        };

        let encrypted = MemWriter::new();
        try!(encrypted.write_struct(req_id));
        try!(encrypted.write_struct(&nonce));
        try!(encrypted.write_encrypted(self.symmetric.with_nonce(&nonce),
                                       private.get_ref()));

        let packet = MemWriter::new();
        try!(packet.write_u8(2));
        try!(packet.write_struct(&self.public));
        try!(packet.write_struct(&nonce));
        try!(packet.write_encrypted(self.precomputed(&id).with_nonce(&nonce),
                                    encrypted.get_ref()));

        self.udp.send_to(addr, packet.get_ref());
    }

    fn get_close_nodes(&self, close_to: &Key, lan_ok: bool,
                       only_hard: bool) -> Vec<Node> {
        let mut close_nodes = Vec::with_capacity(MAX_SENT_NODES);
        self.close.get_close_nodes(close_to, lan_ok, only_hard, &mut close_nodes);
        for friend in self.friends.iter() {
            // hardening is not implemented for friends
            friend.clients.get_close_nodes(close_to, lan_ok, false, &mut close_nodes);
        }
        close_nodes
    }

    fn handle_get_nodes(&mut self, addr: SocketAddr,
                        mut data: MemReader) -> IoResult<()> {
        let their_key: Key = try!(data.read_struct());
        let our_key = self.precomputed(&their_key).clone();

        let nonce: Nonce = try!(data.read_struct());
        let data = try!(data.read_encrypted(&our_key.with_nonce(&nonce)));
        let mut data = MemReader::new(data);

        let req_key: Key = try!(data.read_struct());
        let close = self.get_close_nodes(&req_key, addr);

        // IPv4:

        let mut encrypted = MemWriter::new();
        try!(encrypted.write_struct(&close.ipv4()));
        try!(encrypted.write(data.slice_to_end()));

        let nonce = Nonce::random();
        let mut packet = MemWriter::new();
        try!(packet.write_u8(SEND_NODES4));
        try!(packet.write_struct(&self.public));
        try!(packet.write_struct(&nonce));
        try!(packet.write_encrypted(our_key.with_nonce(&nonce), encrypted.get_ref()));

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
        try!(packet.write_encrypted(our_key.with_nonce(&nonce), encrypted.get_ref()));

        self.udp.send_to(addr, packet.get_ref());

        self.pinger.add(addr, their_key.clone());
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
        let our_key = self.precomputed(&their_key).clone();

        let nonce: Nonce = try!(data.read_struct());
        let data = try!(data.read_encrypted(&our_key.with_nonce(&nonce)));

        if data.len() < 160 {
            return other_error();
        }

        let nodes = match case {
            IPv4 => try!(Node::parse4(data.slice(0, data.len()-160))),
            IPv6 => try!(Node::parse( data.slice(0, data.len()-160))),
        };

        let private = BufReader::new(data.slice(data.len()-160, data.len()));
        let private_nonce: Nonce = try!(private.read_struct());
        let private =
            try!(private.read_encrypted(self.symmetric.with_nonce(&private_nonce)));
        let private = MemReader::new(private);

        let time = try!(private.read_be_u64());
        let now = utils::time::sec();
        if time + GET_NODES_TIMEOUT < now || now < time {
            return other_error();
        }
        let send_to_node: Node = try!(private.read_struct());
        let send_back_node: Node = try!(private.read_struct());
        if send_to_node.ip != addr || send_to_node.id != their_key {
            return other_error();
        }

        for node in nodes.iter() {
            if !node.ip.is_zero() && !node.id.is_broadcast() {
                self.pinger.ping(node.ip, node.id);
                self.returned_node(node, &their_key);
            }
        }

        if !send_back_node.ip.is_zero() {
            self.send_hardening_getnode_reps(send_back_node, their_key, nodes);
        }

        self.add_to_lists(addr, their_key);
    }

    fn returned_node(&mut self, node: Node, sender: Key) {
        let update_first = |mut_list| {
            for n in mut_list {
                if sender == n.id {
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
            for friend in self.friends.mut_iter() {
                if friend.id == node.id {
                    if update_first(friend.clients.mut_iter()) {
                        return;
                    }
                }
            }
        }
    }

    fn add_to_lists(&mut self, node: Node) {
        let replace = |mut_list| {
            if !mut_list.contains(&node) {
                if !mut_list.replace_bad(&node, &self.public) {
                    if !mut_list.repcale_possibly_bad(&node, &self.public) {
                        mut_list.replace_good(&node, &self.public);
                    }
                }
            }
        };
        replace(&mut self.close);
        for friend in self.friends.mut_iter() {
            replace(friend);
        }
    }

    fn add_friend(&mut self, id: &Key) {
        self.friends.add(id);
    }

    fn del_friend(&mut self, id: &Key) {
        self.friends.del(id);
    }

    fn get_friend_addr(&self, id: &Key) -> Option<SocketAddr> {
        for friend in self.friends.iter() {
            if friend.id == id {
                return friend.clients.get_addr(id);
            }
        }
        None
    }

    fn do_friends(&mut self) {
        for i in range(0, self.friends.len()) {
            match self.friends[i].do_ping_and_sendnode_requests() {
                Ok(n) => self.get_nodes(&n, &self.friends[i].id, None),
                Err(..) => { }
            }
        }
    }

    fn do_close(&mut self) {
        match self.close.do_ping_and_sendnode_requests() {
            Ok(n) => {
                self.get_nodes(&n, &self.public, None);
                return;
            },
            Err(false) => return,
            Err(true) => { /* all_kill == true */ }
        }

        // All close clients are kill. Reset them to bad so that we have someone to talk
        // to.
        let time = utils::time::sec() - BAD_NODE_TIMEOUT;
        for client in self.clients.mut_iter() {
            client.assoc4.timestamp = time;
            client.assoc6.timestamp = time;
        }
    }

    fn route_to_close(&self, to: &Key, packet: &[u8]) -> bool {
        for client in self.close.iter() {
            if client.id == to {
                if client.assoc6.addr.valid() {
                    self.udp.send_to(client.assoc6.addr, packet);
                    return true;
                } else if client.assoc4.addr.valid() {
                    self.udp.send_to(client.assoc4.addr, packet);
                    return true;
                }
                return false;
            }
        }
        return false;
    }

    fn route_to_friend(&self, to: &Key, packet: &[u8]) -> bool {
        let friend = match self.friends.iter().find(|f| f.id == to) {
            Some(f) => f,
            None => return false,
        };
        let sent = false;
        for client in friend.clients.iter() {
            if client.assoc4.addr.valid() && !client.assoc4.is_bad() {
                self.udp.send_to(client.assoc4.addr, packet);
                sent = true;
            } else if client.assoc6.addr.valid() && !client.assoc6.is_bad() {
                self.udp.send_to(client.assoc6.addr, packet);
                sent = true;
            }
        }
        return sent;
    }

    fn random_path(&self) -> Result<[Node, ..3], ()> {
        let nodes = Vec::with_capacity(3);
        if self.friends.len() == 0 {
            return Err(());
        }
        let lan_ok = false;
        let MAX_TRIES = 6;
        for _ in range(0, MAX_TRIES) {
            let friend_num = task_rng().range(0, self.friends.len());
            match self.friends[friend_num].clients.random_node(lan_ok) {
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
        let rv: [Node, ..3] = unsafe { mem::uninit() };
        for (i, v) in nodes.move_iter().enumerate() {
            rv[i] = v;
        }
        Ok(rv);
    }
}

struct ClientList {
    clients: Vec<Client>,
    bootstrap_times: u64,
    last_get_node: u64,
}

impl ClientList {
    fn random_node(&self, lan_ok: bool) -> Option<Node> {
        let possible = Vec::new();
        for (i, client) in self.clients.enumerate() {
            if !client.assoc4.is_bad() && (lan_ok || !client.assoc4.is_lan()) {
                possible.push((i, IPv4));
            }
            if !client.assoc6.is_bad() && (lan_ok || !client.assoc6.is_lan()) {
                possible.push((i, IPv6));
            }
        }
        if possible.len() == 0 {
            return None;
        }
        let val = task_rng().range(0, possible.len());
        let (i, kind) = possible[val];
        let id = self.clients[i].id.clone();
        let addr = match kind {
            IPv4 => self.clients[i].assoc4.addr,
            IPv6 => self.clients[i].assoc6.addr,
        };
        Node { id: id, addr: addr }
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
        cmp_id.sort(&mut self.clients);
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
        cmp_id.sort(&mut self.clients);
        let last = self.clients.get_mut(self.clients.len()-1);
        if cmp_id.cmp(&last.id, &n.id) == Less {
            return false;
        }
        last.replace(n);
        return true;
    }

    fn get_close_nodes(&self, close_to: &Key, lan_ok: bool, only_hard: bool,
                       nodes: &mut Vec<Node>) {
        for cand in self.clients {
            if nodes.contains(cand.id) {
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
            if addr.is_lan() && !lan_ok {
                continue;
            }
            if !addr.is_lan() && only_hard && !addr.hardened() && cand.id != close_to {
                continue;
            }
            if nodes.len() < MAX_SENT_NODES {
                nodes.push(Node { id: cand.id.clone(), addr: addr });
                if nodes.len() == MAX_SENT_NODES {
                    close_to.sort(nodes);
                }
            } else {
                if close_to.cmp(cand.id, &nodes.tail().id) == Greater {
                    continue;
                }
                nodes.pop();
                let n = nodes.len();
                while (n > 0) {
                    if close_to.cmp(cand.id, &nodes.get(n-1).id) == Greater {
                        break;
                    }
                    n -= 1;
                }
                // This is O(MAX_SENT_NODES) but MAX_SENT_NODES is only 4.
                nodes.insert(n, Node { id: cand.id.clone(), addr: addr });
            }
        }
    }

    fn get_addr(&self, id: &Key) -> Option<SocketAddr> {
        for client in self.clients.iter() {
            if client.id == id {
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

    fn do_ping_and_sendnode_requests(&mut self /* */) -> Result<Node, bool> {
        let all_kill = true;
        let possible = Vec::new();
        for (i, client) in self.clients.enumerate() {
            if !client.assoc4.is_kill() {
                all_kill = false;
                if client.assoc4.should_ping() {
                    self.pinger.send_ping(client.assoc4.addr, client.id.clone());
                }
                if !client.assoc4.is_bad() {
                    possible.push((i, IPv4));
                }
            }
            if !client.assoc6.is_kill() {
                all_kill = false;
                if client.assoc6.should_ping() {
                    self.pinger.send_ping(client.assoc6.addr, client.id.clone());
                }
                if !client.assoc6.is_bad() {
                    possible.push((i, IPv6));
                }
            }
        }
        if (self.get_node_timed_out() || self.can_bootstrap()) && possible.len() > 0 {
            self.last_get_node = utils::time::sec();
            self.bootstrap_times += 1;
            let i = task_rng().range(0, possible.len());
            let (i, family) = possible.get(i);
            match family {
                IPv4 => return Ok(self.clients[i].assoc4.node.clone()),
                IPv6 => return Ok(self.clients[i].assoc6.node.clone()),
            }
        }
        Err(all_kill)
    }
}

struct Client {
    id: Key,
    assoc4: TimedSocketAddr,
    assoc6: TimedSocketAddr,
}

impl Client {
    fn replace(&mut self, n: &Node) {
        match n.ip.family() {
            IPv4 => {
                self.assoc4.addr = n.addr;
                self.assoc4.timestamp = utils::time::sec();
                self.assoc6.addr = TimedSocketAddr::new();
                self.id = n.id.clone();
            },
            IPv6 => {
                self.assoc6.addr = n.addr;
                self.assoc6.timestamp = utils::time::sec();
                self.assoc4.addr = TimedSocketAddr::new();
                self.id = n.id.clone();
            }
        }
    }
}

struct TimedSocketAddr {
    addr: SocketAddr,
    timestamp: u64,
    last_pinged: u64,
}

impl TimedSocketAddr {
    fn new() -> TimedSocketAddr {
        unsafe { mem::init() }
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
    fn get_close_nodes(&self, id: &Key, lan_ok: bool, only_good: bool) -> Vec<Node> {
        unreachable!();
    }

    fn get_closelist_nodes(&self) -> Vec<Node> {
        unreachable!();
    }

    fn random_path(&self) -> IoResult<Box<[Node, ..3]>> {
        unreachable!();
    }

    fn route_to_friend(&self, id: &Key, data: Vec<u8>) {
        unreachable!();
    }

    fn del_friend(&self, id: &Key) {
        unreachable!();
    }

    fn refresh_friend(&self, old: &Key, new: &Key) {
        unreachable!();
    }
}
