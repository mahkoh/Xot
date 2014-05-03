use std::io::net::ip::{SocketAddr};
use std::io::{MemWriter, MemReader};
use crypt::{Key, Nonce};

struct DHT;

impl DHT {
    fn get_nodes(&mut self, addr: SocketAddr, id: &ClientId, req_id: &ClientId,
                 sendback: Option<&Node>) -> IoResult {
        if id == self.id {
            other_error();
        }

        let nonce = Nonce::random();

        let private = MemWriter::new();
        try!(private.write_be_u64(utils::time::sec()));
        try!(private.write_struct(&Node { id: id, addr: addr }));
        match sendback {
            Some(n) => try!(private.write_struct(n)),
            None    => try!(private.write(Node::encoded_empty())),
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
        if get_node_timed_out(time) {
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
                    match node.ip.family() {
                        IPv4 => {
                            close.assoc4.ret_addr = node.addr;
                            close.assoc4.ret_time = utils::time::sec();
                        },
                        IPv6 => {
                            close.assoc6.ret_addr = node.addr;
                            close.assoc6.ret_time = utils::time::sec();
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
}

struct ClientList {
    clients: Vec<Client>,
    bootstrap_times: u64,
    last_get_node: u64,
}

impl ClientList {
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
                    pinger.send_ping(client.assoc4.addr, client.id.clone());
                }
                if !client.assoc4.is_bad() {
                    possible.push((i, IPv4));
                }
            }
            if !client.assoc6.is_kill() {
                all_kill = false;
                if client.assoc6.should_ping() {
                    pinger.send_ping(client.assoc6.addr, client.id.clone());
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

struct TimedSocketAddr {
    addr: SocketAddr,
    timestamp: u64,
    last_pinged: u64,
}

impl TimedSocketAddr {
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
