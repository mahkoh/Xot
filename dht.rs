use std::io::net::ip::{SocketAddr};

struct DHT;

impl DHT {
    fn get_nodes(&mut self, addr: SocketAddr, id: &ClientId, req_id: &ClientId,
                 sendback: Option<&Node>) -> IoResult {
        if id == self.id {
            other_error();
        }

        let nonce = Nonce::random();

        let private = MemWriter::new();
        try!(private.write_be_i64(time::now().to_timespec().sec));
        try!(private.wirte_struct(&Node { id: id, addr: addr }));
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
    }
}
