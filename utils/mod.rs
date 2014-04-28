use std::io::{IoResult, MemWriter, MemReader, BufReader, OtherIoError, standard_error};
use crypt::Machine;

pub mod ringbuffer;

pub trait Writable {
    fn write_to(&self, w: &mut Writer) -> IoResult<()>;

    fn encode(&self) -> Vec<u8> {
        let mut w = MemWriter::new();
        let _ = w.write_struct(self);
        w.unwrap()
    }
}

pub trait StructWriter : Writer {
    fn write_struct(&mut self, s: &Writable) -> IoResult<()> {
        s.write_to(self)
    }
}

impl<T: Writer> StructWriter for T { }

pub trait Readable {
    fn read_from(w: &mut Reader) -> IoResult<Self>;
}

pub trait StructReader : Reader {
    fn read_struct<T: Readable>(&mut self) -> IoResult<T> {
        Readable::read_from(self)
    }
}

impl<T: Reader> StructReader for T { }

pub trait CryptoWriter : Writer {
    fn write_encrypted(&mut self, m: &Machine, data: &[u8]) -> IoResult<()> {
        m.encrypt_to(data, self)
    }
}

impl<T: Writer> CryptoWriter for T { }

pub trait CryptoReader : Reader {
    fn read_encrypted(&mut self, m: &Machine) -> IoResult<Vec<u8>> {
        let data = try!(self.read_to_end());
        m.decrypt(data.as_slice())
    }
}

impl<T: Reader> CryptoReader for T { }

pub trait FiniteReader : Reader {
    fn remaining(&mut self) -> uint;
}

impl FiniteReader for MemReader {
    fn remaining(&mut self) -> uint {
        match self.fill_buf() {
            Ok(b) => b.len(),
            Err(_) => 0,
        }
    }
}

impl<'a> FiniteReader for BufReader<'a> {
    fn remaining(&mut self) -> uint {
        match self.fill_buf() {
            Ok(b) => b.len(),
            Err(_) => 0,
        }
    }
}

pub trait SlicableReader<'a> : Reader {
    fn slice_to_end(&'a self) -> &'a [u8];
}

impl<'a> SlicableReader<'a> for MemReader {
    fn slice_to_end(&'a self) -> &'a [u8] {
        let pos = self.tell().unwrap() as uint;
        self.get_ref().tailn(pos)
    }
}

pub fn other_error<T>() -> IoResult<T> {
    Err(standard_error(OtherIoError))
}
