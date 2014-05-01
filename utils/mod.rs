use std::io::{IoResult, MemWriter, MemReader, BufReader, OtherIoError, standard_error,
              IoError, EndOfFile};
use crypt::Machine;
use time;

pub mod ringbuffer;

/// A trait for objects which can be writte via `writer.write_struct()`.
pub trait Writable {
    /// Write the object to `w`.
    fn write_to(&self, w: &mut Writer) -> IoResult<()>;

    /// Write the object to a `MemWriter` and return the resulting vector.
    fn encode(&self) -> Vec<u8> {
        let mut w = MemWriter::new();
        let _ = w.write_struct(self);
        w.unwrap()
    }
}

/// A trait for `Writer`s which can write `Writable` objects.
pub trait StructWriter : Writer {
    /// Write `s`.
    fn write_struct(&mut self, s: &Writable) -> IoResult<()> {
        s.write_to(self)
    }
}

impl<T: Writer> StructWriter for T { }

/// A trait for objects which can be read via `writer.read_struct()`.
pub trait Readable {
    /// Read the object from `w`.
    fn read_from(w: &mut Reader) -> IoResult<Self>;
}

/// A trait for `Reader`s which can read `Readable` objects.
pub trait StructReader : Reader {
    /// Read an object.
    fn read_struct<T: Readable>(&mut self) -> IoResult<T> {
        Readable::read_from(self)
    }
}

impl<T: Reader> StructReader for T { }

/// A trait for `Writer`s which can write encrypted data.
pub trait CryptoWriter : Writer {
    /// Encrypts `data` via `m` and writes it to the stream.
    fn write_encrypted(&mut self, m: &Machine, data: &[u8]) -> IoResult<()> {
        m.encrypt_to(data, self)
    }
}

impl<T: Writer> CryptoWriter for T { }

/// A trait for `Reader`s which can read encrypted data.
pub trait CryptoReader : Reader {
    /// Decrypts the rest of the stream via `m`.
    fn read_encrypted(&mut self, m: &Machine) -> IoResult<Vec<u8>> {
        let data = try!(self.read_to_end());
        m.decrypt(data.as_slice())
    }
}

impl<T: Reader> CryptoReader for T { }

/// A trait for `Reader`s which have a finite know length.
pub trait FiniteReader : Reader {
    /// Returns the remaining bytes in the `Reader`.
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

/// A trait for `Reader`s which can return a slice of the remaining stream without having
/// to copy the data.
pub trait SlicableReader<'a> : Reader {
    fn slice_to_end(&'a self) -> &'a [u8];
}

impl<'a> SlicableReader<'a> for MemReader {
    fn slice_to_end(&'a self) -> &'a [u8] {
        let pos = self.tell().unwrap() as uint;
        self.get_ref().tailn(pos)
    }
}

/// Returns the standard error of type `OtherIoError`.
pub fn other_error<T>() -> IoResult<T> {
    Err(standard_error(OtherIoError))
}

/// Returns the current time in micro seconds.
pub fn micro_time() -> u64 {
    let now = time::get_time();
    (now.sec as u64 * 1000000) + (now.nsec as u64 / 1000)
}

impl Readable for Vec<u32> {
    fn read_from(w: &mut Reader) -> IoResult<Vec<u32>> {
        let mut buf = Vec::new();
        loop {
            let v = match w.read_be_u32() {
                Ok(v) => v,
                Err(e) => match e.kind {
                    EndOfFile => return Ok(buf),
                    _ => return Err(IoError::last_error()),
                }
            };
            buf.push(v);
        }
    }
}

impl Writable for Vec<u32> {
    fn write_to(&self, w: &mut Writer) -> IoResult<()> {
        self.as_slice().write_to(w)
    }
}

impl<'a> Writable for &'a [u32] {
    fn write_to(&self, w: &mut Writer) -> IoResult<()> {
        for x in self.iter() {
            try!(w.write_be_u32(*x));
        }
        Ok(())
    }
}

pub fn parse_hex(s: &str, buf: &mut [u8]) -> Result<(),()> {
    if s.len() != 2*buf.len() {
        return Err(());
    }
    for i in range(0u, buf.len()) {
        for j in range(0u, 2) {
            buf[i] = (buf[i] << 4) + match s[2*i + j] as char {
                c @ '0' .. '9' => (c as u8) - ('0' as u8),
                c @ 'a' .. 'f' => (c as u8) - ('a' as u8) + 10,
                c @ 'A' .. 'F' => (c as u8) - ('A' as u8) + 10,
                _              => return Err(()),
            }
        }
    }
    return Ok(());
}
