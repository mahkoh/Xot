use std::io::{standard_error, IoResult, EndOfFile, SeekStyle};
use std::cmp::{min};
use std::slice::bytes::{copy_memory};
use std::{uint};
use utils::{FiniteReader};

pub struct BufReader<'a> {
    buf: &'a [u8],
    pos: uint
}

impl<'a> BufReader<'a> {
    /// Creates a new buffered reader which will read the specified buffer
    pub fn new<'a>(buf: &'a [u8]) -> BufReader<'a> {
        BufReader {
            buf: buf,
            pos: 0
        }
    }

    pub fn eof(&self) -> bool { self.pos >= self.buf.len() }

    pub fn get_ref(&'a self) -> &'a [u8] {
        self.buf
    }

    pub fn slice_to_end(&'a self) -> &'a [u8] {
        self.buf.slice(self.pos, self.buf.len())
    }

    pub fn consume(&mut self, n: uint) {
        assert!(self.pos <= uint::MAX - n);
        assert!(self.pos + n <= self.buf.len());
        self.pos += n;
    }
}

impl<'a> Reader for BufReader<'a> {
    fn read(&mut self, buf: &mut [u8]) -> IoResult<uint> {
        if self.eof() { return Err(standard_error(EndOfFile)) }

        let write_len = min(buf.len(), self.buf.len() - self.pos);
        {
            let input = self.buf.slice(self.pos, self.pos + write_len);
            let output = buf.mut_slice(0, write_len);
            copy_memory(output, input);
        }
        self.pos += write_len;

        return Ok(write_len);
     }
}

impl<'a> FiniteReader for BufReader<'a> {
    fn remaining(&mut self) -> uint {
        self.buf.len() - self.pos
    }
}
