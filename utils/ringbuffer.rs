use std::mem::{replace};

pub struct RingBuffer<T> {
    len: uint,
    front: uint,
    buf: Vec<Option<T>>,
}

impl<'a, T> RingBuffer<T> {
    pub fn new(cap: uint) -> RingBuffer<T> {
        RingBuffer {
            len: 0,
            front: 0,
            buf: Vec::from_fn(cap, |_| None),
        }
    }

    pub fn push(&mut self, v: T) {
        let end = (self.front + self.len) % self.buf.capacity();
        *self.buf.get_mut(end) = Some(v);
        if self.len == self.buf.capacity() {
            self.front = (self.front + 1) % self.buf.capacity();
        } else {
            self.len += 1;
        }
    }

    pub fn pop(&mut self) -> Option<T> {
        if self.len == 0 {
            return None;
        }
        let val = replace(self.buf.get_mut(self.front), None);
        self.len -= 1;
        self.front = (self.front + 1) % self.buf.capacity();
        val
    }

    pub fn peek(&'a mut self) -> Option<&'a T> {
        if self.len == 0 {
            return None;
        }
        self.buf.get_mut(self.front).as_ref()
    }

    pub fn iter(&'a self) -> RingBufIter<'a, T> {
        RingBufIter {
            pos: 0,
            buf: self,
        }
    }
}

pub struct RingBufIter<'a, T> {
    pos: uint,
    buf: &'a RingBuffer<T>,
}

impl<'a, T> Iterator<&'a T> for RingBufIter<'a, T> {
    fn next(&mut self) -> Option<&'a T> {
        if self.pos == self.buf.len {
            return None;
        }
        self.pos += 1;
        self.buf.buf.get((self.buf.front + self.pos - 1)
                           % self.buf.buf.capacity()).as_ref()
    }
}
