use std::mem::{replace};
use std::ptr::{copy_nonoverlapping_memory};

/// A ring buffer with fixed capacity.
pub struct RingBuffer<T> {
    len: uint,
    front: uint,
    buf: Vec<Option<T>>,
}

impl<'a, T> RingBuffer<T> {
    /// Creates a new `RingBuffer` with capacity `c`.
    pub fn new(cap: uint) -> RingBuffer<T> {
        RingBuffer {
            len: 0,
            front: 0,
            buf: Vec::from_fn(cap, |_| None),
        }
    }

    /// Adds an element to the end of the buffer, possibly overwriting the front.
    pub fn push(&mut self, v: T) {
        let end = (self.front + self.len) % self.buf.len();
        *self.buf.get_mut(end) = Some(v);
        if self.len == self.buf.capacity() {
            self.front = (self.front + 1) % self.buf.len();
        } else {
            self.len += 1;
        }
    }

    /// Pops an element from the front of the buffer if the buffer is not empty.
    pub fn pop(&mut self) -> Option<T> {
        if self.len == 0 {
            return None;
        }
        let val = replace(self.buf.get_mut(self.front), None);
        self.len -= 1;
        self.front = (self.front + 1) % self.buf.len();
        val
    }

    /// Returns a reference to the front of the buffer without removing the element.
    pub fn peek(&'a mut self) -> Option<&'a T> {
        if self.len == 0 {
            return None;
        }
        self.buf.get_mut(self.front).as_ref()
    }

    /// Creates an iterator over all elements from front to back.
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

/// A fixed size buffer with holes.
/// 
/// ```rust
/// let mut buf = XBuffer::new(2);
/// buf.set_pos(1, 1.0);
/// assert!(buf.has(1));
/// assert_eq!(buf.pop(), None);
/// buf.set_pos(0, 2.0);
/// assert_eq!(buf.pop(), Some(2.0));
/// assert!(!buf.has(1));
/// assert_eq!(buf.pop(), Some(1.0));
/// ```
pub struct XBuffer<T> {
    front: uint,
    buf: Vec<Option<T>>,
}

impl<T> XBuffer<T> {
    /// Creates a new buffer with capacity `cap`.
    pub fn new(cap: uint) -> XBuffer<T> {
        assert!(cap > 0);
        XBuffer {
            front: 0,
            buf: Vec::from_fn(cap, |_| None),
        }
    }

    /// Resizes the buffer by copying all elements.
    pub fn resize(&mut self, cap: uint) {
        let prev_cap = self.buf.len();
        assert!(cap >= prev_cap);
        if cap == prev_cap {
            return;
        }
        let mut buf = Vec::with_capacity(cap);
        unsafe {
            let mut buf_ptr = buf.as_mut_ptr();
            let prev_ptr = self.buf.as_ptr();
            copy_nonoverlapping_memory(buf_ptr, prev_ptr.offset(self.front as int),
                                       prev_cap - self.front);
            buf_ptr = buf_ptr.offset(prev_cap as int - self.front as int);
            copy_nonoverlapping_memory(buf_ptr, prev_ptr, self.front);
            for _ in range(0, cap-prev_cap) {
                buf_ptr = buf_ptr.offset(1);
                *buf_ptr = None;
            }
            self.buf.set_len(0);
            buf.set_len(cap);
        }
        self.front = 0;
        self.buf = buf;
    }

    /// Sets the value at point `pos` in the buffer to `val`.
    ///
    /// `pos` is relative to the front of the buffer.
    pub fn set_pos(&mut self, pos: uint, val: T) {
        let cap = self.buf.len();
        *self.buf.get_mut((self.front + pos) % cap) = Some(val);
    }

    /// Pops the front element from the buffer if the front element is set.
    ///
    /// Otherwise the front isn't changed and `None` is returned.
    pub fn pop(&mut self) -> Option<T> {
        if self.buf.get(self.front).is_some() {
            let rv = replace(self.buf.get_mut(self.front), None);
            self.front = (self.front + 1) % self.buf.len();
            return rv;
        } else {
            return None;
        }
    }

    /// Returns the capacity of the buffer.
    pub fn cap(&self) -> uint {
        self.buf.len()
    }

    /// Returns if position `pos` has a set value.
    pub fn has(&self, pos: uint) -> bool {
        self.buf.get(pos).is_some()
    }
}
