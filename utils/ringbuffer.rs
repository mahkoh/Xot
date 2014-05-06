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

    pub fn resize(&mut self, cap: uint) {
        assert!(cap >= self.buf.len());
        if cap == self.buf.len() {
            return;
        }
        unsafe { resize_ring(&mut self.buf, self.front, cap); }
        self.front = 0;
    }

    pub fn len(&self) -> uint {
        self.len;
    }

    pub fn remove_while(&mut self, f: |&T| -> bool) {
        loop {
            if self.len == 0 {
                return;
            }
            if !f(self.buf.get(self.front)) {
                return;
            }
            *self.buf.get(self.front) = None;
            self.len -= 1;
            self.front += 1;
            if self.front == self.buf.len() {
                self.front = 0;
            }
        }
    }

    /// Adds an element to the end of the buffer, possibly overwriting the front.
    pub fn push(&mut self, v: T) {
        let end = (self.front + self.len) % self.buf.len();
        *self.buf.get_mut(end) = Some(v);
        if self.len == self.buf.len() {
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
                           % self.buf.buf.len()).as_ref()
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
        unsafe { resize_ring(&mut self.buf, self.front, cap); }
        self.front = 0;
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

/// Creates a new vector and copies the old one.
///
/// `cap` must be larger than the old capacity.
unsafe fn resize_ring<T>(old: &mut Vec<Option<T>>, front: uint, cap: uint) {
    let old_cap = old.len();
    let mut new = Vec::with_capacity(cap);
    let mut new_ptr = new.as_mut_ptr();
    let old_ptr = old.as_ptr();
    copy_nonoverlapping_memory(new_ptr, old_ptr.offset(front as int),
                               old_cap - front);
    new_ptr = new_ptr.offset(old_cap as int - front as int);
    copy_nonoverlapping_memory(new_ptr, old_ptr, front);
    for _ in range(0, cap-old_cap) {
        new_ptr = new_ptr.offset(1);
        *new_ptr = None;
    }
    old.set_len(0);
    new.set_len(cap);
    *old = new;
}
