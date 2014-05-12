//! Tools for encrypting, decrypting, and hashing messages.

use libc::{c_uchar, c_int, c_ulonglong, size_t, c_void};
use libc::funcs::posix88::mman::{mlock, munlock};
use rand;
use rand::{Rng};
use rand::os::{OSRng};
use std::mem;
use std::io::{IoResult, MemWriter, standard_error, OtherIoError};
use std::hash::{Hash};
use std::hash::sip::{SipState};
use utils::{Readable, Writable};
use std::num::{abs};
use std::intrinsics::{volatile_set_memory};

#[link(name = "sodium")]
extern {
    fn sodium_init();
    fn crypto_box_keypair(pk: *mut c_uchar, sk: *mut c_uchar) -> c_int;
    fn crypto_hash_sha256(h: *mut c_uchar, m: *c_uchar, len: c_ulonglong) -> c_int;
    fn crypto_box_beforenm(k: *mut c_uchar, pk: *c_uchar, sk: *c_uchar) -> c_int;
    fn crypto_box_afternm(c: *mut c_uchar, m: *c_uchar, len: c_ulonglong, n: *c_uchar,
                          k: *c_uchar) -> c_int;
    fn crypto_box_open_afternm(m: *mut c_uchar, c: *c_uchar, len: c_ulonglong,
                               n: *c_uchar, k: *c_uchar) -> c_int;
    fn crypto_secretbox(c: *mut c_uchar, m: *c_uchar, len: c_ulonglong, n: *c_uchar,
                        k: *c_uchar) -> c_int;
    fn crypto_secretbox_open(m: *mut c_uchar, c: *c_uchar, len: c_ulonglong, n: *c_uchar,
                             k: *c_uchar) -> c_int;
}

pub static KEY:     uint = 32;
pub static NONCE:   uint = 24;
pub static ZERO:    uint = 32;
pub static BOXZERO: uint = 16;
pub static HASH:    uint = 32;

mod test {
    fn test() { }
}

/// This function must be called before any other to guarantee thread safety.
pub fn init() {
    unsafe { sodium_init(); }
}

pub enum MachineType {
    Symmetric,
    Asymmetric,
}

/// Structure that can decrypt and encrypt data.
pub struct Machine<'a> {
    key: &'a Key,
    nonce: &'a Nonce,
    kind: MachineType,
}

impl<'a> Machine<'a> {
    /// Encrypts data and writes to a Writer.
    /// 
    /// Returns the result of the write operation.
    pub fn encrypt_to(&self, data: &[u8], writer: &mut Writer) -> IoResult<()> {
        let mut plain = Vec::with_capacity(data.len() + ZERO);
        let mut encrypted = Vec::from_elem(data.len() + ZERO, 0u8);
        let &Key(ref key) = self.key;
        let &Nonce(ref nonce) = self.nonce;

        plain.push_all([0u8, ..ZERO]);
        plain.push_all(data);

        unsafe {
            match self.kind {
                Symmetric => 
                    crypto_secretbox(encrypted.as_mut_ptr(), plain.as_ptr(),
                                     plain.len() as c_ulonglong, nonce.as_ptr(),
                                     key.as_ptr()),
                Asymmetric =>
                    crypto_box_afternm(encrypted.as_mut_ptr(), plain.as_ptr(),
                                       plain.len() as c_ulonglong, nonce.as_ptr(),
                                       key.as_ptr()),
            };
        }
        writer.write(encrypted.tailn(BOXZERO))
    }

    /// Encrypts data.
    pub fn encrypt(&self, data: &[u8]) -> Vec<u8> {
        let mut w = MemWriter::with_capacity(data.len() + BOXZERO);
        let _ = self.encrypt_to(data, &mut w);
        w.unwrap()
    }

    /// Decrypts data and writes to a Writer.
    /// 
    /// Returns Err(()) if decryption or the write operation fail.
    pub fn decrypt_to(&self, data: &[u8], writer: &mut Writer) -> IoResult<()> {
        let mut encrypted = Vec::with_capacity(data.len() + BOXZERO);
        let mut plain     = Vec::from_elem(data.len() + BOXZERO, 0u8);
        let &Key(ref key) = self.key;
        let &Nonce(ref nonce) = self.nonce;

        encrypted.push_all([0u8, ..BOXZERO]);
        encrypted.push_all(data);

        let rv = unsafe {
            match self.kind {
                Symmetric => 
                    crypto_secretbox_open(plain.as_mut_ptr(), encrypted.as_ptr(),
                                          encrypted.len() as c_ulonglong,
                                          nonce.as_ptr(), key.as_ptr()),
                Asymmetric =>
                    crypto_box_open_afternm(plain.as_mut_ptr(), encrypted.as_ptr(),
                                            encrypted.len() as c_ulonglong,
                                            nonce.as_ptr(), key.as_ptr()),
            }
        };
        if rv == -1 {
            return Err(standard_error(OtherIoError));
        }
        writer.write(plain.tailn(ZERO))
    }

    /// Decrypts data.
    /// 
    /// Returns None if the decryption fails.
    pub fn decrypt(&self, data: &[u8]) -> IoResult<Vec<u8>> {
        let mut w = MemWriter::new();
        match self.decrypt_to(data, &mut w) {
            Ok(_) => Ok(w.unwrap()),
            Err(e) => Err(e),
        }
    }

    pub fn kind(&self) -> MachineType {
        self.kind
    }
}

/// A key used for encryption.
pub struct Key(pub [u8, ..KEY]);

impl<'a> Key {
    /// Get the internal buffer.
    pub fn raw(&'a self) -> &'a [u8, ..KEY] {
        let &Key(ref key) = self;
        key
    }

    /// Returns a machine using symmetric encryption with the nonce.
    pub fn with_nonce(&'a self, nonce: &'a Nonce) -> Machine<'a> {
        Machine {
            key: self,
            nonce: nonce,
            kind: Symmetric,
        }
    }

    pub fn dist(&self, other: &Key) -> u64 {
        let &Key(ref my) = self;
        let &Key(ref other) = other;
        let mut dist = 0u64;
        for i in range(0u,8) {
            dist = (dist << 8) | abs((my[i] ^ other[i]) as i8) as u64;
        }
        dist
    }

    pub fn cmp(&self, one: &Key, two: &Key) -> Ordering {
        let &Key(ref my) = self;
        let &Key(ref one) = one;
        let &Key(ref two) = two;
        for i in range(0u, my.len()) {
            let dist1 = abs((my[i] ^ one[i]) as i8);
            let dist2 = abs((my[i] ^ two[i]) as i8);
            if dist1 < dist2 {
                return Less;
            } else if dist1 > dist2 {
                return Greater;
            }
        }
        Equal
    }

    pub fn sort(&self, slice: &mut [Key]) {
        slice.sort_by(|one, two| { self.cmp(one, two) });
    }
}

impl Writable for Key {
    fn write_to(&self, w: &mut Writer) -> IoResult<()> {
        let &Key(ref key) = self;
        w.write(key.as_slice())
    }
}

impl Readable for Key {
    fn read_from(r: &mut Reader) -> IoResult<Key> {
        let mut key: [u8, ..KEY] = unsafe { mem::uninit() };
        try!(r.fill(key.as_mut_slice()));
        Ok(Key(key))
    }
}

impl Eq for Key {
    fn eq(&self, other: &Key) -> bool {
        let &Key(ref my) = self;
        let &Key(ref their) = other;
        my.as_slice() == their.as_slice()
    }
}

impl TotalEq for Key { }

impl Hash for Key {
    fn hash(&self, state: &mut SipState) {
        let &Key(ref key) = self;
        key.as_slice().hash(state);
    }
}

/// Key that must not be swapped to disk and has to be securely erased.
pub struct SecretKey {
    key: ~[u8, ..KEY],
}

impl SecretKey {
    /// Create a new `SecretKey` initialized to zero.
    fn new() -> SecretKey {
        let key = box() ([0u8, ..KEY]);
        unsafe { assert_eq!(mlock(key.as_ptr() as *c_void, KEY as size_t), 0); }
        SecretKey { key: key }
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        unsafe {
            volatile_set_memory(self.key.as_mut_ptr(), 0, KEY);
            munlock(self.key.as_ptr() as *c_void, KEY as size_t);
        }
    }
}

impl Clone for SecretKey {
    fn clone(&self) -> SecretKey {
        let mut new_key = box() ([0u8, ..KEY]);
        unsafe { assert_eq!(mlock(new_key.as_ptr() as *c_void, KEY as size_t), 0); }
        *new_key = *self.key;
        SecretKey { key: new_key }
    }
}

/// Generate a new key for symmetric encryption.
pub fn key() -> Key {
    let mut key: [u8, ..KEY] = unsafe { mem::uninit() };
    OSRng::new().unwrap().fill_bytes(key.as_mut_slice());
    Key(key)
}

/// Generate a key-pair used for public key encryption.
///
/// The first key is the private key.
/// The second key is the public key.
pub fn key_pair() -> (SecretKey, Key) {
    let mut secret = SecretKey::new();
    let mut public: [u8, ..KEY] = unsafe { mem::uninit() };
    unsafe { crypto_box_keypair(public.as_mut_ptr(), secret.key.as_mut_ptr()); }
    (secret, Key(public))
}

/// A nonce used for encryption.
pub struct Nonce([u8, ..NONCE]);

impl<'a> Nonce {
    /// Generate a new random nonce.
    pub fn random() -> Nonce {
        let mut nonce: [u8, ..NONCE] = unsafe { mem::uninit() };
        OSRng::new().unwrap().fill_bytes(nonce.as_mut_slice());
        Nonce(nonce)
    }

    /// Increment the nonce.
    pub fn increment(&mut self) {
        let &Nonce(ref mut nonce) = self;
        for v in nonce.mut_iter() {
            *v = *v + 1;
            if *v != 0 {
                break;
            }
        }
    }

    /// Get the internal buffer.
    pub fn raw(&'a self) -> &'a [u8] {
        let &Nonce(ref nonce) = self;
        nonce.as_slice()
    }
}

impl Writable for Nonce {
    fn write_to(&self, w: &mut Writer) -> IoResult<()> {
        let &Nonce(ref nonce) = self;
        w.write(nonce.as_slice())
    }
}

impl Readable for Nonce {
    fn read_from(r: &mut Reader) -> IoResult<Nonce> {
        let mut nonce: [u8, ..NONCE] = unsafe { mem::uninit() };
        try!(r.fill(nonce.as_mut_slice()));
        Ok(Nonce(nonce))
    }
}

/// An encoder used for public key encryption and decryption.
pub struct PrecomputedKey {
    key: Key,
}

impl<'a> PrecomputedKey {
    /// Create a new PartialMachine with a key-pair.
    ///
    /// The first key our secret key.
    /// The second key is the other party's public key.
    pub fn new(secret: &SecretKey, &Key(ref public): &Key) -> PrecomputedKey {
        unsafe {
            let mut key: [u8, ..KEY] = mem::uninit();
            crypto_box_beforenm(key.as_mut_ptr(), public.as_ptr(), secret.key.as_ptr());
            PrecomputedKey {
                key: Key(key)
            }
        }
    }

    /// Returns a machine using asymmetric encryption with the nonce.
    pub fn with_nonce(&'a self, nonce: &'a Nonce) -> Machine<'a> {
        Machine {
            key: &self.key,
            nonce: nonce,
            kind: Asymmetric,
        }
    }
}

/// Hash data
pub fn hash(data: &[u8]) -> [u8, ..HASH] {
    unsafe {
        let mut hash: [u8, ..HASH] = unsafe { mem::uninit() };
        crypto_hash_sha256(hash.as_mut_ptr(), data.as_ptr(), data.len() as c_ulonglong);
        hash
    }
}

#[test]
fn test_symmetric() {
    let input = "hello encrypted world";
    let nonce = Nonce::random();
    let key = key();
    let encrypted = key.with_nonce(&nonce).encrypt(input.as_bytes());
    let output = key.with_nonce(&nonce).decrypt(encrypted.as_slice());
    assert!(output.is_ok());
    assert!(input.as_bytes() == output.unwrap().as_slice());
}

#[test]
fn test_asymmetric() {
    let input = "hello encrypted world";

    let nonce = Nonce::random();

    let (secret1, public1) = key_pair();
    let (secret2, public2) = key_pair();

    let e1 = PrecomputedKey::new(&secret1, &public2);
    let e2 = PrecomputedKey::new(&secret2, &public1);

    let encrypted = e1.with_nonce(&nonce).encrypt(input.as_bytes());
    let output = e2.with_nonce(&nonce).decrypt(encrypted.as_slice());

    assert!(output.is_ok());
    assert!(input.as_bytes() == output.unwrap().as_slice());
}

#[test]
fn test_hash() {
    let input = "hello hashed world";
    let hash = hash(input.as_bytes());
    assert!(hash == vec!(190, 185, 195, 17, 49, 170, 83, 221, 73, 210, 100, 157, 151, 27,
                         113, 190, 55, 114, 206, 100, 134, 135, 159, 85, 169, 174, 20,
                         153, 100, 150, 83, 218));
}
