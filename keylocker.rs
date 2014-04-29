//! Container for precomputed keys.
//!
//! We use these lockers to avoid unnecessary key computations.

use crypt::{Key, PrecomputedKey};
use time::{get_time};
use std::{u8,u64};
use std::cast::{transmute_lifetime};

/// Time in seconds before the precomputed key is considered dead.
static TIMEOUT:       i64 = 600;
static KEYS_PER_SLOT: uint = 4u; // it's a plenty big number
/// Total number of keys in the locker.
static TOTAL:         uint = (u8::MAX as uint + 1u) * KEYS_PER_SLOT;

/// An object that holds precomputed keys.
pub struct Keylocker {
    secret: Key,
    holes: [Option<Entry>, ..TOTAL]
}

/// An entry in the Keylocker.
struct Entry {
    id: Key,
    computed: PrecomputedKey,
    request_count: u64,
    last_requested: i64,
}

impl Entry {
    /// Check if the entry has outlived its usefulness. 
    fn timed_out(&self) -> bool {
        self.last_requested + TIMEOUT < get_time().sec
    }
}

impl<'a> Keylocker {
    /// Create a new keylocker with secret key `secret`.
    pub fn new(secret: Key) -> Keylocker {
        Keylocker { secret: secret, holes: [None, ..TOTAL] }
    }

    /// Gets the precomputed key associated with `public` from the locker.
    ///
    /// If the key isn't in the locker yet, it's computed and possibly replaces another
    /// key.
    pub fn get(&'a mut self, public: &Key) -> &'a PrecomputedKey {
        let mut replacable = 0u;
        let mut min_requested = u64::MAX;
        for i in range(0, KEYS_PER_SLOT) {
            let index = (public.raw()[30] as uint * KEYS_PER_SLOT) + i;
            let entry = match self.holes[index] {
                Some(ref mut e) => e,
                None => {
                    min_requested = 0;
                    replacable = index;
                    continue;
                },
            };
            if entry.id == *public {
                entry.request_count += 1;
                entry.last_requested = get_time().sec;
                // Borrow checker thinks this return doesn't stop the loop.
                return unsafe { transmute_lifetime(&entry.computed) };
            }
            if min_requested > 0 {
                if entry.timed_out() {
                    min_requested = 0;
                    replacable = index;
                } else if min_requested >= entry.request_count {
                    min_requested = entry.request_count;
                    replacable = index;
                }
            }
        }

        self.holes[replacable] = Some(Entry {
            id: *public,
            computed: PrecomputedKey::new(&self.secret, public),
            request_count: 1,
            last_requested: get_time().sec,
        });

        &self.holes[replacable].as_ref().unwrap().computed
    }
}
