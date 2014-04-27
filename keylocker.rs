use crypt::{Key, PrecomputedKey};
use time::{get_time};
use std::{u8,u64};
use std::cast::{transmute_lifetime};

static TIMEOUT:       i64 = 600;
static KEYS_PER_SLOT: uint = 4u; // it's a plenty big number
static TOTAL:         uint = (u8::MAX as uint + 1u) * KEYS_PER_SLOT;

pub struct Keylocker {
    secret: Key,
    holes: [Option<Entry>, ..TOTAL]
}

struct Entry {
    id: Key,
    computed: PrecomputedKey,
    request_count: u64,
    last_requested: i64,
}

impl Entry {
    fn timed_out(&self) -> bool {
        self.last_requested + TIMEOUT < get_time().sec
    }
}

impl<'a> Keylocker {
    pub fn new(secret: Key) -> Keylocker {
        Keylocker { secret: secret, holes: [None, ..TOTAL] }
    }

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
