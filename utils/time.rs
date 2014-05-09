use time::{precise_time_ns};

pub fn sec() -> u64 {
    precise_time_ns() / 1_000_000
}
