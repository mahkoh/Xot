use time::{precise_time_ns};

pub fn sec() -> u64 {
    precise_time_ns() / 1_000_000_000
}

pub fn milli() -> u64 {
    precise_time_ns() / 1_000_000
}

pub fn micro() -> u64 {
    precise_time_ns() / 1_000
}

pub fn nano() -> u64 {
    precise_time_ns()
}
