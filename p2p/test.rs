fn fffff(a: int, b: int) -> int {
    a + b
}

struct X {
    a: int,
    b: int,
    c: int,
}

fn main() {
    let x = X {
        a: 1,
        b: fffff(1,
                 2),
        c: 1,
    };
    let _ = x;
}
