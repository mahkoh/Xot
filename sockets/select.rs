//! Tools to select on sockets.

pub use self::select::{FdSet, FD_SETSIZE};

#[cfg(target_os = "windows")]
mod select {
    use std::mem;
    use std::ptr::{null};
    use std::cmp::max;
    use std::io::{IoResult};
    use libc::{c_int, c_uint, timeval};
    use native::io::net::{sock_t};

    #[link(name = "ws2_32")]
    extern "system" {
        pub fn select(nfds: c_int, readfds: *mut FdSetInt, writefds: *mut FdSetInt,
                      exceptfds: *mut FdSetInt, timeout: *timeval) -> c_int;
    }

    pub static FD_SETSIZE: uint = 64;

    struct FdSetInt {
        count: c_uint,
        bits: [sock_t, ..FD_SETSIZE],
    }

    pub struct FdSet {
        set: FdSetInt,
    }

    impl FdSet {
        pub fn zero() -> FdSet {
            unsafe { mem::init() }
        }

        pub fn set(&mut self, fd: sock_t) {
            if self.set.count as uint == FD_SETSIZE {
                return;
            }
            set.bits[set.fd_count as uint] = s;
            set.count += 1;
        }

        pub fn is_set(&self, fd: sock_t) -> bool {
            // I don't know how FD_ISSET works on Windows. 
            // Let's hope this is correct.
            for i in range(0, self.set.count) {
                if self.set.bits[i] == fd {
                    return true;
                }
            }
            return false;
        }

        pub fn read(&mut self) -> IoResult<()> {
            let rv = unsafe {
                select(0, &mut self.set as *mut FdSetInt, null(), null(), null())
            };
            match rv {
                -1 => Err(()),
                _ => Ok(())
            }
        }
    }
}


#[cfg(target_os = "macos")]
#[cfg(target_os = "android")]
#[cfg(target_os = "freebsd")]
#[cfg(target_os = "linux")]
mod select {
    use std::mem;
    use std::ptr::{null, mut_null};
    use std::cmp::max;
    use libc::{c_int, timeval};
    use native::io::net::{sock_t};
    use std::io::{IoResult, IoError};
    #[cfg(not(target_os = "macos"))]
    use std::uint;

    extern {
        fn select(nfds: c_int, readfds: *mut FdSetInt, writefds: *mut FdSetInt,
                  errorfds: *mut FdSetInt, timeout: *timeval) -> c_int;
    }

    #[cfg(target_os = "macos")]
    type BitType = i32;
    #[cfg(not(target_os = "macos"))]
    type BitType = uint;

    #[cfg(target_os = "macos")]
    static BITS: uint = 32;
    #[cfg(not(target_os = "macos"))]
    static BITS: uint = uint::BITS;

    pub static FD_SETSIZE: uint = 1024;
    
    struct FdSetInt {
        bits: [BitType, ..(FD_SETSIZE / BITS)],
    }

    /// Struct to select on sockets.
    pub struct FdSet {
        set: FdSetInt,
        max: sock_t,
    }

    impl FdSet {
        /// Returns an empty `FdSet`.
        pub fn zero() -> FdSet {
            unsafe { mem::init() }
        }

        /// Sets a file descriptor.
        pub fn set(&mut self, fd: sock_t) {
            if fd < 0 || fd as uint >= FD_SETSIZE {
                return;
            }
            let ufd = fd as uint;
            self.set.bits[ufd / BITS] |= 1 << (ufd % BITS);
            self.max = max(fd, self.max);
        }

        /// Checks if a file descriptor is set.
        pub fn is_set(&self, fd: sock_t) -> bool {
            if fd < 0 || fd as uint >= FD_SETSIZE {
                return false;
            }
            let fd = fd as uint;
            self.set.bits[fd / BITS] & (1 << (fd % BITS)) != 0
        }

        /// Blocks until one of the file descriptors becomes readable.
        pub fn read(&mut self) -> IoResult<()> {
            let rv = unsafe {
                select(self.max+1, &mut self.set as *mut FdSetInt, mut_null(), mut_null(),
                       null())
            };
            match rv {
                -1 => Err(IoError::last_error()),
                _ => Ok(()),
            }
        }
    }
}
