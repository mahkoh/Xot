use std::comm::{Select, Receiver, Handle, TryRecvError, Disconnected};
use std::io::timer::{Timer};
use std::mem::{transmute};

struct Ticker<'a> {
    select: &'a Select,
    timer: Timer,
    recv: Option<Receiver<()>>,
    handle: Option<Handle<'a, ()>>,
}

impl<'a> Ticker<'a> {
    fn new(select: &'a Select) -> Ticker<'a> {
        Ticker {
            select: select,
            timer: Timer::new().unwrap(),
            recv: None,
            handle: None,
        }
    }

    fn set_interval<'b>(&'b mut self, msec: u64) {
        self.handle = None;
        self.recv = Some(self.timer.periodic(msec));
        unsafe {
            let handle = (*self.select).handle(self.recv.as_ref().unwrap());
            self.handle = Some(transmute::<Handle<'b, ()>, Handle<'a, ()>>(handle));
            self.handle.as_mut().unwrap().add();
        }
    }

    fn try_recv(&self) -> Result<(), TryRecvError> {
        match self.recv {
            Some(ref r) => r.try_recv(),
            None => Err(Disconnected),
        }
    }
}

trait AddMany {
    fn add_many<'a, T, U>(&self, many: &mut [T], f: |&'a T| -> &'a Receiver<U>,
                          g: |&'a mut T| -> &'a mut Option<Handle<'a, U>>);

    fn remove_many<'a, T, U>(&self, many: &mut [T],
                             g: |&'a mut T| -> &'a mut Option<Handle<'a, U>>);
}

impl AddMany for Select {
    fn add_many<'a, 'b, T, U>(&self, many: &'b mut [T], f: |&'a T| -> &'a Receiver<U>,
                          g: |&'a mut T| -> &'a mut Option<Handle<'a, U>>) {
        for t in many.mut_iter() {
            unsafe {
                let handle = self.handle(f(t));
                *g(t) = Some(transmute::<Handle<'b, U>,Handle<'a, U>>(handle));
                g(t).as_mut().unwrap().add();
            }
        }
    }

    fn remove_many<'a, T, U>(&self, many: &mut [T],
                             g: |&'a mut T| -> &'a mut Option<Handle<'a, U>>) {
        for t in many.mut_iter() {
            *g(t) = None;
        }
    }
}
