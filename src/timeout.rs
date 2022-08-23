use std::cell::RefCell;
use std::time::{Duration, SystemTime};
use crate::{slog::log, SshError, SshResult};
use crate::error::SshErrorKind;


pub(crate) static mut TIMEOUT: u64 = 15;

pub(crate) struct Timeout(RefCell<SystemTime>);

impl Timeout {
    pub(crate) fn new() -> Self {
        let time = SystemTime::now();
        let time = unsafe { time + Duration::from_secs(TIMEOUT) };
        Timeout(RefCell::new(time))
    }

    pub(crate) fn is_timeout(&self) -> SshResult<()> {
        let time = SystemTime::now();
        if time > *self.0.borrow() {
            log::error!("time out.");
            return Err(SshError::from(SshErrorKind::Timeout))
        }
        Ok(())
    }

    pub(crate) fn renew(&self) {
        let mut ref_mut = self.0.borrow_mut();
        *ref_mut = unsafe { SystemTime::now() + Duration::from_secs(TIMEOUT) };
    }
}