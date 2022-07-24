use std::time::{Duration, SystemTime};
use crate::{SshError, SshResult};
use crate::error::SshErrorKind;


pub(crate) static mut TIMEOUT: u64 = 15;

pub(crate) struct Timeout(SystemTime);

impl Timeout {
    pub(crate) fn new() -> Self {
        let time = SystemTime::now();
        let time = unsafe { time + Duration::from_secs(TIMEOUT) };
        Timeout(time)
    }

    pub(crate) fn is_timeout(&self) -> SshResult<()> {
        let time = SystemTime::now();
        if time > self.0 {
            return Err(SshError::from(SshErrorKind::Timeout))
        }
        Ok(())
    }
}