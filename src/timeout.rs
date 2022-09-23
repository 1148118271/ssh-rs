use std::time::{Duration, SystemTime};
use crate::{slog::log, SshError, SshResult};
use crate::error::SshErrorKind;

pub(crate) struct Timeout {
    time: SystemTime,
    timeout_sec: u64
}

impl Timeout {
    pub(crate) fn new(timeout_sec: u64) -> Self {
        let time = SystemTime::now();
        let time = time + Duration::from_secs(timeout_sec);
        Timeout {
            time,
            timeout_sec
        }
    }

    pub(crate) fn is_timeout(&self) -> SshResult<()> {
        let time = SystemTime::now();
        if time > self.time {
            log::error!("time out.");
            return Err(SshError::from(SshErrorKind::Timeout))
        }
        Ok(())
    }

    pub(crate) fn renew(&mut self) {
        self.time = SystemTime::now() + Duration::from_secs(self.timeout_sec);
    }
}