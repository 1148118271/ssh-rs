use crate::error::SshErrorKind;
use crate::{slog::log, SshError, SshResult};
use std::time::Instant;

pub(crate) struct Timeout {
    instant: Instant,
    timeout_sec: u64,
}

impl Timeout {
    pub fn new(timeout_sec: u64) -> Self {
        Timeout {
            instant: Instant::now(),
            timeout_sec,
        }
    }

    pub fn test(&self) -> SshResult<()> {
        if self.timeout_sec == 0 {
            Ok(())
        } else if self.instant.elapsed().as_secs() > self.timeout_sec {
            log::error!("time out.");
            Err(SshError::from(SshErrorKind::Timeout))
        } else {
            Ok(())
        }
    }

    pub fn renew(&mut self) {
        self.instant = Instant::now();
    }
}
