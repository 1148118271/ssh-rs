use crate::error::SshErrorKind;
use crate::{slog::log, SshError, SshResult};
use std::time::Instant;

pub(crate) struct Timeout {
    instant: Instant,
    timeout_millisec: u128,
}

impl Timeout {
    pub fn new(timeout_millisec: u128) -> Self {
        Timeout {
            instant: Instant::now(),
            timeout_millisec,
        }
    }

    pub fn test(&self) -> SshResult<()> {
        if self.timeout_millisec == 0 {
            Ok(())
        } else if self.instant.elapsed().as_millis() > self.timeout_millisec {
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
