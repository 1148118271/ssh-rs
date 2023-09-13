use crate::{SshError, SshResult};
use std::time::{Duration, Instant};

pub(crate) struct Timeout {
    instant: Instant,
    timeout: Option<Duration>,
}

impl Timeout {
    pub fn new(timeout: Option<Duration>) -> Self {
        Timeout {
            instant: Instant::now(),
            timeout,
        }
    }

    pub fn test(&self) -> SshResult<()> {
        if let Some(t) = self.timeout {
            if self.instant.elapsed() > t {
                tracing::error!("time out.");
                Err(SshError::TimeoutError)
            } else {
                Ok(())
            }
        } else {
            Ok(())
        }
    }

    pub fn renew(&mut self) {
        self.instant = Instant::now();
    }
}
