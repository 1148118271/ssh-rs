use crate::error::SshErrorKind;
use crate::{slog::log, SshError, SshResult};
#[cfg(not(target_family="wasm"))]
use std::time::{Duration, Instant};
#[cfg(target_family="wasm")]
use crate::model::time_wasm::{Duration,Instant};


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
                log::error!("time out.");
                Err(SshError::from(SshErrorKind::Timeout))
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
