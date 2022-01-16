use log::{Level, LevelFilter, Log, Metadata, Record};
use crate::error::{SshErrorKind, SshResult};
use crate::global::SLOG;
use crate::SshError;

pub(crate) struct Slog;


impl Slog {
    pub fn init(level: LevelFilter)-> SshResult<()> {
        if let Err(e) = log::set_logger(&SLOG) {
            return Err(SshError::from(SshErrorKind::LogError))
        }
        log::set_max_level(level);
        Ok(())
    }

    pub fn default() -> SshResult<()> {
        Slog::init(LevelFilter::Trace)
    }
}



impl Log for Slog {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() != LevelFilter::Off
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            println!("[SSH-{}]: {}", record.level(), record.args());
        }
    }

    fn flush(&self) {}
}