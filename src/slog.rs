pub use log;

use log::{LevelFilter, Log, Metadata, Record};

pub(crate) static SLOG: Slog = Slog;

pub struct Slog;

impl Slog {
    fn init(level: LevelFilter) {
        if let Err(e) = log::set_logger(&SLOG) {
            log::error!(
                "initialization log error, the error information is: {:?}",
                e
            );
            return;
        }
        log::set_max_level(level);
    }

    pub fn default() {
        Slog::init(LevelFilter::Info)
    }

    pub fn debug() {
        Slog::init(LevelFilter::Trace)
    }
}

impl Log for Slog {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() != LevelFilter::Off
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            println!("[SSH]-[{}]: {}", record.level(), record.args());
        }
    }

    fn flush(&self) {}
}
