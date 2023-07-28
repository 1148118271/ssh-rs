pub use log;

use log::{LevelFilter, Log, Metadata, Record};
#[cfg(target_family="wasm")]
use wasm_bindgen::prelude::wasm_bindgen;
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

#[cfg(target_family="wasm")]
#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console, js_name = log)]
    fn console_log(s: &str);
}

impl Log for Slog {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() != LevelFilter::Off
    }

    #[cfg(not(target_family="wasm"))]
    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            println!("[SSH]-[{}]: {}", record.level(), record.args());
        }
    }

    #[cfg(target_family="wasm")]
    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            console_log(&format!("[Rust SSH]-[{}]: {}", record.level(), record.args()));
        }
    }

    fn flush(&self) {}
}
