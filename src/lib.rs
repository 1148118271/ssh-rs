//! Dependencies
//! ```toml
//! ssh-rs = "0.3.3"
//! ```
//!
//!Rust implementation of ssh2.0 client.
//!
//! Basic usage
//! ```no_run
//! use ssh_rs::ssh;
//!
//! ssh::debug();
//!
//! let mut session = ssh::create_session()
//!     .username("ubuntu")
//!     .password("password")
//!     .private_key_path("./id_rsa")
//!     .connect("127.0.0.1:22")
//!     .unwrap()
//!     .run_local();
//! let exec = session.open_exec().unwrap();
//! let vec: Vec<u8> = exec.send_command("ls -all").unwrap();
//! println!("{}", String::from_utf8(vec).unwrap());
//! // Close session.
//! session.close();
//! ```
//! For more usage examples and details, please see the
//! [Readme](https://github.com/1148118271/ssh-rs) &
//! [Examples](https://github.com/1148118271/ssh-rs/tree/main/examples)
//! in our [git repo](https://github.com/1148118271/ssh-rs)
//!

pub mod algorithm;
mod channel;
mod client;
mod config;
mod constant;
mod model;
mod session;
mod slog;
mod util;

pub mod error;

pub use channel::*;
pub(crate) use error::SshError;
pub use error::{SshErrorKind, SshResult};
pub use model::{TerminalSize, TerminalSizeType};
pub use session::{LocalSession, SessionBroker, SessionBuilder, SessionConnector};

pub mod ssh {
    use crate::{session::SessionBuilder, slog::Slog};

    /// create a session via session builder w/ default configuration
    ///
    pub fn create_session() -> SessionBuilder {
        SessionBuilder::new()
    }

    /// create a session via session builder w/o default configuration
    ///
    pub fn create_session_without_default() -> SessionBuilder {
        SessionBuilder::disable_default()
    }

    /// set the global log level to `INFO`
    ///
    pub fn enable_log() {
        Slog::default()
    }

    /// set the global log level to `TRACE`
    ///
    /// for diagnostic purposes only
    pub fn debug() {
        Slog::debug()
    }
}
