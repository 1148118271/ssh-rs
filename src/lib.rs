//! Dependencies
//! ```toml
//! ssh-rs = "0.3.0"
//! ```
//!
//! ## Connection method：
//!
//! ### 1. Password:
//! ```no_run
//! use ssh_rs::ssh;
//!
//! let mut session = ssh::create_session()
//!     .username("username")
//!     .password("password")
//!     .build();
//! session.connect("ip:port").unwrap();
//! ```
//!
//! ### 2. Public key:
//! #### Currently, only `RSA-PKCS#1-PEM` type encrypted files with the encryption format `-----BEGIN RSA PRIVATE KEY-----` are supported.
//!
//! #### 1. Use key file path：
//! ```no_run
//! use ssh_rs::ssh;
//!
//! // pem format key path -> /xxx/xxx/id_rsa
//! let mut session = ssh::create_session()
//!     .username("username")
//!     .private_key_path("/path/to/rsa")
//!     .build();
//! session.connect("ip:port").unwrap();
//! ```
//!
//! #### 2. Use key string：
//! ```no_run
//! use ssh_rs::ssh;
//!
//! // pem format key string:
//! //      -----BEGIN RSA PRIVATE KEY-----
//! //          xxxxxxxxxxxxxxxxxxxxx
//! //      -----END RSA PRIVATE KEY-----
//! let mut session = ssh::create_session()
//!     .username("username")
//!     .private_key("rsa_string")
//!     .build();
//! session.connect("ip:port").unwrap();
//! ```
//!
//! ## 3. Use them together
//! According to the implementation of OpenSSH,
//! it will try public key first and fallback to password.
//! So both of them can be provided.
//! ```no_run
//! use ssh_rs::ssh;
//!
//! let mut session = ssh::create_session()
//!     .username("username")
//!     .password("password")
//!     .private_key_path("/path/to/rsa")
//!     .build();
//! session.connect("ip:port").unwrap();
//! ```
//!
//! ## Enable global logging：
//!
//! ```no_run
//! use ssh_rs::ssh;
//!
//! // is_enable_log Whether to enable global logging
//! // The default is false(Do not enable)
//! // Can be set as true (enable)
//! ssh::is_enable_log(true);
//! ```
//!
//!
//! ## Set timeout：
//!
//! ```no_run
//! use ssh_rs::ssh;
//!
//! // set_timeout
//! // The unit is seconds
//! // The default timeout is 30 seconds
//! let mut session = ssh::create_session()
//!     .timeout(15)
//!     .username("username")
//!     .password("password")
//!     .build();
//! session.connect("ip:port").unwrap();
//! ```
//!
//!
//! ## How to use：
//!
//! ### Currently only supports exec shell scp these three functions.
//!
//! ### 1. exec
//!
//! ```no_run
//! use ssh_rs::ssh;
//!
//! ssh::is_enable_log(true);
//!
//! let mut session = ssh::create_session()
//!     .username("username")
//!     .password("password")
//!     .private_key_path("./id_rsa")
//!     .build();
//! session.connect("127.0.0.1:22").unwrap();
//!
//! // Usage 1
//! let exec = session.open_exec().unwrap();
//! let vec: Vec<u8> = exec.send_command("ls -all").unwrap();
//! println!("{}", String::from_utf8(vec).unwrap());
//! // Usage 2
//! let channel = session.open_channel().unwrap();
//! let exec = channel.open_exec().unwrap();
//! let vec: Vec<u8> = exec.send_command("ls -all").unwrap();
//! println!("{}", String::from_utf8(vec).unwrap());
//! // Close session.
//! session.close();
//! ```
//!
//! ### 2. shell
//!
//! ```no_run
//! use std::thread::sleep;
//! use std::time::Duration;
//! use ssh_rs::{ChannelShell, ssh};
//!
//! let mut session = ssh::create_session()
//!     .username("username")
//!     .password("password")
//!     .build();
//! session.connect("127.0.0.1:22").unwrap();
//! // Usage 1
//! let mut shell = session.open_shell().unwrap();
//! run_shell(&mut shell);
//! // Usage 2
//! let channel = session.open_channel().unwrap();
//! let mut shell = channel.open_shell().unwrap();
//! run_shell(&mut shell);
//! // Close channel.
//! shell.close().unwrap();
//! // Close session.
//! session.close();
//!
//! fn run_shell(shell: &mut ChannelShell<std::net::TcpStream>) {
//!     sleep(Duration::from_millis(500));
//!     let vec = shell.read().unwrap();
//!     println!("{}", String::from_utf8(vec).unwrap());
//!
//!     shell.write(b"ls -all\n").unwrap();
//!
//!     sleep(Duration::from_millis(500));
//!
//!     let vec = shell.read().unwrap();
//!     println!("{}", String::from_utf8(vec).unwrap());
//! }
//! ```
//!
//! ### 3. scp
//!
//! ```no_run
//! use ssh_rs::ssh;
//!
//! let mut session = ssh::create_session()
//!     .username("username")
//!     .password("password")
//!     .build();
//! session.connect("127.0.0.1:22").unwrap();
//! // Usage 1
//! let scp = session.open_scp().unwrap();
//! scp.upload("local path", "remote path").unwrap();
//!
//! let scp = session.open_scp().unwrap();
//! scp.download("local path", "remote path").unwrap();
//!
//! // Usage 2
//! let channel = session.open_channel().unwrap();
//! let scp = channel.open_scp().unwrap();
//! scp.upload("local path", "remote path").unwrap();
//!
//! let channel = session.open_channel().unwrap();
//! let scp = channel.open_scp().unwrap();
//! scp.download("local path", "remote path").unwrap();
//!
//! session.close();
//!
//! ```
//!
//! ### 4.bio
//!
//! ```no_run
//! use ssh_rs::ssh;
//! use std::net::{TcpStream, ToSocketAddrs};
//!
//! let mut session = ssh::create_session();
//! let bio = MyProxy::new("127.0.0.1:22");
//! let mut session = ssh::create_session()
//!     .username("username")
//!     .password("password")
//!     .build();
//! session.connect_bio(bio).unwrap();
//! // Usage 1
//! let exec = session.open_exec().unwrap();
//! let vec: Vec<u8> = exec.send_command("ls -all").unwrap();
//! println!("{}", String::from_utf8(vec).unwrap());
//! // Usage 2
//! let channel = session.open_channel().unwrap();
//! let exec = channel.open_exec().unwrap();
//! let vec: Vec<u8> = exec.send_command("ls -all").unwrap();
//! println!("{}", String::from_utf8(vec).unwrap());
//! // Close session.
//! session.close();
//!
//! // Use a real ssh server since I don't wanna implement a ssh-server in the example codes
//! struct MyProxy {
//!     server: TcpStream,
//! }
//!
//! impl MyProxy {
//!     fn new<A>(addr: A) -> Self
//!     where
//!         A: ToSocketAddrs,
//!     {
//!         Self {
//!             server: TcpStream::connect(addr).unwrap(),
//!         }
//!     }
//! }
//!
//! impl std::io::Read for MyProxy {
//!     fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
//!         self.server.read(buf)
//!     }
//! }
//!
//! impl std::io::Write for MyProxy {
//!     fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
//!         self.server.write(buf)
//!     }
//!
//!     fn flush(&mut self) -> std::io::Result<()> {
//!         self.server.flush()
//!     }
//! }
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
pub use session::{BackendSession, LocalSession, SessionBuilder, SessionConnector};

use crate::error::{SshError, SshResult};

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
