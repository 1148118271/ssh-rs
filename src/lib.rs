//! Dependencies
//! ```
//! ssh-rs = "*"
//! ```
//!
//! Quick example:
//!
//!```
//! use ssh_rs::ssh;
//! use ssh_rs::{ChannelExec, Session};
//! use std::thread;
//! use std::thread::sleep;          
//! use std::io::{stdin, stdout, Write};
//! use std::time::Duration;
//!
//! fn main() {
//!
//! let mut session = ssh::create_session();
//!     session.is_usage_log(true);
//!     session.set_user_and_password("root", "123456");
//!     session.connect("127.0.0.1:22").unwrap();
//!
//!     // exec(&mut session);
//!     // shell(&mut session);
//!     // t_shell(&mut session);
//!
//!
//!     // let mut scp = session.open_scp().unwrap();
//!     // file upload
//!     // scp.upload("localPath", "remotePath").unwrap();
//!     // file download
//!     // scp.download("localPath", "remotePath").unwrap();
//! }
//!
//! fn exec(session: &mut Session) {
//! let exec: ChannelExec = session.open_exec().unwrap();
//!     let vec = exec.send_command("ls -all").unwrap();
//!     println!("{}", String::from_utf8(vec).unwrap());
//! }
//!
//! fn shell(session: &mut Session) {
//! let mut shell = session.open_shell().unwrap();
//!     thread::sleep(Duration::from_millis(200));
//!     let vec = shell.read().unwrap();
//!     let result = String::from_utf8(vec).unwrap();
//!     println!("{}", result);
//!     shell.write(b"ls -a\n").unwrap();
//!     thread::sleep(Duration::from_millis(200));
//!     let vec = shell.read().unwrap();
//!     let result = String::from_utf8(vec).unwrap();
//!     println!("{}", result);
//!     shell.close().unwrap();
//! }
//!
//! fn t_shell(session: &mut Session) {
//! let mut shell = session.open_shell().unwrap();
//!     loop {
//!
//!         sleep(Duration::from_millis(300));
//!
//!         let vec = shell.read().unwrap();
//!         if vec.is_empty() { continue; }
//!         stdout().write(vec.as_slice()).unwrap();
//!         stdout().flush().unwrap();
//!
//!         let mut cm = String::new();
//!         stdin().read_line(&mut cm).unwrap();
//!         shell.write(cm.as_bytes()).unwrap();
//!
//!     }
//! }
//!```



mod client;
mod client_r;
mod client_w;
mod session;
mod channel;
mod kex;
mod channel_shell;
mod channel_exec;
mod channel_scp;
mod channel_scp_d;
mod channel_scp_u;
mod config;
mod util;
mod window_size;
mod error;
mod slog;
mod constant;
mod data;
mod packet;
mod encryption;
mod algorithm;

pub use session::Session;
pub use channel::Channel;
pub use channel_shell::ChannelShell;
pub use channel_exec::ChannelExec;

use crate::error::{SshError, SshResult};
use crate::config::Config;


pub mod ssh {
    use crate::{config, Config, Session};

    pub fn create_session() -> Session {
        config::init(Config::new());
        Session
    }

}
