//! Dependencies
//! ```
//! ssh-rs = "*"
//! ```
//!
//! Quick example:
//!
//!```
//!use std::io::{stdin, stdout, Write};
//!use std::sync::{Arc, Mutex};
//!use std::{thread, time};
//!use ssh_rs::{Channel, ChannelExec, Session, SSH};
//!fn main() {
//!     let ssh: SSH = SSH::new();
//!     // enable logging
//!     ssh.enable_log(true).unwrap();
//!     let mut session = ssh.get_session("127.0.0.1:22").unwrap();
//!     session.set_user_and_password("root", "123456");
//!     session.connect().unwrap();
//!     exec(&mut session);
//!     shell(&mut session);
//!     // t_shell(&mut session);
//! }
//!
//! fn exec(session: &mut Session) {
//!     let exec: ChannelExec = session.open_exec().unwrap();
//!     let vec = exec.send_command("ls -all").unwrap();
//!     println!("{}", String::from_utf8(vec).unwrap());
//! }
//!
//! fn shell(session: &mut Session) {
//!     let mut shell = session.open_shell().unwrap();
//!     thread::sleep(time::Duration::from_millis(200));
//!     let vec = shell.read().unwrap();
//!     let result = String::from_utf8(vec).unwrap();
//!     println!("{}", result);
//!     shell.write(b"ls -a\r").unwrap();
//!     thread::sleep(time::Duration::from_millis(200));
//!     let vec = shell.read().unwrap();
//!     let result = String::from_utf8(vec).unwrap();
//!     println!("{}", result);
//!     shell.close().unwrap();
//! }
//!
//! fn t_shell(session: &mut Session) {
//!     let shell = session.open_shell().unwrap();
//!     let c1 = Arc::new(Mutex::new(shell));
//!     let c2 = Arc::clone(&c1);
//!     let t1 = thread::spawn( move || {
//!         loop {
//!             let x = c1.lock().unwrap().read().unwrap();
//!             if x.is_empty() { continue }
//!             stdout().write(x.as_slice()).unwrap();
//!             stdout().flush().unwrap();
//!         }
//!     });
//!
//!     let t2 = thread::spawn( move || {
//!         loop {
//!             let mut cm = String::new();
//!             stdin().read_line(&mut cm).unwrap();
//!             c2.lock().unwrap().write(cm.as_bytes()).unwrap();
//!         }
//!     });
//!
//!     t1.join().unwrap();
//!     t2.join().unwrap();
//! }
//!
//!
//!
//!```



extern crate core;

mod client;
mod session;
mod channel;
mod kex;
mod channel_shell;
mod channel_exec;

mod channel_scp;
mod config;
mod util;
mod window_size;

pub use session::Session;
pub use channel::Channel;
pub use channel_shell::ChannelShell;
pub use channel_exec::ChannelExec;

use std::net::ToSocketAddrs;
use slog::{log, Slog};
use error::{SshError, SshResult};
use crate::config::Config;

pub struct SSH;

impl SSH {
    pub fn new() -> Self {
        Self
    }

    pub fn get_session<A: ToSocketAddrs>(self, adder: A) -> SshResult<Session> {
        client::connect(adder)?;
        config::init(Config::new());
        log::info!("connection to the server is successful.");
        Session.set_nonblocking(true)?;
        Ok(Session)
    }

    pub fn enable_log(&self, b: bool) -> SshResult<()> {
        if b {
            Slog::default()?
        }
        Ok(())
    }
}
