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
//!     session.set_user_and_password("root".to_string(), "123456".to_string());
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




mod packet;
mod tcp;
mod encryption;
mod session;
mod hash;
mod channel;
mod kex;
mod global;
mod channel_shell;
mod channel_exec;

pub mod error;
mod channel_scp;
mod config;
mod util;
mod slog;

pub use session::Session;
pub use channel::Channel;
pub use channel_shell::ChannelShell;
pub use channel_exec::ChannelExec;

use std::net::ToSocketAddrs;
use std::sync::Mutex;
use crate::config::Config;
use crate::encryption::{CURVE25519, KeyExchange, PublicKey};
use crate::encryption::rsa::RSA;
use crate::error::{SshError, SshResult};
use crate::slog::Slog;
use crate::tcp::Client;


pub struct SSH;

impl SSH {
    pub fn new() -> Self {
        Self
    }

    pub fn get_session<A: ToSocketAddrs>(self, adder: A) -> SshResult<Session> {
        util::update_client(
            Some(Mutex::new(Client::connect(adder)?))
        );

        util::update_config(
            Some(
                Mutex::new(Config::new()))
        );

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


#[allow(dead_code)]
pub mod strings {
    pub const CLIENT_VERSION            :&'static str = "SSH-2.0-SSH_RS-0.1.3";
    pub const SSH_USERAUTH              :&'static str = "ssh-userauth";
    pub const SSH_CONNECTION            :&'static str = "ssh-connection";
    pub const PASSWORD                  :&'static str = "password";
    pub const SESSION                   :&'static str = "session";
    pub const SHELL                     :&'static str = "shell";
    pub const EXEC                      :&'static str = "exec";
    pub const SCP                       :&'static str = "scp";
    pub const PTY_REQ                   :&'static str = "pty-req";
    pub const XTERM_VAR                 :&'static str = "xterm-256color";
}

#[allow(dead_code)]
pub mod permission {
    // 文件夹默认权限
    pub const DIR                       :&'static str = "775";
    // 文件默认权限
    pub const FILE                      :&'static str = "664";
}

#[allow(dead_code)]
pub mod scp_arg {
    pub const SOURCE                    :&'static str = "-f";
    pub const SINK                      :&'static str = "-t";
    pub const RECURSIVE                 :&'static str = "-r";
    pub const VERBOSE                   :&'static str = "-v";
    pub const PRESERVE_TIMES            :&'static str = "-p";
    pub const QUIET                     :&'static str = "-q";
    pub const LIMIT                     :&'static str = "-l";
}


#[allow(dead_code)]
pub mod scp_flag {
    pub const T                         :u8   = 'T' as u8;
    pub const D                         :u8   = 'D' as u8;
    pub const C                         :u8   = 'C' as u8;
    pub const E                         :u8   = 'E' as u8;
    // '\0'
    pub const END                       :u8   = 0;
    pub const ERR                       :u8   = 1;
    pub const FATAL_ERR                 :u8   = 2;
}


#[allow(dead_code)]
pub mod size {
    pub const ONE_GB                    :u32    = 1073741824;
    pub const BUF_SIZE                  :usize  = 32768;
    pub const LOCAL_WINDOW_SIZE         :u32    = 2097152;
}


#[allow(dead_code)]
pub mod message {
    pub const SSH_MSG_DISCONNECT                                :u8 = 1;
    pub const SSH_MSG_IGNORE                                    :u8 = 2;
    pub const SSH_MSG_UNIMPLEMENTED                             :u8 = 3;
    pub const SSH_MSG_DEBUG                                     :u8 = 4;
    pub const SSH_MSG_SERVICE_REQUEST                           :u8 = 5;
    pub const SSH_MSG_SERVICE_ACCEPT                            :u8 = 6;
    pub const SSH_MSG_KEXINIT                                   :u8 = 20;
    pub const SSH_MSG_NEWKEYS                                   :u8 = 21;
    pub const SSH_MSG_KEX_ECDH_INIT                             :u8 = 30;
    pub const SSH_MSG_KEX_ECDH_REPLY                            :u8 = 31;
    pub const SSH_MSG_USERAUTH_REQUEST                          :u8 = 50;
    pub const SSH_MSG_USERAUTH_FAILURE                          :u8 = 51;
    pub const SSH_MSG_USERAUTH_SUCCESS                          :u8 = 52;
    pub const SSH_MSG_GLOBAL_REQUEST                            :u8 = 80;
    pub const SSH_MSG_REQUEST_SUCCESS                           :u8 = 81;
    pub const SSH_MSG_REQUEST_FAILURE                           :u8 = 82;
    pub const SSH_MSG_CHANNEL_OPEN                              :u8 = 90;
    pub const SSH_MSG_CHANNEL_OPEN_CONFIRMATION                 :u8 = 91;
    pub const SSH_MSG_CHANNEL_OPEN_FAILURE                      :u8 = 92;
    pub const SSH_MSG_CHANNEL_WINDOW_ADJUST                     :u8 = 93;
    pub const SSH_MSG_CHANNEL_DATA                              :u8 = 94;
    pub const SSH_MSG_CHANNEL_EXTENDED_DATA                     :u8 = 95;
    pub const SSH_MSG_CHANNEL_EOF                               :u8 = 96;
    pub const SSH_MSG_CHANNEL_CLOSE                             :u8 = 97;
    pub const SSH_MSG_CHANNEL_REQUEST                           :u8 = 98;
    pub const SSH_MSG_CHANNEL_SUCCESS                           :u8 = 99;
    pub const SSH_MSG_CHANNEL_FAILURE                           :u8 = 100;
}


#[allow(dead_code)]
pub mod disconnection_message {
    pub const SSH_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT        :u8 = 1;
    pub const SSH_DISCONNECT_PROTOCOL_ERROR                     :u8 = 2;
    pub const SSH_DISCONNECT_KEY_EXCHANGE_FAILED                :u8 = 3;
    pub const SSH_DISCONNECT_RESERVED                           :u8 = 4;
    pub const SSH_DISCONNECT_MAC_ERROR                          :u8 = 5;
    pub const SSH_DISCONNECT_COMPRESSION_ERROR                  :u8 = 6;
    pub const SSH_DISCONNECT_SERVICE_NOT_AVAILABLE              :u8 = 7;
    pub const SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED     :u8 = 8;
    pub const SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE            :u8 = 9;
    pub const SSH_DISCONNECT_CONNECTION_LOST                    :u8 = 10;
    pub const SSH_DISCONNECT_BY_APPLICATION                     :u8 = 11;
    pub const SSH_DISCONNECT_TOO_MANY_CONNECTIONS               :u8 = 12;
    pub const SSH_DISCONNECT_AUTH_CANCELLED_BY_USER             :u8 = 13;
    pub const SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE     :u8 = 14;
    pub const SSH_DISCONNECT_ILLEGAL_USER_NAME                  :u8 = 15;
}


#[allow(dead_code)]
pub mod algorithms {
    pub const DH_CURVE25519_SHA256                              :&'static str = "curve25519-sha256";
    pub const DH_ECDH_SHA2_NISTP256                             :&'static str = "ecdh-sha2-nistp256";

    pub const PUBLIC_KEY_ED25519                                :&'static str = "ssh-ed25519";
    pub const PUBLIC_KEY_RSA                                    :&'static str = "ssh-rsa";

    pub const ENCRYPTION_CHACHA20_POLY1305_OPENSSH              :&'static str = "chacha20-poly1305@openssh.com";

    pub const MAC_ALGORITHMS                                    :&'static str = "none";

    pub const COMPRESSION_ALGORITHMS                            :&'static str = "none";
}
