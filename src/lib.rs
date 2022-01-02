mod packet;
mod tcp;
mod algorithms;
mod encryption;
mod session;
mod hash;
mod channel;
mod key_exchange;
mod global_variable;
mod error;
mod channel_shell;
mod channel_exec;


pub use session::Session;


use std::net::ToSocketAddrs;
use crate::error::SshError;
use crate::key_exchange::KeyExchange;
use crate::session::Config;
use crate::tcp::Client;


pub struct ZmSsh;

impl ZmSsh {
    pub fn new() -> Self {
        Self
    }

    pub fn get_session<A: ToSocketAddrs>(self, adder: A) -> Result<Session, SshError> {
        Ok(Session {
            stream: Client::connect(adder)?,
            config: Config::new(),
            key_exchange: KeyExchange::new()
        })
    }

}




#[allow(dead_code)]
pub mod strings {
    pub const CLIENT_VERSION: &'static str = "SSH-2.0-ZmSsh-0.0.1";
    pub const SSH_USERAUTH: &'static str = "ssh-userauth";
    pub const SSH_CONNECTION: &'static str = "ssh-connection";
    pub const PASSWORD: &'static str = "password";
    pub const SESSION: &'static str = "session";
    pub const SHELL: &'static str = "shell";
    pub const EXEC: &'static str = "exec";
    pub const PTY_REQ: &'static str = "pty-req";
    pub const XTERM_VAR: &'static str = "xterm-256color";
}

#[allow(dead_code)]
pub mod size {
    pub const ONE_GB: u32 = 1073741824;
    pub const BUF_SIZE: usize = 32768;
    pub const LOCAL_WINDOW_SIZE: u32 = 2097152;
}

#[allow(dead_code)]
pub mod message {
    pub const SSH_MSG_DISCONNECT: u8 = 1;
    pub const SSH_MSG_IGNORE: u8 = 2;
    pub const SSH_MSG_UNIMPLEMENTED: u8 = 3;
    pub const SSH_MSG_DEBUG: u8 = 4;
    pub const SSH_MSG_SERVICE_REQUEST: u8 = 5;
    pub const SSH_MSG_SERVICE_ACCEPT: u8 = 6;
    pub const SSH_MSG_KEXINIT: u8 = 20;
    pub const SSH_MSG_NEWKEYS: u8 = 21;
    pub const SSH_MSG_KEX_ECDH_INIT: u8 = 30;
    pub const SSH_MSG_KEX_ECDH_REPLY: u8 = 31;
    pub const SSH_MSG_USERAUTH_REQUEST: u8 = 50;
    pub const SSH_MSG_USERAUTH_FAILURE: u8 = 51;
    pub const SSH_MSG_USERAUTH_SUCCESS: u8 = 52;
    pub const SSH_MSG_GLOBAL_REQUEST: u8 = 80;
    pub const SSH_MSG_REQUEST_SUCCESS: u8 = 81;
    pub const SSH_MSG_REQUEST_FAILURE: u8 = 82;
    pub const SSH_MSG_CHANNEL_OPEN: u8 = 90;
    pub const SSH_MSG_CHANNEL_OPEN_CONFIRMATION: u8 = 91;
    pub const SSH_MSG_CHANNEL_OPEN_FAILURE: u8 = 92;
    pub const SSH_MSG_CHANNEL_WINDOW_ADJUST: u8 = 93;
    pub const SSH_MSG_CHANNEL_DATA: u8 = 94;
    pub const SSH_MSG_CHANNEL_EXTENDED_DATA: u8 = 95;
    pub const SSH_MSG_CHANNEL_EOF: u8 = 96;
    pub const SSH_MSG_CHANNEL_CLOSE: u8 = 97;
    pub const SSH_MSG_CHANNEL_REQUEST: u8 = 98;
    pub const SSH_MSG_CHANNEL_SUCCESS: u8 = 99;
    pub const SSH_MSG_CHANNEL_FAILURE: u8 = 100;
}


#[allow(dead_code)]
pub mod disconnection_message {
    pub const SSH_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT: u8 = 1;
    pub const SSH_DISCONNECT_PROTOCOL_ERROR: u8 = 2;
    pub const SSH_DISCONNECT_KEY_EXCHANGE_FAILED: u8 = 3;
    pub const SSH_DISCONNECT_RESERVED: u8 = 4;
    pub const SSH_DISCONNECT_MAC_ERROR: u8 = 5;
    pub const SSH_DISCONNECT_COMPRESSION_ERROR: u8 = 6;
    pub const SSH_DISCONNECT_SERVICE_NOT_AVAILABLE: u8 = 7;
    pub const SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED: u8 = 8;
    pub const SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE: u8 = 9;
    pub const SSH_DISCONNECT_CONNECTION_LOST: u8 = 10;
    pub const SSH_DISCONNECT_BY_APPLICATION: u8 = 11;
    pub const SSH_DISCONNECT_TOO_MANY_CONNECTIONS: u8 = 12;
    pub const SSH_DISCONNECT_AUTH_CANCELLED_BY_USER: u8 = 13;
    pub const SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE: u8 = 14;
    pub const SSH_DISCONNECT_ILLEGAL_USER_NAME: u8 = 15;
}
