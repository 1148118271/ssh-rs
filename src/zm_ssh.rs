use std::io;
use std::net::ToSocketAddrs;
use crate::key_exchange::KeyExchange;
use crate::Session;
use crate::session::Config;
use crate::tcp::Client;

pub struct ZmSsh;

impl ZmSsh {
    pub fn new() -> Self {
        Self
    }

    pub fn get_session<A: ToSocketAddrs>(self, adder: A) -> io::Result<Session> {
        Ok(Session {
            stream: Client::connect(adder)?,
            config: Config::new(),
            key_exchange: KeyExchange::new()
        })
    }

}