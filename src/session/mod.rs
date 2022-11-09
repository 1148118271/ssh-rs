// pub(crate) use session_inner::SessionInner;

use std::{
    io::{Read, Write},
    net::{TcpStream, ToSocketAddrs},
    path::Path,
};

use crate::{
    algorithm::{Compress, Digest, Enc, Kex, Mac, PubKey},
    client::Client,
    config::{version::SshVersion, Config},
    error::SshResult,
};

enum SessionState<S>
where
    S: Read + Write,
{
    Init(Config, S),
    Version(Config, S),
    Auth(Client, S),
    Connected(Client, S),
}

pub struct Session<S>
where
    S: Read + Write,
{
    inner: SessionState<S>,
}

impl<S> Session<S>
where
    S: Read + Write,
{
    fn connect(self) -> SshResult<Self> {
        match self.inner {
            SessionState::Init(config, stream) => Self {
                inner: SessionState::Version(config, stream),
            }
            .connect(),
            SessionState::Version(mut config, mut stream) => {
                log::info!("start for version negotiation.");
                // Receive the server version
                let version = SshVersion::from(&mut stream)?;
                // Version validate
                version.validate()?;
                // Send Client version
                SshVersion::write(&mut stream)?;
                // Store the version info
                config.ver = version;

                // from now on
                // each step of the interaction is subject to the ssh constraints on the packet
                // so we create a client to hide the underlay details
                let client = Client::new(config);

                Self {
                    inner: SessionState::Auth(client, stream),
                }
                .connect()
            }
            SessionState::Auth(mut client, mut stream) => {
                // before auth,
                // we should have a key exchange at first
                let mut digest = Digest::new();
                client.key_agreement(&mut stream, &mut digest)?;
                client.do_auth(&mut stream, &mut digest)?;
                Ok(Self {
                    inner: SessionState::Connected(client, stream),
                })
            }
            _ => unreachable!(),
        }
    }

    pub fn close(self) {
        drop(self)
    }
}

#[derive(Default)]
pub struct SessionBuilder {
    config: Config,
}

impl SessionBuilder {
    pub fn new() -> Self {
        Self {
            ..Default::default()
        }
    }

    pub fn disable_default() -> Self {
        Self {
            config: Config::disable_default(),
        }
    }

    pub fn timeout(mut self, timeout: u64) -> Self {
        self.config.timeout = timeout;
        self
    }

    pub fn username(mut self, username: &str) -> Self {
        self.config.auth.username(username).unwrap();
        self
    }

    pub fn password(mut self, password: &str) -> Self {
        self.config.auth.password(password).unwrap();
        self
    }

    pub fn private_key<K>(mut self, private_key: K) -> Self
    where
        K: ToString,
    {
        match self.config.auth.private_key(private_key) {
            Ok(_) => (),
            Err(e) => log::error!(
                "Parse private key from string: {}, will fallback to password authentication",
                e
            ),
        }
        self
    }

    pub fn private_key_path<P>(mut self, key_path: P) -> Self
    where
        P: AsRef<Path>,
    {
        match self.config.auth.private_key_path(key_path) {
            Ok(_) => (),
            Err(e) => log::error!(
                "Parse private key from file: {}, will fallback to password authentication",
                e
            ),
        }
        self
    }

    pub fn add_kex_algorithms(mut self, alg: Kex) -> Self {
        self.config
            .algs
            .key_exchange
            .0
            .push(alg.as_str().to_owned());
        self
    }

    pub fn add_pubkey_algorithms(mut self, alg: PubKey) -> Self {
        self.config.algs.public_key.0.push(alg.as_str().to_owned());
        self
    }

    pub fn add_enc_algorithms(mut self, alg: Enc) -> Self {
        self.config
            .algs
            .c_encryption
            .0
            .push(alg.as_str().to_owned());
        self.config
            .algs
            .s_encryption
            .0
            .push(alg.as_str().to_owned());
        self
    }

    pub fn add_mac_algortihms(mut self, alg: Mac) -> Self {
        self.config.algs.c_mac.0.push(alg.as_str().to_owned());
        self.config.algs.s_mac.0.push(alg.as_str().to_owned());
        self
    }

    pub fn add_compress_algorithms(mut self, alg: Compress) -> Self {
        self.config
            .algs
            .c_compression
            .0
            .push(alg.as_str().to_owned());
        self.config
            .algs
            .s_compression
            .0
            .push(alg.as_str().to_owned());
        self
    }

    pub fn connect<A>(self, addr: A) -> SshResult<Session<TcpStream>>
    where
        A: ToSocketAddrs,
    {
        // connect tcp by default
        let tcp = TcpStream::connect(addr)?;
        // default nonblocking
        tcp.set_nonblocking(true).unwrap();
        self.connect_bio(tcp)
    }

    pub fn connect_bio<S>(self, stream: S) -> SshResult<Session<S>>
    where
        S: Read + Write,
    {
        Session {
            inner: SessionState::Init(self.config, stream),
        }
        .connect()
    }
}
