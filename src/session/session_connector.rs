use crate::{
    algorithm::Digest,
    client::Client,
    config::{
        algorithm::AlgList,
        version::SshVersion,
        Config,
    },
    error::SshResult,
    model::{Packet, SecPacket},
    LocalSession, SessionBroker,
};
use async_recursion::async_recursion;
use std::io::{Read, Write};

pub(crate) enum SessionState<S>
where
    S: Read + Write,
{
    Init(Config, S),
    Version(Config, S),
    Auth(Client, S),
    Connected(Client, S),
}

pub struct SessionConnector<S>
where
    S: Read + Write,
{
    pub(crate) inner: SessionState<S>,
}

impl<S> SessionConnector<S>
where
    S: Read + Write,
{
    pub(super) fn connect(self) -> SshResult<Self> {
        match self.inner {
            SessionState::Init(config, stream) => Self {
                inner: SessionState::Version(config, stream),
            }
            .connect(),
            SessionState::Version(mut config, mut stream) => {
                log::info!("start for version negotiation.");
                // Receive the server version
                let version = SshVersion::from(&mut stream, config.timeout)?;
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
                let server_algs = SecPacket::from_stream(&mut stream, &mut client)?;
                digest.hash_ctx.set_i_s(server_algs.get_inner());
                let server_algs = AlgList::unpack(server_algs)?;
                client.key_agreement(&mut stream, server_algs, &mut digest)?;
                client.do_auth(&mut stream, &mut digest)?;
                Ok(Self {
                    inner: SessionState::Connected(client, stream),
                })
            }
            _ => unreachable!(),
        }
    }

    /// To run this ssh session on the local thread
    ///
    /// It will return a [LocalSession] which doesn't support multithread concurrency
    ///
    pub fn run_local(self) -> LocalSession<S> {
        if let SessionState::Connected(client, stream) = self.inner {
            LocalSession::new(client, stream)
        } else {
            unreachable!("Why you here?")
        }
    }

    /// close the session and consume it
    ///
    pub fn close(self) {
        drop(self)
    }
}

impl<S> SessionConnector<S>
where
    S: Read + Write + Send + 'static,
{
    /// To spwan a new thread to run this ssh session
    ///
    /// It will return a [SessionBroker] which supports multithread concurrency
    ///
    pub fn run_backend(self) -> SessionBroker {
        if let SessionState::Connected(client, stream) = self.inner {
            SessionBroker::new(client, stream)
        } else {
            unreachable!("Why you here?")
        }
    }
}

pub(crate) enum AsyncSessionState<S>
where
    S: async_std::io::Read + async_std::io::Write,
{
    Init(Config, S),
    Version(Config, S),
    Auth(Client, S),
    Connected(Client, S),
}

pub struct SessionAsyncConnector<S>
where
    S: async_std::io::Read + async_std::io::Write,
{
    pub(crate) inner: AsyncSessionState<S>,
}

impl<S> SessionAsyncConnector<S>
where
    S: async_std::io::Read + async_std::io::Write + std::marker::Send + Unpin + 'static,
{
    #[async_recursion]
    pub(super) async fn connect(self) -> SshResult<Self> {
        match self.inner {
            AsyncSessionState::Init(config, stream) => {
                Self {
                    inner: AsyncSessionState::Version(config, stream),
                }
                .connect()
                .await
            }
            AsyncSessionState::Version(mut config, mut stream) => {
                let version = SshVersion::from_async(&mut stream).await?;
                version.validate()?;
                SshVersion::async_write(&mut stream).await?;
                config.ver = version;
                let client = Client::new(config);
                Ok(Self {
                    inner: AsyncSessionState::Auth(client, stream),
                }
                .connect()
                .await?)
            },
            AsyncSessionState::Auth(mut client, mut stream) => {
                // before auth,
                // we should have a key exchange at first
                let server_algs = SecPacket::from_stream_async(&mut stream, &mut client).await?;
                let mut digest = Digest::new();
                digest.hash_ctx.set_i_s(server_algs.get_inner());
                let server_algs = AlgList::unpack(server_algs)?;
                client.key_agreement_async(&mut stream, server_algs, &mut digest).await?;
                client.do_auth_async(&mut stream, &mut digest).await?;
                Ok(Self {
                    inner: AsyncSessionState::Connected(client, stream),
                })
            },
            _ => unreachable!(),
        }
    }
}
