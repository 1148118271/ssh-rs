use std::io;
use std::net::{Shutdown, TcpStream, ToSocketAddrs};
use std::ops::{Deref, DerefMut};
use crate::algorithm::encryption::Encryption;
use crate::error::{SshError, SshResult};
use crate::timeout::Timeout;
use crate::config::Config;


pub struct Client {
    pub(crate) stream: TcpStream,
    pub(crate) sequence: Sequence,
    pub(crate) timeout: Timeout,
    pub(crate) encryption: Option<Box<dyn Encryption>>,
    pub(crate) is_encryption: bool,
    pub(crate) session_id: Vec<u8>,
}

#[derive(Clone)]
pub(crate) struct Sequence {
    pub(crate) client_sequence_num: u32,
    pub(crate) server_sequence_num: u32
}

impl Sequence {

    pub(crate) fn client_auto_increment(&mut self) {
        if self.client_sequence_num == u32::MAX {
            self.client_sequence_num = 0;
        }
        self.client_sequence_num += 1;
    }

    pub(crate) fn server_auto_increment(&mut self) {
        if self.server_sequence_num == u32::MAX {
            self.server_sequence_num = 0;
        }
        self.server_sequence_num += 1;
    }
}

impl Client {
    pub(crate) fn connect<A: ToSocketAddrs>(addr: A, timeout_sec: u64) -> SshResult<Client> {
        match TcpStream::connect(addr) {
            Ok(stream) => {
                // default nonblocking
                stream.set_nonblocking(true).unwrap();

                Ok(
                    Client{
                        stream,
                        sequence: Sequence {
                            client_sequence_num: 0,
                            server_sequence_num: 0
                        },
                        timeout: Timeout::new(timeout_sec),
                        encryption: None,
                        is_encryption: false,
                        session_id: vec![]
                    }
                )
            }
            Err(e) => Err(SshError::from(e))
        }
    }

    pub(crate) fn version(&mut self, config: &mut Config) -> SshResult<()> {
        log::info!("start for version negotiation.");
        // 获取服务端版本
        let vec = self.read_version();
        let from_utf8 = crate::util::from_utf8(vec)?;
        let sv = from_utf8.trim();
        log::info!("server version: [{}]", sv);
        config.version.server_version = sv.to_string();
        // 发送客户端版本
        let cv = config.version.client_version.clone();
        self.write_version(format!("{}\r\n", cv.as_str()).as_bytes())?;
        log::info!("client version: [{}]", cv);
        // 版本验证
        config.version.validation()?;
        log::info!("version negotiation was successful.");
        Ok(())
    }

    pub(crate) fn close(&mut self) -> Result<(), SshError> {
        match self.stream.shutdown(Shutdown::Both) {
            Ok(o) => Ok(o),
            Err(e) => Err(SshError::from(e))
        }
    }

    pub(crate) fn is_would_block(e: &io::Error) -> bool {
        e.kind() == io::ErrorKind::WouldBlock
    }

}

impl Deref for Client {
    type Target = TcpStream;

    fn deref(&self) -> &Self::Target {
        &self.stream
    }
}

impl DerefMut for Client {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.stream
    }
}
