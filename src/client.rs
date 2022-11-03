use crate::algorithm::encryption::Encryption;
use crate::client_r::Signature;
use crate::error::{SshError, SshResult};
use crate::timeout::Timeout;
use crate::config::Config;
use crate::user_info::UserInfo;
use crate::h::H;
use std::io;
use std::net::{Shutdown, TcpStream, ToSocketAddrs};
use std::ops::{Deref, DerefMut};


pub struct Client {
    pub(crate) stream: TcpStream,
    pub(crate) sequence: Sequence,
    pub(crate) timeout: Timeout,
    pub(crate) config: Config,
    pub(crate) encryption: Option<Box<dyn Encryption>>,
    pub(crate) is_encryption: bool,
    /// session id
    /// 只使用第一次密钥交换生成的
    pub(crate) session_id: Vec<u8>,
    pub(crate) w_size: usize,
    pub(crate) signature: Option<Signature>,
    pub(crate) is_r_1_gb: bool,
    pub(crate) is_w_1_gb: bool
}

#[derive(Clone)]
pub(crate) struct Sequence {
    pub(crate) client_sequence_num: u32,
    pub(crate) server_sequence_num: u32,
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
    pub(crate) fn connect<A: ToSocketAddrs>(addr: A, timeout_sec: u64, user_info: UserInfo) -> SshResult<Client> {
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
                        config: Config::new(user_info),
                        encryption: None,
                        is_encryption: false,
                        session_id: vec![],
                        w_size: 0,
                        signature: None,
                        is_r_1_gb: false,
                        is_w_1_gb: false
                    }
                )
            }
            Err(e) => Err(SshError::from(e)),
        }
    }

    pub(crate) fn version(&mut self, h: &mut H) -> SshResult<()> {
        log::info!("start for version negotiation.");
        // 获取服务端版本
        let vec = self.read_version();
        let from_utf8 = crate::util::from_utf8(vec)?;
        let sv = from_utf8.trim();
        log::info!("server version: [{}]", sv);
        self.config.version.server_version = sv.to_string();
        // 发送客户端版本
        let cv = self.config.version.client_version.clone();
        self.write_version(format!("{}\r\n", cv.as_str()).as_bytes())?;
        log::info!("client version: [{}]", cv);
        // 版本验证
        self.config.version.validation()?;
        h.set_v_s(sv);
        h.set_v_c(&cv);
        log::info!("version negotiation was successful.");
        Ok(())
    }

    pub(crate) fn close(&mut self) -> Result<(), SshError> {
        match self.stream.shutdown(Shutdown::Both) {
            Ok(o) => Ok(o),
            Err(e) => Err(SshError::from(e)),
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
