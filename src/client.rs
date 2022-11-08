use crate::h::H;
use crate::timeout::Timeout;
use crate::{algorithm::encryption::Encryption, config::version::SshVersion};
use crate::{client_r::Signature, config::Config};
use crate::{config::algorithm::AlgList, error::SshResult};
use std::ops::{Deref, DerefMut};
use std::{
    io::{self, Read, Write},
    sync::{Arc, Mutex},
};

pub(crate) struct Client<S>
where
    S: Read + Write,
{
    pub(crate) stream: S,
    pub(crate) sequence: Sequence,
    pub(crate) timeout: Timeout,
    pub(crate) config: Arc<Mutex<Config>>,
    pub(crate) negotiated: AlgList,
    pub(crate) encryption: Option<Box<dyn Encryption>>,
    pub(crate) is_encryption: bool,
    /// session id
    /// 只使用第一次密钥交换生成的
    pub(crate) session_id: Vec<u8>,
    pub(crate) w_size: usize,
    pub(crate) signature: Option<Signature>,
    pub(crate) is_r_1_gb: bool,
    pub(crate) is_w_1_gb: bool,
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

impl<S> Client<S>
where
    S: Read + Write,
{
    pub(crate) fn connect(
        stream: S,
        timeout_sec: u64,
        config: Arc<Mutex<Config>>,
    ) -> SshResult<Client<S>> {
        Ok(Client {
            stream,
            sequence: Sequence {
                client_sequence_num: 0,
                server_sequence_num: 0,
            },
            timeout: Timeout::new(timeout_sec),
            config,
            negotiated: AlgList::new(),
            encryption: None,
            is_encryption: false,
            session_id: vec![],
            w_size: 0,
            signature: None,
            is_r_1_gb: false,
            is_w_1_gb: false,
        })
    }

    pub(crate) fn version(&mut self, h: &mut H) -> SshResult<()> {
        log::info!("start for version negotiation.");
        // 获取服务端版本
        let version = SshVersion::from(&mut self.stream, h)?;
        // 版本验证
        version.validate()?;
        // 发送客户端版本
        SshVersion::write(&mut self.stream, h)?;

        self.config.lock().unwrap().ver = version;
        Ok(())
    }

    pub(crate) fn is_would_block(e: &io::Error) -> bool {
        e.kind() == io::ErrorKind::WouldBlock
    }
}

impl<S> Drop for Client<S>
where
    S: Read + Write,
{
    fn drop(&mut self) {
        log::info!("client close");
    }
}

impl<S> Deref for Client<S>
where
    S: Read + Write,
{
    type Target = S;

    fn deref(&self) -> &Self::Target {
        &self.stream
    }
}

impl<S> DerefMut for Client<S>
where
    S: Read + Write,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.stream
    }
}
