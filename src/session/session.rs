use crate::client::Client;
use crate::constant::{size, ssh_msg_code, ssh_str};
use crate::h::H;
use crate::kex;
use crate::model::Data;
use crate::slog::log;
use crate::model::WindowSize;
use crate::{algorithm::hash::HashType, config::Config};
use crate::{
    algorithm::{Compress, Enc, Kex, Mac, PubKey},
    error::{SshError, SshResult},
};
use crate::{Channel, ChannelExec, ChannelScp, ChannelShell};
use std::rc::Rc;
use std::{cell::RefCell, sync::Mutex};
use std::{
    io::{Read, Write},
    net::{TcpStream, ToSocketAddrs},
    path::Path,
};
use std::{ops::DerefMut, sync::Arc};

#[derive(Default)]
pub struct SessionBuilder {
    timeout_sec: u64,
    config: Config,
}

impl SessionBuilder {
    pub fn new() -> Self {
        Self {
            timeout_sec: 30,
            ..Default::default()
        }
    }

    pub fn disable_default() -> Self {
        Self {
            timeout_sec: 30,
            config: Config::disable_default(),
        }
    }

    pub fn timeout(mut self, timeout: u64) -> Self {
        self.timeout_sec = timeout;
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

    pub fn build<S>(self) -> Session<S>
    where
        S: Read + Write,
    {
        Session {
            timeout_sec: self.timeout_sec,
            config: Arc::new(Mutex::new(self.config)),
            client: None,
            client_channel_no: 0,
        }
    }
}

pub struct Session<S>
where
    S: Read + Write,
{
    pub(crate) timeout_sec: u64,

    pub(crate) config: Arc<Mutex<Config>>,

    pub(crate) client: Option<Rc<RefCell<Client<S>>>>,

    pub(crate) client_channel_no: u32,
}

impl Session<TcpStream> {
    pub fn connect<A>(&mut self, addr: A) -> SshResult<()>
    where
        A: ToSocketAddrs,
    {
        // 建立通道
        let tcp = TcpStream::connect(addr)?;
        // default nonblocking
        tcp.set_nonblocking(true).unwrap();
        self.connect_bio(tcp)
    }
}

impl<S> Session<S>
where
    S: Read + Write,
{
    pub fn connect_bio(&mut self, stream: S) -> SshResult<()> {
        // 建立通道
        self.client = Some(Rc::new(RefCell::new(Client::<S>::connect(
            stream,
            self.timeout_sec,
            self.config.clone(),
        )?)));
        log::info!("session opened.");
        self.post_connect()
    }

    fn post_connect(&mut self) -> SshResult<()> {
        let mut h = H::new();

        // 版本协商
        let client = self.get_client()?;
        client.as_ref().borrow_mut().version(&mut h)?;
        // 密钥协商
        let hash_type = kex::key_agreement(&mut h, client.as_ref().borrow_mut().deref_mut(), None)?;
        // 用户验证
        self.initiate_authentication()?;
        self.authentication(hash_type, h)
    }

    pub fn close(self) {
        log::info!("session close.");
        drop(self)
    }
}

impl<S> Session<S>
where
    S: Read + Write,
{
    pub fn open_channel(&mut self) -> SshResult<Channel<S>> {
        log::info!("channel opened.");
        self.send_open_channel(self.client_channel_no)?;
        let (server_channel_no, rws) = self.receive_open_channel()?;
        // 打开成功， 通道号+1
        let mut win_size = WindowSize::new();
        win_size.server_channel_no = server_channel_no;
        win_size.client_channel_no = self.client_channel_no;
        win_size.add_remote_window_size(rws);

        self.client_channel_no += 1;

        Ok(Channel {
            remote_close: false,
            local_close: false,
            window_size: win_size,
            client: self.get_client()?,
        })
    }

    pub fn open_exec(&mut self) -> SshResult<ChannelExec<S>> {
        let channel = self.open_channel()?;
        channel.open_exec()
    }

    pub fn open_shell(&mut self) -> SshResult<ChannelShell<S>> {
        let channel = self.open_channel()?;
        channel.open_shell()
    }

    pub fn open_scp(&mut self) -> SshResult<ChannelScp<S>> {
        let channel = self.open_channel()?;
        channel.open_scp()
    }
}

impl<S> Session<S>
where
    S: Read + Write,
{
    // 本地请求远程打开通道
    fn send_open_channel(&mut self, client_channel_no: u32) -> SshResult<()> {
        let mut data = Data::new();
        data.put_u8(ssh_msg_code::SSH_MSG_CHANNEL_OPEN)
            .put_str(ssh_str::SESSION)
            .put_u32(client_channel_no)
            .put_u32(size::LOCAL_WINDOW_SIZE)
            .put_u32(size::BUF_SIZE as u32);
        self.get_client()?.as_ref().borrow_mut().write(data)
    }

    // 远程回应是否可以打开通道
    fn receive_open_channel(&mut self) -> SshResult<(u32, u32)> {
        loop {
            let results = self.get_client()?.as_ref().borrow_mut().read()?;
            for mut result in results {
                if result.is_empty() {
                    continue;
                }
                let message_code = result.get_u8();
                match message_code {
                    // 打开请求通过
                    ssh_msg_code::SSH_MSG_CHANNEL_OPEN_CONFIRMATION => {
                        // 接收方通道号
                        result.get_u32();
                        // 发送方通道号
                        let server_channel_no = result.get_u32();
                        // 远程初始窗口大小
                        let rws = result.get_u32();
                        // 远程的最大数据包大小， 暂时不需要
                        result.get_u32();
                        return Ok((server_channel_no, rws));
                    }
                    /*
                        byte SSH_MSG_CHANNEL_OPEN_FAILURE
                        uint32 recipient channel
                        uint32 reason code
                        string description，ISO-10646 UTF-8 编码[RFC3629]
                        string language tag，[RFC3066]
                    */
                    // 打开请求拒绝
                    ssh_msg_code::SSH_MSG_CHANNEL_OPEN_FAILURE => {
                        result.get_u32();
                        // 失败原因码
                        let code = result.get_u32();
                        // 消息详情 默认utf-8编码
                        let description = String::from_utf8(result.get_u8s())
                            .unwrap_or_else(|_| String::from("error"));
                        // language tag 暂不处理， 应该是 en-US
                        result.get_u8s();

                        let err_msg = match code {
                            ssh_msg_code::SSH_OPEN_ADMINISTRATIVELY_PROHIBITED => {
                                format!("SSH_OPEN_ADMINISTRATIVELY_PROHIBITED: {}", description)
                            }
                            ssh_msg_code::SSH_OPEN_CONNECT_FAILED => {
                                format!("SSH_OPEN_CONNECT_FAILED: {}", description)
                            }
                            ssh_msg_code::SSH_OPEN_UNKNOWN_CHANNEL_TYPE => {
                                format!("SSH_OPEN_UNKNOWN_CHANNEL_TYPE: {}", description)
                            }
                            ssh_msg_code::SSH_OPEN_RESOURCE_SHORTAGE => {
                                format!("SSH_OPEN_RESOURCE_SHORTAGE: {}", description)
                            }
                            _ => description,
                        };
                        return Err(SshError::from(err_msg));
                    }
                    _ => {}
                }
            }
        }
    }

    fn initiate_authentication(&mut self) -> SshResult<()> {
        let mut data = Data::new();
        data.put_u8(ssh_msg_code::SSH_MSG_SERVICE_REQUEST)
            .put_str(ssh_str::SSH_USERAUTH);
        self.get_client()?.as_ref().borrow_mut().write(data)
    }

    fn authentication(&mut self, ht: HashType, h: H) -> SshResult<()> {
        let mut tried_public_key = false;
        loop {
            let results = self.get_client()?.as_ref().borrow_mut().read()?;
            for mut result in results {
                if result.is_empty() {
                    continue;
                }
                let message_code = result.get_u8();
                match message_code {
                    ssh_msg_code::SSH_MSG_SERVICE_ACCEPT => {
                        let auth = &self.config.lock().unwrap().auth;
                        if auth.key_pair.is_none() {
                            tried_public_key = true;
                            // if no private key specified
                            // just try password auth
                            self.password_authentication(auth)?
                        } else {
                            // if private key was provided
                            // use public key auth first, then fallback to password auth
                            self.public_key_authentication(auth)?
                        }
                    }
                    ssh_msg_code::SSH_MSG_USERAUTH_FAILURE => {
                        if !tried_public_key {
                            log::error!("user auth failure. (public key)");
                            log::info!("fallback to password authentication");
                            tried_public_key = true;
                            let auth = &self.config.lock().unwrap().auth;
                            // keep the same with openssh
                            // if the public key auth failed
                            // try with password again
                            self.password_authentication(auth)?
                        } else {
                            log::error!("user auth failure. (password)");
                            return Err(SshError::from("user auth failure."));
                        }
                    }
                    ssh_msg_code::SSH_MSG_USERAUTH_PK_OK => {
                        log::info!("user auth support this algorithm.");
                        self.public_key_signature(ht, h.clone())?
                    }
                    ssh_msg_code::SSH_MSG_USERAUTH_SUCCESS => {
                        log::info!("user auth successful.");
                        return Ok(());
                    }
                    ssh_msg_code::SSH_MSG_GLOBAL_REQUEST => {
                        let mut data = Data::new();
                        data.put_u8(ssh_msg_code::SSH_MSG_REQUEST_FAILURE);
                        self.get_client()?.as_ref().borrow_mut().write(data)?
                    }
                    _ => {}
                }
            }
        }
    }

    pub(crate) fn get_client(&self) -> SshResult<Rc<RefCell<Client<S>>>> {
        if self.client.is_none() {
            return Err(SshError::from("client is none."));
        }
        Ok(self.client.as_ref().unwrap().clone())
    }
}
