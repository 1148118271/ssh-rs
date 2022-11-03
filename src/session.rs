use crate::algorithm::hash::HashType;
use crate::client::Client;
use crate::config::Config;
use crate::constant::{size, ssh_msg_code, ssh_str};
use crate::data::Data;
use crate::error::{SshError, SshResult};
use crate::h::H;
use crate::kex;
use crate::slog::log;
use crate::user_info::AuthType;
use crate::window_size::WindowSize;
use crate::{Channel, ChannelExec, ChannelScp, ChannelShell};
use std::net::ToSocketAddrs;

pub struct Session {
    pub(crate) timeout_sec: u64,

    pub(crate) config: Option<Config>,

    pub(crate) client: Option<Client>,

    pub(crate) client_channel_no: u32,
}

impl Session {
    pub fn set_timeout(&mut self, secs: u64) {
        self.timeout_sec = secs;
    }

    pub fn connect<A>(&mut self, addr: A) -> SshResult<()>
    where
        A: ToSocketAddrs,
    {
        if self.config.is_none() {
            return Err(SshError::from("config is none."));
        }
        // 建立通道
        self.client = Some(Client::connect(addr, self.timeout_sec)?);
        log::info!("session opened.");

        let mut h = H::new();
        let client = self.client.as_mut().unwrap();
        let config = self.config.as_mut().unwrap();

        // 版本协商
        client.version(config)?;
        h.set_v_c(&config.version.client_version);
        h.set_v_s(&config.version.server_version);
        // 密钥协商
        let hash_type = kex::key_agreement(&mut h, client, config)?;
        // 用户验证
        self.initiate_authentication()?;
        self.authentication(hash_type, h)
    }

    pub fn close(self) -> SshResult<()> {
        log::info!("session close.");
        self.client.unwrap().close()
    }
}

impl Session {
    pub fn open_channel(&mut self) -> SshResult<Channel> {
        log::info!("channel opened.");
        self.send_open_channel(self.client_channel_no)?;
        let (server_channel_no, rws) = self.receive_open_channel()?;
        // 打开成功， 通道号+1
        let mut win_size = WindowSize::new();
        win_size.server_channel_no = server_channel_no;
        win_size.client_channel_no = self.client_channel_no;
        win_size.add_remote_window_size(rws);
        win_size.add_remote_max_window_size(rws);

        self.client_channel_no += 1;

        Ok(Channel {
            remote_close: false,
            local_close: false,
            window_size: win_size,
            session: self as *mut Session,
        })
    }

    pub fn open_exec(&mut self) -> SshResult<ChannelExec> {
        let channel = self.open_channel()?;
        channel.open_exec()
    }

    pub fn open_shell(&mut self) -> SshResult<ChannelShell> {
        let channel = self.open_channel()?;
        channel.open_shell()
    }

    pub fn open_scp(&mut self) -> SshResult<ChannelScp> {
        let channel = self.open_channel()?;
        channel.open_scp()
    }
}

impl Session {
    // 本地请求远程打开通道
    fn send_open_channel(&mut self, client_channel_no: u32) -> SshResult<()> {
        let mut data = Data::new();
        data.put_u8(ssh_msg_code::SSH_MSG_CHANNEL_OPEN)
            .put_str(ssh_str::SESSION)
            .put_u32(client_channel_no)
            .put_u32(size::LOCAL_WINDOW_SIZE)
            .put_u32(size::BUF_SIZE as u32);
        self.client.as_mut().unwrap().write(data)
    }

    // 远程回应是否可以打开通道
    fn receive_open_channel(&mut self) -> SshResult<(u32, u32)> {
        loop {
            let results = self.client.as_mut().unwrap().read()?;
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
        self.client.as_mut().unwrap().write(data)
    }

    fn authentication(&mut self, ht: HashType, h: H) -> SshResult<()> {
        loop {
            let results = self.client.as_mut().unwrap().read()?;
            for mut result in results {
                if result.is_empty() {
                    continue;
                }
                let message_code = result.get_u8();
                match message_code {
                    ssh_msg_code::SSH_MSG_SERVICE_ACCEPT => {
                        let config = self.config.as_ref().unwrap();
                        match config.auth.auth_type {
                            // 开始密码验证
                            AuthType::Password => self.password_authentication()?,
                            AuthType::PublicKey => self.public_key_authentication()?,
                        }
                    }
                    ssh_msg_code::SSH_MSG_USERAUTH_FAILURE => {
                        log::error!("user auth failure.");
                        return Err(SshError::from("user auth failure, auth type is password."));
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
                        self.client.as_mut().unwrap().write(data)?
                    }
                    _ => {}
                }
            }
        }
    }
}
