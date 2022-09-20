use std::cell::RefCell;
use std::net::ToSocketAddrs;
use std::rc::Rc;
use std::sync::Arc;
use crate::data::Data;
use crate::constant::{ssh_msg_code, size, ssh_str};
use crate::error::{SshError, SshResult};
use crate::slog::{log, Slog};
use crate::{channel, timeout, util};
use crate::algorithm::encryption::Encryption;
use crate::algorithm::hash::hash::HASH;
use crate::algorithm::key_exchange::KeyExchange;
use crate::algorithm::public_key::PublicKey;
use crate::channel::Channel;
use crate::h::H;
use crate::client::Client;
use crate::config::Config;
use crate::user_info::AuthType;
use crate::window_size::WindowSize;


pub struct Session {

    pub(crate) timeout_sec: u64,

    pub(crate) h: Rc<RefCell<H>>,

    pub(crate) config: Option<Config>,

    pub(crate) client: Option<Client>,

    pub(crate) encryption: Option<Box<dyn Encryption>>,

    pub(crate) key_exchange: Option<Box<dyn KeyExchange>>,

    pub(crate) public_key: Option<Box<dyn PublicKey>>,

    pub(crate) is_encryption: bool,

    pub(crate) client_channel_no: u32,

}

impl Session {
    pub fn is_enable_log(&self, b: bool) {
        if b {
            Slog::default()
        }
    }

    pub fn set_timeout(&self, secs: u64) {
        unsafe {
            timeout::TIMEOUT = secs
        }
    }

}

impl Session {

    pub fn connect<A>(&mut self, addr: A) -> SshResult<()>
    where
        A: ToSocketAddrs
    {

        if self.config.is_none() {
            return Err(SshError::from("config is none."))
        }

        // 建立通道
        self.client = Some(Client::connect(addr)?);


        log::info!("session opened.");

        log::info!("prepare for version negotiation.");

        // 版本协商
        // 获取服务端版本
        self.receive_version()?;

        // 发送客户端版本
        self.send_version()?;

        log::info!("version negotiation was successful.");

        log::info!("prepare for key negotiation.");

        // 密钥协商
        // 发送客户端密钥
        self.send_algorithm()?;
        // 接收服务端密钥
        self.receive_algorithm()?;

        // 版本验证
        {
            let config = self.config.as_ref().unwrap();
            config.version.validation()?;


            // 缓存密钥交换算法
            self.key_exchange = Some(config.algorithm.matching_key_exchange_algorithm()?);
            // 公钥算法
            self.public_key = Some(config.algorithm.matching_public_key_algorithm()?);

            self.h.borrow_mut().set_v_c(config.version.client_version.as_str());
            self.h.borrow_mut().set_v_s(config.version.server_version.as_str());
        }

        self.send_qc()?;
        self.verify_signature_and_new_keys()?;

        let hash = HASH::new(self.h.clone(), self.key_exchange.as_ref().unwrap().get_hash_type());


        let config = self.config.as_ref().unwrap();

        // mac 算法
        let mac = config.algorithm.matching_mac_algorithm()?;

        // 加密算法
        self.encryption = Some(config.algorithm.matching_encryption_algorithm(hash, mac)?);

        log::info!("key negotiation successful.");

        self.initiate_authentication()?;
        self.authentication()
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
            session: self as *mut Session
        })
    }

    // pub fn open_exec(&mut self) -> SshResult<ChannelExec> {
    //     let channel = self.open_channel()?;
    //     channel.open_exec()
    // }
    //
    // pub fn open_shell(&mut self) -> SshResult<ChannelShell> {
    //     let channel = self.open_channel()?;
    //     channel.open_shell()
    // }
    //
    // pub fn open_scp(&mut self) -> SshResult<ChannelScp> {
    //     let channel = self.open_channel()?;
    //     channel.open_scp()
    // }
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
        self.write(data)
    }

    // 远程回应是否可以打开通道
    fn receive_open_channel(&mut self) -> SshResult<(u32, u32)> {
        loop {
            let results = self.read()?;
            for mut result in results {
                if result.is_empty() { continue }
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
                    },
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
                            .unwrap_or(String::from("error"));
                        // language tag 暂不处理， 应该是 en-US
                        result.get_u8s();

                        let err_msg = match code {
                            ssh_msg_code::SSH_OPEN_ADMINISTRATIVELY_PROHIBITED => {
                                format!("SSH_OPEN_ADMINISTRATIVELY_PROHIBITED: {}", description)
                            },
                            ssh_msg_code::SSH_OPEN_CONNECT_FAILED => {
                                format!("SSH_OPEN_CONNECT_FAILED: {}", description)
                            },
                            ssh_msg_code::SSH_OPEN_UNKNOWN_CHANNEL_TYPE => {
                                format!("SSH_OPEN_UNKNOWN_CHANNEL_TYPE: {}", description)
                            },
                            ssh_msg_code::SSH_OPEN_RESOURCE_SHORTAGE => {
                                format!("SSH_OPEN_RESOURCE_SHORTAGE: {}", description)
                            },
                            _ => description
                        };
                        return Err(SshError::from(err_msg))
                    },
                    _ => {}
                }
            }
        }
    }

    fn initiate_authentication(&mut self) -> SshResult<()> {
        let mut data = Data::new();
        data.put_u8(ssh_msg_code::SSH_MSG_SERVICE_REQUEST)
            .put_str(ssh_str::SSH_USERAUTH);
        self.write(data)
    }

    fn authentication(&mut self) -> SshResult<()> {
        loop {
            let results = self.read()?;
            for mut result in results {
                if result.is_empty() { continue }
                let message_code = result.get_u8();
                match message_code {
                    ssh_msg_code::SSH_MSG_SERVICE_ACCEPT => {
                        let config = self.config.as_ref().unwrap();
                        match config.auth.auth_type {
                            // 开始密码验证
                            AuthType::Password => self.password_authentication()?,
                            AuthType::PublicKey => self.public_key_authentication()?
                        }

                    }
                    ssh_msg_code::SSH_MSG_USERAUTH_FAILURE => {
                        log::error!("user auth failure.");
                        return Err(SshError::from("user auth failure, auth type is password."))
                    }
                    ssh_msg_code::SSH_MSG_USERAUTH_PK_OK => {
                        log::info!("user auth support this algorithm.");
                        self.public_key_signature()?
                    }
                    ssh_msg_code::SSH_MSG_USERAUTH_SUCCESS => {
                        log::info!("user auth successful.");
                        return Ok(())
                    }
                    ssh_msg_code::SSH_MSG_GLOBAL_REQUEST => {
                        let mut data = Data::new();
                        data.put_u8(ssh_msg_code::SSH_MSG_REQUEST_FAILURE);
                        self.write(data)?
                    }
                    _ => {}
                }
            }
        }
    }

    fn send_version(&mut self) -> SshResult<()> {
        let cv = {
            let config = self.config.as_ref().unwrap();
            config.version.client_version.clone()
        };
        self.write_version(format!("{}\r\n", cv.as_str()).as_bytes())?;
        log::info!("client version: [{}]", cv);
        Ok(())
    }

    fn receive_version(&mut self) -> SshResult<()> {
        let vec = self.read_version();
        let from_utf8 = util::from_utf8(vec)?;
        let sv = from_utf8.trim();
        log::info!("server version: [{}]", sv);
        let config = self.config.as_mut().unwrap();
        config.version.server_version = sv.to_string();
        Ok(())
    }


}

