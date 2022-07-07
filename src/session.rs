use std::io::Read;
use std::net::ToSocketAddrs;
use log::log;
use rsa::pkcs1::FromRsaPrivateKey;
use rsa::PublicKeyParts;
use crate::data::Data;
use crate::constant::{ssh_msg_code, size, ssh_str};
use crate::error::{SshError, SshErrorKind, SshResult};
use crate::slog::{log, Slog};
use crate::channel::Channel;
use crate::channel_scp::ChannelScp;
use crate::{channel, ChannelExec, ChannelShell, client, config, kex, util};
use crate::algorithm::hash::h;
use crate::algorithm::{encryption, key_exchange, mac, public_key};
use crate::config_auth::AuthType;
use crate::window_size::WindowSize;


pub struct Session;


impl Session {
    pub fn is_usage_log(&self, b: bool) {
        if b {
            Slog::default()
        }
    }
}

impl Session {

    pub fn auth_password<S>(&self, user: S, password: S)
        where S: Into<String>
    {
        let config = config::config();
        config.auth.auth_type = AuthType::Password;
        config.auth.username = user.into();
        config.auth.password = password.into();
    }


    pub fn auth_public_key<S>(&self, user: S, private_key_algorithm_name: S, private_key: S)
        where S: Into<String>
    {
        let config = config::config();
        config.auth.auth_type = AuthType::PublicKey;
        config.auth.username = user.into();
        config.auth.private_key = private_key.into();
        config.auth.private_key_algorithm_name = private_key_algorithm_name.into();
    }

}

impl Session {

    pub fn connect<A>(&mut self, addr: A) -> Result<(), SshError>
    where
        A: ToSocketAddrs
    {

        // tcp 发起连接
        client::connect(addr)?;

        log::info!("session opened.");

        log::info!("prepare for version negotiation.");

        // 版本协商
        // 获取服务端版本
        self.receive_version()?;

        // 版本验证
        let config = config::config();
        config.version.validation()?;
        // 发送客户端版本
        self.send_version()?;

        log::info!("version negotiation was successful.");

        log::info!("prepare for key negotiation.");

        // 密钥协商
        kex::send_algorithm()?;
        kex::receive_algorithm()?;

        // 缓存密钥交换算法
        key_exchange::put(config.algorithm.matching_key_exchange_algorithm()?);
        // 公钥算法
        public_key::put(config.algorithm.matching_public_key_algorithm()?);

        h::get().set_v_c(config.version.client_version.as_str());
        h::get().set_v_s(config.version.server_version.as_str());

        kex::send_qc()?;
        kex::verify_signature_and_new_keys()?;

        // 加密算法
        encryption::put(config.algorithm.matching_encryption_algorithm()?);
        // mac 算法
        mac::put(config.algorithm.matching_mac_algorithm()?);

        log::info!("key negotiation successful.");

        self.initiate_authentication()?;
        self.authentication()
    }

    pub fn open_channel(&mut self) -> SshResult<Channel> {
        log::info!("channel opened.");
        let client_channel = channel::current_client_channel_no();
        self.send_open_channel(client_channel)?;
        let (server_channel, rws) = self.receive_open_channel()?;
        let mut win_size = WindowSize::new();
        win_size.server_channel = server_channel;
        win_size.client_channel = client_channel;
        win_size.add_remote_window_size(rws);
        win_size.add_remote_max_window_size(rws);
        Ok(Channel {
            remote_close: false,
            local_close: false,
            window_size: win_size
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

    pub fn close(self) -> SshResult<()> {
        log::info!("session close.");
        client::default()?.close()
    }

}

impl Session {

    // 本地请求远程打开通道
    fn send_open_channel(&mut self, client_channel: u32) -> SshResult<()> {
        let mut data = Data::new();
        data.put_u8(ssh_msg_code::SSH_MSG_CHANNEL_OPEN)
            .put_str(ssh_str::SESSION)
            .put_u32(client_channel)
            .put_u32(size::LOCAL_WINDOW_SIZE)
            .put_u32(size::BUF_SIZE as u32);
        let client = client::default()?;
        client.write(data)
    }

    // 远程回应是否可以打开通道
    fn receive_open_channel(&mut self) -> SshResult<(u32, u32)> {
        loop {
            let client = client::default()?;
            let results = client.read()?;
            for mut result in results {
                if result.is_empty() { continue }
                let message_code = result.get_u8();
                match message_code {
                    // 打开请求通过
                    ssh_msg_code::SSH_MSG_CHANNEL_OPEN_CONFIRMATION => {
                        // 接收方通道号
                        result.get_u32();
                        // 发送方通道号
                        let server_channel = result.get_u32();
                        // 远程初始窗口大小
                        let rws = result.get_u32();
                        // 远程的最大数据包大小， 暂时不需要
                        result.get_u32();
                        return Ok((server_channel, rws));
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
                        return Err(SshError::from(SshErrorKind::SshConnectionError(err_msg)))
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
        let client = client::default()?;
        client.write(data)
    }

    fn authentication(&mut self) -> SshResult<()> {
        let client = client::default()?;
        loop {
            let results = client.read()?;
            for mut result in results {
                if result.is_empty() { continue }
                let message_code = result.get_u8();
                match message_code {
                    ssh_msg_code::SSH_MSG_SERVICE_ACCEPT => {
                        let config = config::config();
                        match config.auth.auth_type {
                            // 开始密码验证
                            AuthType::Password => self.password_authentication()?,
                            AuthType::PublicKey => self.public_key_authentication()?
                        }

                    }
                    ssh_msg_code::SSH_MSG_USERAUTH_FAILURE => {
                        log::error!("user auth failure.");
                        println!("{:?}", String::from_utf8(result.get_u8s()).unwrap());
                        return Err(SshError::from(SshErrorKind::PasswordError))
                    }
                    ssh_msg_code::SSH_MSG_USERAUTH_PK_OK => {
                        log::info!("user auth support this algorithm.");
                        // return Ok(())
                    }
                    ssh_msg_code::SSH_MSG_USERAUTH_SUCCESS => {
                        log::info!("user auth successful.");
                        return Ok(())
                    }
                    ssh_msg_code::SSH_MSG_GLOBAL_REQUEST => {
                        let mut data = Data::new();
                        data.put_u8(ssh_msg_code::SSH_MSG_REQUEST_FAILURE);
                        client.write(data)?
                    }
                    _ => {}
                }
            }
        }
    }

    fn send_version(&mut self) -> SshResult<()> {
        let client = client::default()?;
        let config = config::config();
        client.write_version(format!("{}\r\n", config.version.client_version).as_bytes())?;
        log::info!("client version: [{}]", config.version.client_version);
        Ok(())
    }

    fn receive_version(&mut self) -> SshResult<()> {
        let client = client::default()?;
        let vec = client.read_version();
        let from_utf8 = util::from_utf8(vec)?;
        let sv = from_utf8.trim();
        log::info!("server version: [{}]", sv);
        let config = config::config();
        config.version.server_version = sv.to_string();
        Ok(())
    }

    fn password_authentication(&self) -> SshResult<()> {
        log::info!("password authentication.");

        let config = config::config();
        if config.auth.username.is_empty() {
            return Err(SshError::from(SshErrorKind::UserNullError))
        }
        if config.auth.password.is_empty() {
            return Err(SshError::from(SshErrorKind::PasswordNullError))
        }

        let mut data = Data::new();
        data.put_u8(ssh_msg_code::SSH_MSG_USERAUTH_REQUEST)
            .put_str(config.auth.username.as_str())
            .put_str(ssh_str::SSH_CONNECTION)
            .put_str(ssh_str::PASSWORD)
            .put_u8(false as u8)
            .put_str(config.auth.password.as_str());
        let client = client::default()?;
        client.write(data)
    }

    fn public_key_authentication(&self) -> SshResult<()> {
        log::info!("public key authentication.");

        let config = config::config();
        let rprk = rsa::RsaPrivateKey::from_pkcs1_pem(config.auth.private_key.as_str()).unwrap();
        let rpuk = rprk.to_public_key();
        let es = rpuk.e().to_bytes_be();
        let ns = rpuk.n().to_bytes_be();

        let mut blob = Data::new();
        blob.put_str("ssh-rsa");
        blob.put_mpint(&es);
        blob.put_mpint(&ns);
        let blob = blob.as_slice();
        println!("blob length : {}", blob.len());
        let mut data = Data::new();
        data.put_u8(ssh_msg_code::SSH_MSG_USERAUTH_REQUEST)
            .put_str(config.auth.username.as_str())
            .put_str(ssh_str::SSH_CONNECTION)
            .put_str(ssh_str::PUBLIC_KEY)
            .put_u8(false as u8)
            .put_str(config.auth.private_key_algorithm_name.as_str())
            .put_u8s(blob);
        let client = client::default()?;
        client.write(data)
    }

}

