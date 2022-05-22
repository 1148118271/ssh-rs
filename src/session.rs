use std::sync::MutexGuard;
use std::sync::atomic::Ordering::Relaxed;
use packet::Data;
use constant::{ssh_msg_code, size, ssh_str};
use error::{SshError, SshErrorKind, SshResult};
use slog::log;
use crate::channel::Channel;
use crate::client::Client;
// use crate::channel_scp::ChannelScp;
use crate::kex::Kex;
use crate::{ChannelExec, ChannelShell, client, global, util};
use crate::window_size::WindowSize;


pub struct Session;


impl Session {
    pub fn connect(&mut self) -> Result<(), SshError> {

        log::info!("session opened.");

        log::info!("prepare for version negotiation.");

        // 版本协商
        // 获取服务端版本
        self.receive_version()?;

        // 版本验证
        let config = util::config()?;
        config.version.validation()?;
        util::unlock(config);
        // 发送客户端版本
        self.send_version()?;

        log::info!("version negotiation was successful.");

        log::info!("prepare for key negotiation.");

        // 密钥协商
        let mut kex = Kex::new()?;
        kex.send_algorithm()?;
        kex.receive_algorithm()?;

        let config = util::config()?;
        let (dh, sign) = config.algorithm.matching_algorithm()?;
        kex.dh = dh;
        kex.signature = sign;

        kex.h.set_v_c(config.version.client_version.as_str());
        kex.h.set_v_s(config.version.server_version.as_str());

        util::unlock(config);

        kex.send_qc()?;
        kex.verify_signature_and_new_keys()?;

        log::info!("key negotiation successful.");

        self.initiate_authentication()?;
        self.authentication()
    }

    pub fn set_nonblocking(&mut self, nonblocking: bool) -> SshResult<()> {
        log::info!("set nonblocking: [{}]", nonblocking);
        if let Err(e) = client::locking()?.set_nonblocking(nonblocking) {
            return Err(SshError::from(e))
        }
        Ok(())
    }

    pub fn set_user_and_password<S: Into<String>>(&mut self, user: S, password: S) -> SshResult<()> {
        let mut config = util::config()?;
        config.user.username = user.into();
        config.user.password = password.into();
        Ok(())
    }

    pub fn close(self) -> SshResult<()> {
        log::info!("session close.");
        client::locking()?.close()
    }

    pub fn open_channel(&mut self) -> SshResult<Channel> {
        log::info!("channel opened.");
        let client_channel = global::CLIENT_CHANNEL.load(Relaxed);
        self.send_open_channel(client_channel)?;
        let (server_channel, rws) = self.receive_open_channel()?;
        global::CLIENT_CHANNEL.fetch_add(1, Relaxed);
        let mut win_size = WindowSize::new();
        win_size.server_channel = server_channel;
        win_size.client_channel = client_channel;
        win_size.add_remote_window_size(rws);
        win_size.add_remote_max_window_size(rws);
        Ok(Channel {
            kex: Kex::new()?,
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

    // pub fn open_scp(&mut self) -> SshResult<ChannelScp> {
    //     let channel = self.open_channel()?;
    //     channel.open_scp()
    // }

    // 本地请求远程打开通道
    fn send_open_channel(&mut self, client_channel: u32) -> SshResult<()> {
        let mut data = Data::new();
        data.put_u8(ssh_msg_code::SSH_MSG_CHANNEL_OPEN)
            .put_str(ssh_str::SESSION)
            .put_u32(client_channel)
            .put_u32(size::LOCAL_WINDOW_SIZE)
            .put_u32(size::BUF_SIZE as u32);
        let mut client = client::locking()?;
        client.write(data)
    }

    // 远程回应是否可以打开通道
    fn receive_open_channel(&mut self) -> SshResult<(u32, u32)> {
        loop {
            let mut client = client::locking()?;
            let results = client.read()?;
            client::unlock(client);
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
        let mut client = client::locking()?;
        client.write(data)
    }

    fn authentication(&mut self) -> SshResult<()> {
        let mut client = client::locking()?;
        loop {
            let results = client.read()?;
            for mut result in results {
                if result.is_empty() { continue }
                let message_code = result.get_u8();
                match message_code {
                    ssh_msg_code::SSH_MSG_SERVICE_ACCEPT => {
                        log::info!("密码验证");
                        // 开始密码验证 TODO 目前只支持密码验证
                        password_authentication(&mut client)?;
                    }
                    ssh_msg_code::SSH_MSG_USERAUTH_FAILURE => {
                        log::error!("user auth failure.");
                        return Err(SshError::from(SshErrorKind::PasswordError))
                    },
                    ssh_msg_code::SSH_MSG_USERAUTH_SUCCESS => {
                        log::info!("user auth successful.");
                        return Ok(())
                    },
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
        let mut client = client::locking()?;
        let config = util::config()?;
        client.write_version(format!("{}\r\n", config.version.client_version).as_bytes())?;
        log::info!("client version: [{}]", config.version.client_version);
        Ok(())
    }

    fn receive_version(&mut self) -> SshResult<()> {
        let mut client = client::locking()?;
        let vec = client.read_version();
        let from_utf8 = util::from_utf8(vec)?;
        let sv = from_utf8.trim();
        log::info!("server version: [{}]", sv);
        let mut config = util::config()?;
        config.version.server_version = sv.to_string();
        Ok(())
    }
}


fn password_authentication(client: &mut MutexGuard<'static, Client>) -> SshResult<()> {
    let config = util::config()?;
    if config.user.username.is_empty() {
        return Err(SshError::from(SshErrorKind::UserNullError))
    }
    if config.user.password.is_empty() {
        return Err(SshError::from(SshErrorKind::PasswordNullError))
    }

    let mut data = Data::new();
    data.put_u8(ssh_msg_code::SSH_MSG_USERAUTH_REQUEST)
        .put_str(config.user.username.as_str())
        .put_str(ssh_str::SSH_CONNECTION)
        .put_str(ssh_str::PASSWORD)
        .put_u8(false as u8)
        .put_str(config.user.password.as_str());
    client.write(data)
}

