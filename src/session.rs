use std::error::Error;
use std::process::exit;
use std::io;
use std::string::FromUtf8Error;
use crate::channel::Channel;
use crate::tcp::Client;
use crate::{strings, message, size};
use crate::error::{SshError, SshErrorKind};
use crate::key_exchange::KeyExchange;
use crate::packet::{Data, Packet};

static mut CLIENT_CHANNEL: u32 = 0;

#[derive(Clone)]
pub struct Config {
    username: String,
    password: String,
}

impl Config {
    pub(crate) fn new() -> Self {
        Config {
            username: "".to_string(),
            password: "".to_string(),
        }
    }
}

pub struct Session {
    pub(crate) stream: Client,
    pub(crate) config: Config,
    pub(crate) key_exchange: KeyExchange
}


impl Session {
    pub fn connect(&mut self) -> Result<(), SshError> {
        // 版本协商
        self.version_negotiation()?;

        // 密钥协商交换
        self.key_exchange.key_exchange(&mut self.stream)?;
        Ok(())
    }
    pub fn set_nonblocking(&mut self, nonblocking: bool) -> Result<(), SshError>{
        match self.stream.stream.set_nonblocking(nonblocking) {
            Ok(_) => Ok(()),
            Err(e) => Err(SshError::from(e))
        }
    }

    pub fn open_channel(&mut self) -> Result<Channel, SshError> {
        // 开始身份验证  TODO!!!
        self.msg_service_request()?;
        loop {
            let results = self.stream.read()?;
            for buf in results {
                let message_code = buf[5];
                match message_code {
                    message::SSH_MSG_SERVICE_ACCEPT => {
                        // 开始密码验证 TODO 目前只支持密码验证
                        self.password_authentication()?;
                    }
                    message::SSH_MSG_USERAUTH_FAILURE => {
                        println!("密码验证失败！");
                        exit(0)
                    }

                    message::SSH_MSG_USERAUTH_SUCCESS => {
                        let client_channel = unsafe {
                            CLIENT_CHANNEL + 1
                        };
                        // 验证成功
                        println!("验证成功！");
                        self.ssh_open_channel(client_channel)?;
                        let channel = Channel {
                            stream: self.stream.clone()?,
                            server_channel: 0,
                            client_channel,
                            key_exchange: KeyExchange {
                                            session_id: self.key_exchange.session_id.clone(),
                                            h: self.key_exchange.h.clone(),
                                            encryption_algorithm: None
                                        }
                        };
                        return Ok(channel)
                    }

                    message::SSH_MSG_GLOBAL_REQUEST => {
                        let mut data = Data::new();
                        data.put_u8(message::SSH_MSG_REQUEST_FAILURE);
                        let mut packet = Packet::from(data);
                        packet.build();
                        self.stream.write(packet.as_slice())?;
                    }

                    _ => {}
                }
            }
        }
    }



    pub fn set_user_and_password(&mut self, user: String, password: String) {
        self.config.username = user;
        self.config.password = password;
    }

    pub fn close(self) -> Result<(), SshError> {
        self.stream.close()
    }

    fn ssh_open_channel(&mut self, client_channel: u32) -> Result<(), SshError> {
        let mut data = Data::new();
        data.put_u8(message::SSH_MSG_CHANNEL_OPEN)
            .put_str(strings::SESSION)
            .put_u32(client_channel)
            .put_u32(size::LOCAL_WINDOW_SIZE)
            .put_u32(size::BUF_SIZE as u32);
        let mut packet = Packet::from(data);
        packet.build();
        Ok(self.stream.write(packet.as_slice())?)
    }

    fn password_authentication(&mut self) -> Result<(), SshError> {
        let username = &mut self.config.username;
        if username.is_empty() {
            eprintln!("请输入用户！");
            exit(0)
        }
        let password = &mut self.config.password;
        if password.is_empty() {
            eprintln!("请输入密码！");
            exit(0)
        }

        let mut data = Data::new();
        data.put_u8(message::SSH_MSG_USERAUTH_REQUEST)
            .put_str(username)
            .put_str(strings::SSH_CONNECTION)
            .put_str(strings::PASSWORD)
            .put_u8(false as u8)
            .put_str(password);
        let mut packet = Packet::from(data);
        packet.build();
        Ok(self.stream.write(packet.as_slice())?)
    }


    fn msg_service_request(&mut self) -> Result<(), SshError> {
        let mut data = Data::new();
        data.put_u8(message::SSH_MSG_SERVICE_REQUEST)
            .put_str(strings::SSH_USERAUTH);
        let mut packet = Packet::from(data);
        packet.build();
        Ok(self.stream.write(packet.as_slice())?)
    }


    fn version_negotiation(&mut self) -> Result<(), SshError> {
        let svb = self.stream.read_version();
        let server_version = match String::from_utf8(svb) {
            Ok(v) => v,
            Err(_) => return Err(SshError::from(SshErrorKind::FromUtf8Error))
        };
        if server_version.contains("SSH-2.0") {
            let sv = server_version.trim();
            self.key_exchange.h.set_v_s(sv);
            self.key_exchange.h.set_v_c(strings::CLIENT_VERSION);
            println!(">> server version: {}", sv);
            println!(">> client version: {}", strings::CLIENT_VERSION);
            match self.stream.write_version(format!("{}\r\n", strings::CLIENT_VERSION).as_bytes()) {
                Ok(_) => {}
                Err(e) => return Err(SshError::from(e))
            };
        } else { exit(0) }
        Ok(())
    }

}

