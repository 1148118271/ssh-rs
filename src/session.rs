use std::process::exit;
use std::io;
use crate::channel::Channel;
use crate::tcp::Client;
use crate::constants::{strings, message, size};
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
    pub fn connect(&mut self) -> io::Result<()> {


        // 版本协商
        self.version_negotiation()?;

        // 密钥协商交换
        self.key_exchange.key_exchange(&mut self.stream)?;
        Ok(())
    }

    pub fn open_channel(&mut self) -> io::Result<Channel> {
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
                        let mut channel = Channel {
                            stream: self.stream.clone(),
                            server_channel: 0,
                            client_channel,
                            key_exchange: self.key_exchange.clone()
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


    fn ssh_open_channel(&mut self, client_channel: u32) -> io::Result<()> {
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

    fn password_authentication(&mut self) -> io::Result<()> {
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


    fn msg_service_request(&mut self) -> io::Result<()> {
        let mut data = Data::new();
        data.put_u8(message::SSH_MSG_SERVICE_REQUEST)
            .put_str(strings::SSH_USERAUTH);
        let mut packet = Packet::from(data);
        packet.build();
        Ok(self.stream.write(packet.as_slice())?)
    }


    fn version_negotiation(&mut self) -> io::Result<()> {
        let svb = self.stream.read_version()?;
        let server_version = String::from_utf8(svb).unwrap();
        if server_version.contains("SSH-2.0") {
            let sv = server_version.trim();
            self.key_exchange.h.set_v_s(sv);
            self.key_exchange.h.set_v_c(strings::CLIENT_VERSION);
            println!(">> server version: {}", sv);
            println!(">> client version: {}", strings::CLIENT_VERSION);
            self.stream.write_version(format!("{}\r\n", strings::CLIENT_VERSION).as_bytes())?;
        } else { exit(0) }
        Ok(())
    }

}

