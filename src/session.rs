use std::sync::{Arc, Mutex};
use std::sync::atomic::Ordering::Relaxed;
use crate::channel::Channel;
use crate::tcp::Client;
use crate::{strings, message, size, global_variable};
use crate::error::{SshError, SshErrorKind, SshResult};
use crate::key_agreement::KeyAgreement;
use crate::packet::{Data, Packet};



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
    pub(crate) stream: Arc<Mutex<Client>>,
    pub(crate) config: Config,
    pub(crate) key_agreement: KeyAgreement
}


impl Session {
    pub fn connect(&mut self) -> Result<(), SshError> {
        // 版本协商
        self.version_negotiation()?;
        // 密钥协商交换
        self.key_agreement.key_agreement(&mut self.stream.lock().unwrap())?;
        // 身份验证
        self.authentication()
    }
    pub fn set_nonblocking(&mut self, nonblocking: bool) -> SshResult<()> {
        match self.stream.lock() {
            Ok(ref mut v) => {
                if let Err(e) = v.stream.set_nonblocking(nonblocking) {
                    return Err(SshError::from(e))
                }
                Ok(())
            }
            Err(_) =>
                Err(SshError::from(SshErrorKind::MutexError))
        }
    }

    pub fn authentication(&mut self) -> SshResult<()> {
        // 开始身份验证  TODO!!!
        self.msg_service_request()?;
        loop {
            let results = match self.stream.lock() {
                Ok(mut v) => v.read()?,
                Err(_) =>
                    return Err(SshError::from(SshErrorKind::MutexError))
            };
            for buf in results {
                let message_code = buf[5];
                match message_code {
                    message::SSH_MSG_SERVICE_ACCEPT => {
                        // 开始密码验证 TODO 目前只支持密码验证
                        self.password_authentication()?;
                    }
                    message::SSH_MSG_USERAUTH_FAILURE => return Err(SshError::from(SshErrorKind::PasswordError)),
                    message::SSH_MSG_USERAUTH_SUCCESS => return Ok(()),
                    message::SSH_MSG_GLOBAL_REQUEST => {
                        let mut data = Data::new();
                        data.put_u8(message::SSH_MSG_REQUEST_FAILURE);
                        let mut packet = Packet::from(data);
                        packet.build();
                        match self.stream.lock() {
                            Ok(ref mut v) => v.write(packet.as_slice())?,
                            Err(_) =>
                                return Err(SshError::from(SshErrorKind::MutexError))
                        }
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

    pub fn close(self) -> SshResult<()> {
        match self.stream.lock() {
            Ok(ref mut v) =>
                Ok(v.close()?),
            Err(_) =>
                Err(SshError::from(SshErrorKind::MutexError))
        }
    }


    pub fn open_channel(&mut self) -> SshResult<Channel> {
        let client_channel = global_variable::CLIENT_CHANNEL.load(Relaxed);
        self.ssh_open_channel(client_channel)?;
        global_variable::CLIENT_CHANNEL.fetch_add(1, Relaxed);
        Ok(Channel {
            stream: Arc::clone(&self.stream),
            server_channel: 0,
            client_channel,
            key_agreement:
                KeyAgreement {
                    session_id: self.key_agreement.session_id.clone(),
                    h: self.key_agreement.h.clone(),
                    algorithm: self.key_agreement.algorithm.clone()
                }
        })
    }

    fn ssh_open_channel(&mut self, client_channel: u32) -> SshResult<()> {
        let mut data = Data::new();
        data.put_u8(message::SSH_MSG_CHANNEL_OPEN)
            .put_str(strings::SESSION)
            .put_u32(client_channel)
            .put_u32(size::LOCAL_WINDOW_SIZE)
            .put_u32(size::BUF_SIZE as u32);
        let mut packet = Packet::from(data);
        packet.build();
        return match self.stream.lock() {
            Ok(ref mut v) =>
                Ok(v.write(packet.as_slice())?),
            Err(_) =>
                Err(SshError::from(SshErrorKind::MutexError))
        }
    }

    fn password_authentication(&mut self) -> SshResult<()> {
        let username = &mut self.config.username;
        if username.is_empty() {
            return Err(SshError::from(SshErrorKind::UserNullError))
        }
        let password = &mut self.config.password;
        if password.is_empty() {
            return Err(SshError::from(SshErrorKind::PasswordNullError))
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
        return match self.stream.lock() {
            Ok(ref mut v) =>
                Ok(v.write(packet.as_slice())?),
            Err(_) =>
                Err(SshError::from(SshErrorKind::MutexError))
        }
    }


    fn msg_service_request(&mut self) -> SshResult<()> {
        let mut data = Data::new();
        data.put_u8(message::SSH_MSG_SERVICE_REQUEST)
            .put_str(strings::SSH_USERAUTH);
        let mut packet = Packet::from(data);
        packet.build();
        return match &mut self.stream.lock() {
            Ok(v) =>
                Ok(v.write(packet.as_slice())?),
            Err(_) =>
                Err(SshError::from(SshErrorKind::MutexError))
        }
    }


    fn version_negotiation(&mut self) -> SshResult<()> {
        let svb = match self.stream.lock() {
            Ok(ref mut v) => v.read_version(),
            Err(_) =>
            return Err(SshError::from(SshErrorKind::MutexError))
        };
        let server_version = match String::from_utf8(svb) {
            Ok(v) => v,
            Err(_) => return Err(SshError::from(SshErrorKind::FromUtf8Error))
        };
        if !server_version.contains("SSH-2.0") {
            return Err(SshError::from(SshErrorKind::VersionError))
        }
        let sv = server_version.trim();
        self.key_agreement.h.set_v_s(sv);
        self.key_agreement.h.set_v_c(strings::CLIENT_VERSION);
        // println!(">> server version: {}", sv);
        // println!(">> client version: {}", strings::CLIENT_VERSION);
        return match self.stream.lock() {
            Ok(ref mut v) =>
                Ok(v.write_version(format!("{}\r\n", strings::CLIENT_VERSION).as_bytes())?),
            Err(_) =>
                Err(SshError::from(SshErrorKind::MutexError))
        }
    }

}

