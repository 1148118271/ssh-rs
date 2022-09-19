use std::path::Path;
use crate::{client, config, Session, SshError, SshResult};
use crate::config::Config;
use crate::constant::{ssh_msg_code, ssh_str};
use crate::data::Data;
use crate::key_pair::{KeyPair, KeyPairType};
use crate::user_info::UserInfo;

impl Session {

    pub fn get_config(&self) -> SshResult<&Config> {
        if self.config.is_none() {
            return Err(SshError::from("config is none."))
        }
        Ok(self.config.as_ref().unwrap())
    }

    pub fn get_config_mut(&mut self) -> SshResult<&mut Config> {
        if self.config.is_none() {
            return Err(SshError::from("config is none."))
        }
        Ok(self.config.as_mut().unwrap())
    }

    pub fn auth_user_info(&mut self, user_info: UserInfo) {
        self.config = Some(Config::new(user_info));
    }

    pub fn set_user_and_password<U: ToString, P: ToString>(&mut self, username: U, password: P) {
        let user_info = UserInfo::from_password(username.to_string(), password.to_string());
        self.auth_user_info(user_info);
    }

    pub fn set_user_and_key_pair<U: ToString, K: ToString>(&mut self, username: U, key_str: K, key_type: KeyPairType) -> SshResult<()> {
        let pair = KeyPair::from_str(key_str.to_string().as_str(), key_type)?;
        let user_info = UserInfo::from_key_pair(username, pair);
        self.auth_user_info(user_info);
        Ok(())
    }

    pub fn set_user_and_key_pair_path
    <U: ToString, P: AsRef<Path>>
    (&mut self,
     username: U,
     key_path: P,
     key_type: KeyPairType)
        -> SshResult<()>
    {
        let pair = KeyPair::from_path(key_path, key_type)?;
        let user_info = UserInfo::from_key_pair(username.to_string(), pair);
        self.auth_user_info(user_info);
        Ok(())
    }

    pub(crate) fn password_authentication(&self) -> SshResult<()> {
        log::info!("password authentication.");
        let config =  self.get_config()?;
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

    pub(crate) fn public_key_authentication(&self) -> SshResult<()> {
        log::info!("public key authentication.");
        let config = self.get_config()?;
        let mut data = Data::new();
        data.put_u8(ssh_msg_code::SSH_MSG_USERAUTH_REQUEST)
            .put_str(config.auth.username.as_str())
            .put_str(ssh_str::SSH_CONNECTION)
            .put_str(ssh_str::PUBLIC_KEY)
            .put_u8(false as u8)
            .put_str(config.auth.key_pair.key_type.as_str())
            .put_u8s(config.auth.key_pair.blob.as_slice());
        let client = client::default()?;
        client.write(data)
    }

    pub(crate) fn public_key_signature(&self) -> SshResult<()> {
        let config = self.get_config()?;
        let mut data = Data::new();
        data.put_u8(ssh_msg_code::SSH_MSG_USERAUTH_REQUEST)
            .put_str(config.auth.username.as_str())
            .put_str(ssh_str::SSH_CONNECTION)
            .put_str(ssh_str::PUBLIC_KEY)
            .put_u8(true as u8)
            .put_str(config.auth.key_pair.key_type.as_str())
            .put_u8s(config.auth.key_pair.blob.as_slice());
        let signature = config.auth.key_pair.signature(data.as_slice());
        data.put_u8s(&signature);
        let client = client::default()?;
        client.write(data)
    }
}
