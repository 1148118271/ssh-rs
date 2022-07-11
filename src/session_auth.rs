use crate::{client, config, Session, SshResult};
use crate::constant::{ssh_msg_code, ssh_str};
use crate::data::Data;
use crate::user_info::UserInfo;

impl Session {



    pub fn auth_user_info(&self, user_info: UserInfo) {
        let config = config::config();
        config.auth = user_info
    }

    pub(crate) fn password_authentication(&self) -> SshResult<()> {
        log::info!("password authentication.");
        let config = config::config();
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

        let config = config::config();
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
        let config = config::config();
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
