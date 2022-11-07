use crate::constant::{ssh_msg_code, ssh_str};
use crate::data::Data;
use crate::h::H;
use crate::user_info::UserInfo;
use crate::{algorithm::hash::HashType, Config};
use crate::{Session, SshResult};
use std::io::{Read, Write};

impl<S> Session<S>
where
    S: Read + Write,
{
    fn get_user_info(&self) -> &UserInfo {
        &self.get_config().auth
    }

    fn get_config(&self) -> &Config {
        &self.client.as_ref().unwrap().config
    }

    pub(crate) fn password_authentication(&mut self) -> SshResult<()> {
        log::info!("password authentication.");
        let user_info = self.get_user_info();
        let mut data = Data::new();
        data.put_u8(ssh_msg_code::SSH_MSG_USERAUTH_REQUEST)
            .put_str(user_info.username.as_str())
            .put_str(ssh_str::SSH_CONNECTION)
            .put_str(ssh_str::PASSWORD)
            .put_u8(false as u8)
            .put_str(user_info.password.as_str());
        self.client.as_mut().unwrap().write(data)
    }

    pub(crate) fn public_key_authentication(&mut self) -> SshResult<()> {
        log::info!(
            "public key authentication. algorithm: {:?}",
            &(self.get_config().algorithm.negotiated.public_key.0)[0]
        );

        let pubkey_alg = &(self.get_config().algorithm.negotiated.public_key.0)[0];

        let user_info = self.get_user_info();
        let mut data = Data::new();
        data.put_u8(ssh_msg_code::SSH_MSG_USERAUTH_REQUEST)
            .put_str(user_info.username.as_str())
            .put_str(ssh_str::SSH_CONNECTION)
            .put_str(ssh_str::PUBLIC_KEY)
            .put_u8(false as u8)
            .put_str(pubkey_alg)
            .put_u8s(&user_info.key_pair.as_ref().unwrap().get_blob(pubkey_alg));
        self.client.as_mut().unwrap().write(data)
    }

    pub(crate) fn public_key_signature(&mut self, ht: HashType, h: H) -> SshResult<()> {
        let user_info = self.get_user_info();
        let pubkey_alg = &(self.get_config().algorithm.negotiated.public_key.0)[0];

        let mut data = Data::new();
        data.put_u8(ssh_msg_code::SSH_MSG_USERAUTH_REQUEST)
            .put_str(user_info.username.as_str())
            .put_str(ssh_str::SSH_CONNECTION)
            .put_str(ssh_str::PUBLIC_KEY)
            .put_u8(true as u8)
            .put_str(pubkey_alg)
            .put_u8s(&user_info.key_pair.as_ref().unwrap().get_blob(pubkey_alg));
        let signature =
            user_info
                .key_pair
                .as_ref()
                .unwrap()
                .signature(data.as_slice(), h, ht, pubkey_alg);
        data.put_u8s(&signature);
        self.client.as_mut().unwrap().write(data)
    }
}
