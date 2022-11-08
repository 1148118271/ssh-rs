use crate::algorithm::hash::HashType;
use crate::constant::{ssh_msg_code, ssh_str};
use crate::data::Data;
use crate::h::H;
use crate::{Session, SshResult};
use std::io::{Read, Write};

impl<S> Session<S>
where
    S: Read + Write,
{
    pub(crate) fn password_authentication(&mut self) -> SshResult<()> {
        log::info!("password authentication.");
        let client = self.get_client()?;
        let user_info = &client.borrow().config.auth;
        let mut data = Data::new();
        data.put_u8(ssh_msg_code::SSH_MSG_USERAUTH_REQUEST)
            .put_str(user_info.username.as_str())
            .put_str(ssh_str::SSH_CONNECTION)
            .put_str(ssh_str::PASSWORD)
            .put_u8(false as u8)
            .put_str(user_info.password.as_str());
        self.get_client()?.borrow_mut().write(data)
    }

    pub(crate) fn public_key_authentication(&mut self) -> SshResult<()> {
        let client = self.get_client()?;
        let client = client.borrow();
        let pubkey_alg = client.negotiated.public_key.0[0].as_str();
        let auth_info = &client.config.auth;

        log::info!("public key authentication. algorithm: {:?}", pubkey_alg);

        let mut data = Data::new();
        data.put_u8(ssh_msg_code::SSH_MSG_USERAUTH_REQUEST)
            .put_str(auth_info.username.as_str())
            .put_str(ssh_str::SSH_CONNECTION)
            .put_str(ssh_str::PUBLIC_KEY)
            .put_u8(false as u8)
            .put_str(pubkey_alg)
            .put_u8s(&auth_info.key_pair.as_ref().unwrap().get_blob(pubkey_alg));
        self.get_client()?.borrow_mut().write(data)
    }

    pub(crate) fn public_key_signature(&mut self, ht: HashType, h: H) -> SshResult<()> {
        let client = self.get_client()?;
        let client = client.borrow();
        let pubkey_alg = client.negotiated.public_key.0[0].as_str();
        let auth_info = &client.config.auth;

        let mut data = Data::new();
        data.put_u8(ssh_msg_code::SSH_MSG_USERAUTH_REQUEST)
            .put_str(auth_info.username.as_str())
            .put_str(ssh_str::SSH_CONNECTION)
            .put_str(ssh_str::PUBLIC_KEY)
            .put_u8(true as u8)
            .put_str(pubkey_alg)
            .put_u8s(&auth_info.key_pair.as_ref().unwrap().get_blob(pubkey_alg));
        let signature =
            auth_info
                .key_pair
                .as_ref()
                .unwrap()
                .signature(data.as_slice(), h, ht, pubkey_alg);
        data.put_u8s(&signature);
        self.get_client()?.borrow_mut().write(data)
    }
}
