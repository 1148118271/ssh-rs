use crate::constant::{ssh_msg_code, ssh_str};
use crate::h::H;
use crate::model::Data;
use crate::{algorithm::hash::HashType, config::auth::AuthInfo};
use crate::{Session, SshResult};
use std::io::{Read, Write};

impl<S> Session<S>
where
    S: Read + Write,
{
    pub(crate) fn password_authentication(&self, auth: &AuthInfo) -> SshResult<()> {
        log::info!("password authentication.");
        let mut data = Data::new();
        data.put_u8(ssh_msg_code::SSH_MSG_USERAUTH_REQUEST)
            .put_str(auth.username.as_str())
            .put_str(ssh_str::SSH_CONNECTION)
            .put_str(ssh_str::PASSWORD)
            .put_u8(false as u8)
            .put_str(auth.password.as_str());
        self.get_client()?.borrow_mut().write(data)
    }

    pub(crate) fn public_key_authentication(&self, auth: &AuthInfo) -> SshResult<()> {
        let data = {
            let client = self.get_client()?;
            let client = client.borrow();
            let pubkey_alg = client.negotiated.public_key.0[0].as_str();

            log::info!("public key authentication. algorithm: {:?}", pubkey_alg);

            let mut data = Data::new();
            data.put_u8(ssh_msg_code::SSH_MSG_USERAUTH_REQUEST)
                .put_str(auth.username.as_str())
                .put_str(ssh_str::SSH_CONNECTION)
                .put_str(ssh_str::PUBLIC_KEY)
                .put_u8(false as u8)
                .put_str(pubkey_alg)
                .put_u8s(&auth.key_pair.as_ref().unwrap().get_blob(pubkey_alg));
            data
        };
        self.get_client()?.borrow_mut().write(data)
    }

    pub(crate) fn public_key_signature(&self, ht: HashType, h: H) -> SshResult<()> {
        let data = {
            let client = self.get_client()?;
            let client = client.borrow();
            let pubkey_alg = client.negotiated.public_key.0[0].as_str();
            let auth_info = &client.config.lock().unwrap().auth;

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
            data
        };
        self.get_client()?.borrow_mut().write(data)
    }
}
