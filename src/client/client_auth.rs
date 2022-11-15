use std::io::{Read, Write};

use crate::{
    algorithm::Digest,
    constant::{ssh_msg_code, ssh_str},
    error::{SshError, SshResult},
    model::{Data, Packet, SecPacket},
};

use super::Client;

impl Client {
    pub fn do_auth<S>(&mut self, stream: &mut S, digest: &mut Digest) -> SshResult<()>
    where
        S: Read + Write,
    {
        log::info!("Auth start");
        let mut data = Data::new();
        data.put_u8(ssh_msg_code::SSH_MSG_SERVICE_REQUEST)
            .put_str(ssh_str::SSH_USERAUTH);
        data.pack(self).write_stream(stream)?;

        let mut tried_public_key = false;
        loop {
            let mut data = Data::unpack(SecPacket::from_stream(stream, self)?)?;
            let message_code = data.get_u8();
            match message_code {
                ssh_msg_code::SSH_MSG_SERVICE_ACCEPT => {
                    if self.config.auth.key_pair.is_none() {
                        tried_public_key = true;
                        // if no private key specified
                        // just try password auth
                        self.password_authentication(stream)?
                    } else {
                        // if private key was provided
                        // use public key auth first, then fallback to password auth
                        self.public_key_authentication(stream)?
                    }
                }
                ssh_msg_code::SSH_MSG_USERAUTH_FAILURE => {
                    if !tried_public_key {
                        log::error!("user auth failure. (public key)");
                        log::info!("fallback to password authentication");
                        tried_public_key = true;
                        // keep the same with openssh
                        // if the public key auth failed
                        // try with password again
                        self.password_authentication(stream)?
                    } else {
                        log::error!("user auth failure. (password)");
                        return Err(SshError::from("user auth failure."));
                    }
                }
                ssh_msg_code::SSH_MSG_USERAUTH_PK_OK => {
                    log::info!("user auth support this algorithm.");
                    self.public_key_signature(stream, digest)?
                }
                ssh_msg_code::SSH_MSG_USERAUTH_SUCCESS => {
                    log::info!("user auth successful.");
                    return Ok(());
                }
                ssh_msg_code::SSH_MSG_GLOBAL_REQUEST => {
                    let mut data = Data::new();
                    data.put_u8(ssh_msg_code::SSH_MSG_REQUEST_FAILURE);
                    data.pack(self).write_stream(stream)?;
                }
                _ => {}
            }
        }
    }

    fn password_authentication<S>(&mut self, stream: &mut S) -> SshResult<()>
    where
        S: Write,
    {
        log::info!("password authentication.");
        let mut data = Data::new();
        data.put_u8(ssh_msg_code::SSH_MSG_USERAUTH_REQUEST)
            .put_str(self.config.auth.username.as_str())
            .put_str(ssh_str::SSH_CONNECTION)
            .put_str(ssh_str::PASSWORD)
            .put_u8(false as u8)
            .put_str(self.config.auth.password.as_str());

        data.pack(self).write_stream(stream)
    }

    fn public_key_authentication<S>(&mut self, stream: &mut S) -> SshResult<()>
    where
        S: Write,
    {
        let data = {
            let pubkey_alg = &self.negotiated.public_key.0[0];
            log::info!("public key authentication. algorithm: {:?}", pubkey_alg);
            let mut data = Data::new();
            data.put_u8(ssh_msg_code::SSH_MSG_USERAUTH_REQUEST)
                .put_str(self.config.auth.username.as_str())
                .put_str(ssh_str::SSH_CONNECTION)
                .put_str(ssh_str::PUBLIC_KEY)
                .put_u8(false as u8)
                .put_str(pubkey_alg)
                .put_u8s(
                    &self
                        .config
                        .auth
                        .key_pair
                        .as_ref()
                        .unwrap()
                        .get_blob(pubkey_alg),
                );
            data
        };
        data.pack(self).write_stream(stream)
    }

    pub(crate) fn public_key_signature<S>(
        &mut self,
        stream: &mut S,
        digest: &Digest,
    ) -> SshResult<()>
    where
        S: Write,
    {
        let data = {
            let pubkey_alg = &self.negotiated.public_key.0[0];

            let mut data = Data::new();
            data.put_u8(ssh_msg_code::SSH_MSG_USERAUTH_REQUEST)
                .put_str(self.config.auth.username.as_str())
                .put_str(ssh_str::SSH_CONNECTION)
                .put_str(ssh_str::PUBLIC_KEY)
                .put_u8(true as u8)
                .put_str(pubkey_alg)
                .put_u8s(
                    &self
                        .config
                        .auth
                        .key_pair
                        .as_ref()
                        .unwrap()
                        .get_blob(pubkey_alg),
                );
            let signature = self.config.auth.key_pair.as_ref().unwrap().signature(
                data.as_slice(),
                digest.hash_ctx.clone(),
                digest.key_exchange.as_ref().unwrap().get_hash_type(),
                pubkey_alg,
            );
            data.put_u8s(&signature);
            data
        };
        data.pack(self).write_stream(stream)
    }
}
